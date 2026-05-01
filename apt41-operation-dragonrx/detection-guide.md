# Detection Guide — Operation DragonRx
## SOC Analyst Playbook: Detecting APT41 TTPs

**Detection stack:** Wazuh + Elastic SIEM + Sysmon + Zeek (+ optional Suricata)
**Perspective:** Blue team analyst receiving Wazuh/Elastic alerts during the live attack simulation.

**Lab access:**
```bash
# Kibana SIEM
open http://localhost:5601

# Zeek logs (inside Docker container)
docker exec dragonrx_zeek tail -f /usr/local/zeek/logs/current/conn.log
docker exec dragonrx_zeek cat /usr/local/zeek/logs/current/http.log | zeek-cut ts id.orig_h uri

# Wazuh manager
docker exec -it dragonrx_wazuh bash

# Deployed rule files
#   dragonrx-lab/siem/wazuh/rules/dragonrx_rules.xml   (custom rules 100110–100170)
#     → installed at runtime: docker cp siem/wazuh/rules/dragonrx_rules.xml \
#                             dragonrx_wazuh:/var/ossec/etc/rules/
#   dragonrx-lab/siem/zeek/local.zeek                   (Log4Shell JNDI + long-label DNS detection)
#   dragonrx-lab/siem/sysmon/sysmonconfig.xml            (EID 1,3,7,10,11,22)
```

---

## Detection Coverage Map

| Attack Phase | Detection Method | Alert Name | Confidence |
|-------------|-----------------|------------|------------|
| Log4Shell initial access | Zeek HTTP + Suricata IDS | Log4Shell JNDI in HTTP header | High |
| JSP webshell deployment | Sysmon EID 11 + file integrity | Webshell created in Tomcat webroot | High |
| Config file credential theft | Wazuh file access audit | Sensitive config accessed by www-data | Medium |
| Internal network scan | Zeek connection logs | Port scan from web server | Medium |
| Kerberoasting | Windows EID 4769 | RC4 TGS requested for service account | High |
| LSASS dump (comsvcs.dll) | Sysmon EID 10 + EID 1 | LSASS accessed by rundll32 | High |
| Pass-the-Hash | Windows EID 4624 LogonType 3 | NTLM auth with mismatched logon type | Medium |
| DCSync | Windows EID 4662 | DS-Replication-Get-Changes-All | High |
| DLL sideloading | Sysmon EID 7 | Unsigned DLL loaded from non-standard path | High |
| C2 beacon | Zeek conn.log + DNS | Periodic HTTPS to rare host / Java UA | Medium |
| DNS tunneling | Zeek DNS + entropy | High-entropy subdomain queries | Medium |
| Data staging | Sysmon EID 11 + size | Large archive created in Temp | Medium |
| VSS deletion | Windows EID 524 | Shadow copy deleted | High |

---

## Part 1: Network Detection (Zeek)

### 1.1 Log4Shell in HTTP Headers

**Deployed script:** `dragonrx-lab/siem/zeek/local.zeek` (automatically loaded by the Zeek container)

```zeek
# dragonrx-lab/siem/zeek/local.zeek (excerpt)
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( !is_orig ) return;

    # Single pattern covers both canonical (${jndi:}) and common obfuscations
    # (${${lower:j}ndi:}, ${${::-j}${::-n}...}) by matching j,n,d,i as scattered
    # characters within a ${...} expression.
    if ( /\$\{[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:/ in value ) {
        NOTICE([
            $note=Notice::LOG,
            $conn=c,
            $msg=fmt("[ALERT] Log4Shell JNDI injection attempt: header=%s value=%s src=%s dst=%s:%s",
                     name, value, c$id$orig_h, c$id$resp_h, c$id$resp_p),
            $identifier=cat(c$id$orig_h),
            $suppress_for=1min
        ]);
    }
}
```

**Elastic query:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.module": "zeek"}},
        {"match": {"event.dataset": "zeek.http"}},
        {"regexp": {"zeek.http.user_agent": ".*\\$\\{jndi:.*"}}
      ]
    }
  }
}
```

### 1.2 C2 Beacon Detection — Periodic HTTPS

```bash
# Access Zeek logs from the host via docker exec
# All Zeek logs live at /usr/local/zeek/logs/current/ inside the container
alias zeek-exec="docker exec dragonrx_zeek"

# Quick: count HTTPS connections by src→dst pair
zeek-exec zeek-cut ts id.orig_h id.resp_h id.resp_p \
  < <(docker exec dragonrx_zeek cat /usr/local/zeek/logs/current/conn.log) | \
  awk '$4 == 443' | awk '{print $2, $3}' | sort | uniq -c | sort -rn | head 20

# Python beacon detector (run from Kali container or IR workstation with log access)
python3 << 'EOF'
import json
import sys
from collections import defaultdict
import statistics

connections = defaultdict(list)

# Copy log out first: docker cp dragonrx_zeek:/usr/local/zeek/logs/current/conn.log /tmp/
with open('/tmp/conn.log') as f:
    for line in f:
        if line.startswith('#'): continue
        fields = line.strip().split('\t')
        if len(fields) < 8: continue
        ts, orig_h, resp_h, resp_p = fields[0], fields[2], fields[4], fields[5]
        if resp_p == '443':
            connections[(orig_h, resp_h)].append(float(ts))

for (src, dst), timestamps in connections.items():
    if len(timestamps) < 5: continue
    timestamps.sort()
    intervals = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
    mean_interval = statistics.mean(intervals)
    stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
    
    # Low stdev relative to mean = very regular = likely beacon
    if 20 <= mean_interval <= 300 and stdev/mean_interval < 0.30:
        print(f"[BEACON] {src} → {dst}:443  interval={mean_interval:.1f}s ±{stdev:.1f}s  count={len(timestamps)}")
EOF
```

### 1.3 DNS Tunneling Detection

**Deployed script:** `dragonrx-lab/siem/zeek/local.zeek` includes Shannon entropy DNS detection (auto-fires NOTICE when subdomain entropy > 3.5 and length > 15 chars).

```bash
# Check Zeek NOTICE log for DNS tunnel alerts
docker exec dragonrx_zeek cat /usr/local/zeek/logs/current/notice.log | \
  grep -i "dns.*tunnel\|entropy"

# Manual high-entropy subdomain detection on extracted log
# docker cp dragonrx_zeek:/usr/local/zeek/logs/current/dns.log /tmp/
python3 << 'EOF'
import math
import sys

def entropy(s):
    if not s: return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum(p/len(s)*math.log2(p/len(s)) for p in freq.values())

with open('/tmp/dns.log') as f:
    for line in f:
        if line.startswith('#'): continue
        fields = line.strip().split('\t')
        if len(fields) < 9: continue
        query = fields[9]
        parts = query.split('.')
        if parts:
            subdomain = parts[0]
            e = entropy(subdomain)
            if len(subdomain) > 15 and e > 3.5:
                print(f"[DNS TUNNEL] High entropy subdomain: {query} (entropy={e:.2f})")
EOF

# Also alert on: same domain, many queries/minute with different subdomains
docker exec dragonrx_zeek cat /usr/local/zeek/logs/current/dns.log | \
  zeek-cut query | \
  awk -F'.' '{print $NF"."$(NF-1)}' | sort | uniq -c | sort -rn | \
  awk '$1 > 100' | head 10
```

### 1.4 Unusual User-Agent / Java Update C2

```bash
# Find Oracle Java Update user-agent from non-Java processes
docker exec dragonrx_zeek cat /usr/local/zeek/logs/current/http.log | \
  zeek-cut id.orig_h user_agent uri | \
  grep -i "oracle.*java.*update\|java.*update.*oracle" | \
  grep -v "^192\.168\.10\.50"  # exclude known Java workstations

# Or in Elastic:
# user_agent.original: "Oracle/Java-Update*" AND NOT source.ip: "192.168.10.50"
```

---

## Part 2: Host Detection (Sysmon + Windows Events)

**Deployed rule file:** `dragonrx-lab/siem/wazuh/rules/dragonrx_rules.xml`
Custom rules 100110–100170 are installed into the running container via `docker cp` (done automatically by `make up` / `deploy.sh`). Rules 100101/100102 (below) cover Java→shell process chains and can be appended to that file for Log4Shell-specific coverage.

### 2.1 Log4Shell Reverse Shell — Java Spawning Bash

**Sysmon Event ID 1** (Process Create)

```xml
<!-- Wazuh rule: java.exe/java spawning shell -->
<rule id="100101" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)(java\.exe|tomcat|catalina)</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(cmd\.exe|powershell\.exe|wscript|cscript|mshta)</field>
  <description>Java/Tomcat spawning shell interpreter — possible Log4Shell exploitation</description>
  <mitre>
    <id>T1190</id>
    <id>T1059</id>
  </mitre>
  <group>attack,initial_access,execution</group>
</rule>
```

**Linux equivalent (Wazuh auditd):**

```xml
<rule id="100102" level="15">
  <if_sid>80700</if_sid>
  <field name="audit.exe">/bin/bash</field>
  <field name="audit.ppid" type="pcre2">.*</field>
  <match>ppid.*tomcat\|ppid.*java</match>
  <description>Bash spawned by Java/Tomcat process — Log4Shell reverse shell candidate</description>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>
```

**Elastic detection rule:**
```json
{
  "name": "Log4Shell - Java Spawning Shell",
  "query": "process.parent.name:(java OR catalina OR tomcat) AND process.name:(bash OR sh OR cmd.exe OR powershell.exe)",
  "severity": "critical",
  "risk_score": 95,
  "tags": ["T1190", "Log4Shell", "APT41"]
}
```

### 2.2 LSASS Memory Access (Credential Dumping)

**Sysmon Event ID 10** (Process Access)

```xml
<rule id="100110" level="15">
  <if_group>sysmon_event10</if_group>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <description>LSASS memory access detected — credential dumping attempt</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>attack,credential_access</group>
</rule>

<!-- More specific: comsvcs.dll MiniDump LOLBIN -->
<rule id="100111" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)rundll32\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)comsvcs</field>
  <description>rundll32.exe loading comsvcs.dll — LSASS dump via LOLBIN (T1003.001)</description>
  <mitre>
    <id>T1003.001</id>
    <id>T1218.011</id>
  </mitre>
  <group>attack,credential_access,defense_evasion</group>
</rule>
```

**Elastic KQL:**
```
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe
OR
(event.code:1 AND process.name:rundll32.exe AND process.command_line:*comsvcs*)
```

### 2.3 DCSync Detection

**Windows Event ID 4662** (Object Accessed)

```xml
<rule id="100120" level="15">
  <if_sid>4662</if_sid>
  <field name="win.eventdata.properties" type="pcre2">1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</field>
  <description>DCSync attack: DS-Replication-Get-Changes-All access right observed — possible DCSync</description>
  <mitre>
    <id>T1003.006</id>
  </mitre>
  <group>attack,credential_access</group>
</rule>
```

**Key detail for article:** The GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` is the `DS-Replication-Get-Changes-All` extended right. Only Domain Controllers and accounts with explicit DCSync delegation should ever generate this event. Any workstation or server generating it = DCSync attack in progress.

**Elastic:**
```
event.code:4662 AND winlog.event_data.Properties:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*
AND NOT winlog.event_data.SubjectUserName:*$   # exclude machine accounts (real DCs)
```

### 2.4 Kerberoasting Detection

**Windows Event ID 4769** (Kerberos Service Ticket Requested)

```xml
<rule id="100130" level="12">
  <if_sid>4769</if_sid>
  <field name="win.eventdata.ticketEncryptionType">0x17</field>
  <description>RC4-HMAC TGS requested — Kerberoasting indicator (weak encryption type)</description>
  <mitre>
    <id>T1558.003</id>
  </mitre>
  <group>attack,credential_access</group>
</rule>
```

**Why RC4 (0x17) matters:** Modern AD defaults to AES256 (0x12) for service tickets. If an attacker requests RC4, it's because RC4 hashes are faster to crack offline. Legitimate clients almost never request RC4 in a modern AD environment.

**Elastic query for Kerberoasting sweep:**
```
event.code:4769 
AND winlog.event_data.TicketEncryptionType:0x17
AND winlog.event_data.ServiceName:(*$ )  -- exclude computer accounts
AND winlog.event_data.ServiceName:(svc_* OR SQL* OR http*)  -- service account pattern
```

### 2.5 DLL Sideloading Detection

**Sysmon Event ID 7** (Image Load)

```xml
<rule id="100140" level="13">
  <if_group>sysmon_event7</if_group>
  <field name="win.eventdata.signed">false</field>
  <field name="win.eventdata.imagePath" type="pcre2">(?i)ProgramData|AppData|Temp|Downloads</field>
  <field name="win.eventdata.imageLoaded" type="pcre2">(?i)(jvm\.dll|version\.dll|cryptbase\.dll)</field>
  <description>Unsigned DLL loaded from non-standard path — possible DLL sideloading (T1574.002)</description>
  <mitre>
    <id>T1574.002</id>
  </mitre>
  <group>attack,persistence,defense_evasion</group>
</rule>
```

**Elastic:**
```
event.code:7 
AND winlog.event_data.Signed:false
AND winlog.event_data.ImageLoaded:*jvm.dll
AND NOT winlog.event_data.ImageLoaded:*\\Program Files\\*
```

### 2.6 Pass-the-Hash Detection

**Windows Event ID 4624** (Logon)

```xml
<rule id="100150" level="10">
  <if_sid>4624</if_sid>
  <field name="win.eventdata.logonType">3</field>
  <field name="win.eventdata.authenticationPackageName">NTLM</field>
  <field name="win.eventdata.workstationName" negate="yes" type="pcre2">^(NOVATECH-)?WS0[0-9]$</field>
  <description>NTLM network logon from unexpected workstation — Pass-the-Hash candidate</description>
  <mitre>
    <id>T1550.002</id>
  </mitre>
  <group>attack,lateral_movement</group>
</rule>
```

**Context for article:** Pass-the-Hash is tricky to detect because it looks like a normal NTLM authentication. Key indicators: LogonType=3, NtlmV2, and the source workstation is NOT a domain-joined machine (or is the Linux web server's IP).

### 2.7 Scheduled Task Creation (Persistence)

**Windows Event ID 4698**

```xml
<rule id="100160" level="10">
  <if_sid>4698</if_sid>
  <field name="win.eventdata.taskName" type="pcre2">(?i)(java|update|cache|svc|service|microsoft)</field>
  <field name="win.eventdata.taskContent" type="pcre2">(?i)(ProgramData|AppData|Temp|Downloads)</field>
  <description>Suspicious scheduled task created with payload in non-standard path</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>attack,persistence</group>
</rule>
```

### 2.8 Shadow Copy Deletion (Pre-Ransomware)

**Windows Event ID 524** (or 7036 service stop)

```xml
<rule id="100170" level="15">
  <if_sid>4688</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)vssadmin\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)delete.*shadows</field>
  <description>Volume Shadow Copy deletion — ransomware pre-stage or destructive actor</description>
  <mitre>
    <id>T1485</id>
  </mitre>
  <group>attack,impact</group>
</rule>
```

---

## Part 3: Elastic SIEM — Correlation Rules

### 3.1 Multi-Stage Attack Correlation: Log4Shell → Lateral Movement

```json
{
  "name": "APT41 - Log4Shell to Domain Compromise Sequence",
  "description": "Detects the full kill chain: Log4Shell exploitation followed by credential dumping and lateral movement within 24 hours",
  "type": "eql",
  "query": "sequence by host.name with maxspan=24h\n  [network where event.dataset=\"zeek.http\" and http.request.headers.x-api-version:\"*jndi:*\"]\n  [process where process.parent.name:\"java\" and process.name:(\"bash\",\"sh\",\"cmd.exe\")]\n  [process where process.name:\"rundll32.exe\" and process.command_line:\"*comsvcs*\"]\n  [authentication where event.code:\"4624\" and winlog.event_data.LogonType:\"3\"]",
  "severity": "critical",
  "tags": ["APT41", "T1190", "T1003.001", "T1550.002"]
}
```

### 3.2 Kerberoasting → Lateral Movement Sequence

```json
{
  "name": "APT41 - Kerberoasting followed by lateral movement",
  "type": "eql",
  "query": "sequence with maxspan=4h\n  [authentication where event.code:\"4769\" and winlog.event_data.TicketEncryptionType:\"0x17\"]\n  [authentication where event.code:\"4624\" and winlog.event_data.LogonType:\"3\" and winlog.event_data.AuthenticationPackageName:\"NTLM\"]",
  "severity": "high"
}
```

### 3.3 DCSync from Non-DC Host

```json
{
  "name": "DCSync from Non-Domain-Controller",
  "type": "query",
  "query": "event.code:4662 AND winlog.event_data.Properties:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* AND NOT winlog.computer_name:(DC01* OR DC02*)",
  "severity": "critical"
}
```

---

## Part 4: Suricata Network IDS Rules

> **Lab note:** Suricata is not included in the default `docker-compose.yml` to keep resource requirements manageable. These rules can be deployed to a host-based Suricata instance (`suricata -i any -c /etc/suricata/suricata.yaml`) or added as a service to the compose file if needed. The Zeek `local.zeek` script covers the same detection use cases within the default lab stack.

```bash
# suricata/rules/dragonrx.rules

# Log4Shell JNDI in HTTP headers
alert http any any -> any any (
    msg:"ET EXPLOIT Apache Log4j RCE Attempt (jndi:)";
    flow:established,to_server;
    content:"${jndi:";
    http_header;
    classtype:web-application-attack;
    sid:9001001; rev:1;
)

# Log4Shell obfuscated variant (${${lower:j}ndi:)
alert http any any -> any any (
    msg:"ET EXPLOIT Apache Log4j RCE Attempt (obfuscated)";
    flow:established,to_server;
    pcre:"/\$\{[a-zA-Z:]*\{[a-zA-Z]+:[a-z]\}[a-zA-Z:]*ndi:/H";
    classtype:web-application-attack;
    sid:9001002; rev:1;
)

# JNDI LDAP callback (outbound, from WEB01 to attacker LDAP server)
alert tcp any any -> any 1389 (
    msg:"ET EXPLOIT Log4j JNDI LDAP callback (port 1389)";
    flow:established,to_server;
    classtype:policy-violation;
    sid:9001003; rev:1;
)

# RxPhage beacon User-Agent
alert http any any -> any 443 (
    msg:"ET MALWARE RxPhage C2 beacon User-Agent";
    flow:established,to_server;
    content:"Oracle/Java-Update/"; http_header;
    content:"X-Client-Id"; http_header;
    content:"X-Session"; http_header;
    classtype:trojan-activity;
    sid:9001010; rev:1;
)

# RxPhage C2 URL patterns
alert http any any -> any 443 (
    msg:"ET MALWARE RxPhage C2 telemetry path";
    flow:established,to_server;
    content:"/api/v2/telemetry"; http_uri;
    classtype:trojan-activity;
    sid:9001011; rev:1;
)

# DNS tunneling: suspiciously long subdomain
alert dns any any -> any 53 (
    msg:"ET POLICY Possible DNS Tunneling — long subdomain query";
    dns_query;
    pcre:"/^[a-zA-Z0-9+\/]{30,}\.[a-z]{2,10}\.[a-z]{2,6}$/";
    classtype:policy-violation;
    sid:9001020; rev:1;
)

# Impacket psexec (REMCOMSVC service creation)
alert smb any any -> any 445 (
    msg:"ET ATTACK Impacket psexec REMCOMSVC service";
    content:"REMCOMSVC";
    classtype:policy-violation;
    sid:9001030; rev:1;
)

# CrackMapExec named pipe pattern
alert smb any any -> any 445 (
    msg:"ET ATTACK CrackMapExec SMB execution";
    content:"smbexec";
    nocase;
    classtype:policy-violation;
    sid:9001031; rev:1;
)

# vssadmin delete via network (lateral spread of ransomware)
alert http any any -> any any (
    msg:"ET ATTACK vssadmin shadow delete over network";
    content:"vssadmin"; nocase;
    content:"delete"; nocase;
    content:"shadows"; nocase;
    classtype:policy-violation;
    sid:9001040; rev:1;
)
```

---

## Part 5: Wazuh Active Response

Automatically block the attacker IP when Log4Shell is detected.

**Deployed config:** `dragonrx-lab/siem/wazuh/ossec.conf` (Wazuh 4.7.0 default config — active-response block below is pre-configured in it and applied after `make up`)

```xml
<!-- dragonrx-lab/siem/wazuh/ossec.conf — active-response section -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101,100102</rules_id>  <!-- Log4Shell rules -->
  <timeout>600</timeout>
</active-response>
```

```xml
<!-- /var/ossec/etc/shared/ar.conf (inside dragonrx_wazuh container) -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

---

## Part 6: Detection Timeline — What SOC Sees

| Day | Time | Alert | Severity | Analyst Action |
|-----|------|-------|----------|----------------|
| 1 | 14:23 | Log4Shell JNDI in X-Api-Version header | Critical | Investigate Tomcat logs |
| 1 | 14:24 | Java spawning bash shell (Sysmon) | Critical | Confirm exploit success |
| 1 | 14:30 | New .jsp file created in webroot | High | Identify webshell |
| 2 | 09:15 | Port scan from WEB01 (192.168.10.100) | Medium | Flag for review |
| 3 | 11:45 | LDAP queries from WEB01 to DC01 | Medium | Why is web server querying AD? |
| 3 | 16:30 | NTLM logon from 192.168.10.100 to WS01 | High | Linux IP authenticating Windows = PTH |
| 4 | 08:00 | RC4 TGS for svc_backup from 192.168.10.100 | High | Kerberoasting from Linux host |
| 4 | 10:15 | LSASS accessed by rundll32.exe on WS01 | Critical | Credential dumping confirmed |
| 4 | 13:00 | DS-Replication-Get-Changes-All on DC01 | Critical | DCSync = domain fully compromised |
| 5 | 02:00 | Unsigned jvm.dll loaded by java.exe on DC01 | High | Sideloading persistence |
| 5 | 02:05 | Periodic HTTPS to rare IP at 60s intervals | Medium | C2 beacon pattern |
| 5 | 03:30 | High-entropy DNS subdomains | Medium | DNS tunneling active |
| 5 | 04:00 | 2.3GB data.zip created in C:\Temp | Medium | Data staging — exfil incoming |
| 6 | 08:00 | SOC analyst investigates Day 4 LSASS alert | — | DFIR initiated |

**Realistic gap:** Day 4 LSASS alert generated at 10:15 — SOC analyst investigates Day 6. This 36-hour gap is the article's teaching moment about alert triage, mean time to detect (MTTD), and why automated containment matters.

---

## Part 7: Hunting Queries (Threat Hunting Beyond Alerts)

```bash
# Hunt 1: Find all processes spawned by Tomcat/Java on Linux
# (run on WEB01 via Wazuh agent query)
# Look for bash, wget, curl, nc, python spawned by java
ps aux | awk '{print $1, $2, $3}' | grep -E "www-data|tomcat"
cat /proc/*/status | grep -E "PPid|Name" | paste - - | awk 'seen[$2]++' 2>/dev/null

# Hunt 2: Unusual scheduled tasks on Windows
schtasks /query /fo CSV | ConvertFrom-Csv | Where-Object {
    $_.TaskName -notmatch "Microsoft|Windows|Adobe|Chrome" -and
    $_."Task To Run" -match "ProgramData|AppData|Temp|Downloads"
}

# Hunt 3: Find all unsigned DLLs loaded by java.exe
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 7 -and $_.Message -match "java.exe" -and $_.Message -match "Signed: false"}

# Hunt 4: Beacon pattern hunt — find hosts with regular outbound connections
# (Zeek-based, Python beacon detector above)

# Hunt 5: Kerberoasting — look for RC4 TGS requests historically
Get-WinEvent -LogName Security |
  Where-Object {$_.Id -eq 4769 -and $_.Message -match "0x17"} |
  Select-Object TimeCreated, Message |
  Format-List

# Hunt 6: DCSync attempts
Get-WinEvent -LogName Security |
  Where-Object {$_.Id -eq 4662 -and $_.Message -match "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"} |
  Select-Object TimeCreated, @{N="Subject";E={$_.Properties[1].Value}}, @{N="Object";E={$_.Properties[8].Value}}
```

---

*Next document: [dfir-playbook.md](dfir-playbook.md) — full DFIR response from initial alert through memory forensics, disk analysis, timeline reconstruction, and malware analysis.*
