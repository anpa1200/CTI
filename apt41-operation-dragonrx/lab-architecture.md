# Lab Architecture — Operation DragonRx

> **Part of the Operation DragonRx series** · [Overview](README.md) · **Lab Architecture** · [Attack Playbook](attack-playbook.md) · [DFIR Walkthrough](dfir-walkthrough.md)

**A fully automated, reproducible APT41 detection lab.** Docker + Vagrant + Ansible provisioned in a single command. Three Windows VMs (Active Directory, file server, workstation), eight Linux containers (attacker tooling, Log4Shell target, Wazuh/Elastic/Zeek SIEM), and custom attack simulation tooling. Built for security researchers studying Log4Shell exploitation, Kerberoasting, DCSync, and lateral movement — with full SIEM telemetry from day one.

**Estimated deploy time:** ~25 min (boxes cached) · **Host requirements:** 24 GB RAM, 8 cores, 120 GB SSD

---

## Contents

1. [Deployment Stack](#deployment-stack-docker--vagrant--ansible)
2. [Network Topology](#network-topology)
3. [Directory Structure](#directory-structure)
4. [Deploy from Git](#deploy-from-git)
5. [One-Script Deployment](#one-script-deployment)
6. [Prerequisites](#prerequisites)
7. [Vagrantfile](#vagrantfile)
8. [docker-compose.yml](#docker-composeyml)
9. [Ansible](#ansible)
10. [Ansible Roles](#ansible-roles)
11. [Master Deploy Playbook](#master-deploy-playbook)
12. [Test Playbook](#test-playbook)
13. [Zeek Config](#zeek-config)
14. [Host Networking Setup](#host-networking-setup)
15. [Makefile](#makefile)
16. [Deploy Sequence](#deploy-sequence)
17. [VM Specifications](#vm-specifications)

---

## Deployment Stack: Docker + Vagrant + Ansible

All infrastructure is provisioned and configured automatically. A single `make up` command deploys the complete lab — Linux containers, Windows VMs, Active Directory, SIEM stack, and detection tooling — with zero manual steps.

| Tool | Responsibility |
|------|---------------|
| **Docker Compose** | Linux containers: Kali, Sliver C2, JNDI server, Web01 (Log4Shell target), Wazuh, Elastic, Kibana, Zeek |
| **Vagrant** | Windows VMs (DC01, FS01, WS01) via VirtualBox provider; WinRM auto-configured |
| **Ansible** | All post-boot configuration: AD setup, user accounts, SPNs, Wazuh agents, crown jewel data, file shares |
| **Makefile** | Single-command interface: `make up`, `make test`, `make attack`, `make down`, `make reset` |

---

## Network Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                   ATTACKER NETWORK (10.0.0.0/24)                    │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐  │
│  │  KALI Linux  │   │  Sliver C2   │   │     JNDI Server        │  │
│  │  10.0.0.5    │   │  10.0.0.10   │   │     10.0.0.20          │  │
│  │  (Docker)    │   │  (Docker)    │   │     (Docker)           │  │
│  └──────┬───────┘   └──────────────┘   └────────────────────────┘  │
└─────────┼───────────────────────────────────────────────────────────┘
          │  (host routing: iptables FORWARD between bridges)
          │
┌─────────┼───────────────────────────────────────────────────────────┐
│         │          TARGET NETWORK (192.168.10.0/24)                 │
│         │                                                           │
│  ┌──────▼──────────────┐   ┌───────────────────────────────────┐   │
│  │  WEB01  (Docker)    │   │  Windows AD (Vagrant/VirtualBox)  │   │
│  │  Spring Boot        │   │                                   │   │
│  │  192.168.10.100     │   │  DC01  192.168.10.10  WS 2019     │   │
│  │  log4j-core 2.14.1  │   │  FS01  192.168.10.20  WS 2019     │   │
│  └─────────────────────┘   │  WS01  192.168.10.50  Win 10      │   │
│                            └───────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  SIEM / SOC STACK (Docker)                                   │  │
│  │  Wazuh   192.168.10.200   Zeek   (host network mode)        │  │
│  │  Elastic 192.168.10.202   Kibana 192.168.10.203             │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**Networking note:** Docker `target_net` (192.168.10.0/24) and VirtualBox host-only `vboxnet0` (192.168.10.0/24) share the same subnet. The `scripts/setup_routing.sh` script enables IP forwarding and adds iptables FORWARD rules between both kernel bridges so all nodes can communicate directly.

---

## Directory Structure

```
dragonrx-lab/
├── Makefile                           # make up / test / attack / shell / down / reset
├── Vagrantfile                        # DC01 (WS2019), FS01 (WS2019), WS01 (Win10)
├── docker-compose.yml                 # 8 Linux containers, two named subnets
│
├── scripts/
│   ├── deploy.sh                      # ★ ONE-SCRIPT full deployment (see below)
│   ├── setup_routing.sh               # host iptables bridge: Docker ↔ VirtualBox
│   └── fix_vboxdrv.sh                 # rebuild VBoxDRV DKMS module if needed
│
├── ansible/
│   ├── ansible.cfg                    # interpreter, timeout, retry config
│   ├── requirements.yml               # Galaxy: ansible.windows, microsoft.ad, community.*
│   ├── inventory/
│   │   ├── hosts.ini                  # DC01/FS01/WS01 WinRM addresses
│   │   └── group_vars/
│   │       ├── all.yml                # domain, passwords, Wazuh version
│   │       └── windows.yml            # WinRM connection vars for all Windows hosts
│   ├── playbooks/
│   │   ├── deploy.yml                 # master playbook: 6 phases in order
│   │   └── test.yml                   # smoke tests + detection validation
│   └── roles/
│       ├── dc01/tasks/main.yml        # AD DS install → forest promote → users → SPNs → audit SACL
│       ├── fs01/tasks/main.yml        # domain join → SMB shares → 45 crown-jewel data files
│       ├── ws01/tasks/main.yml        # domain join → jsmith local admin → C:\Temp
│       └── wazuh_agent/tasks/main.yml # download MSI → install → enroll with manager
│
├── jndi/
│   ├── Dockerfile.jndi                # eclipse-temurin:11-jdk-jammy + Maven-built marshalsec
│   ├── start.sh                       # launch HTTP payload server + marshalsec LDAP relay
│   └── payloads/                      # Exploit.class served to Log4Shell victims
│
├── attacker/
│   ├── tools/                         # volume-mounted into Kali container at /opt/tools
│   └── loot/                          # exfil landing zone at /opt/loot
│
├── c2/
│   ├── Dockerfile.sliver              # Sliver v1.7.3 binary from GitHub releases
│   ├── configs/                       # Sliver operator config (auto-generated)
│   └── loot/                          # Sliver download landing zone
│
├── siem/
│   ├── wazuh/
│   │   ├── ossec.conf                 # Wazuh 4.7.0 default manager config (reference copy)
│   │   └── rules/
│   │       └── dragonrx_rules.xml     # 8 custom rules: 100110-100170
│   │                                  # (installed via docker cp post-startup)
│   └── zeek/
│       └── local.zeek                 # Log4Shell JNDI header + long-label DNS detection
```

---

## Deploy from Git

The lab is published at **[github.com/anpa1200/dragonrx-lab](https://github.com/anpa1200/dragonrx-lab)**.

```bash
# Clone
git clone https://github.com/anpa1200/dragonrx-lab
cd dragonrx-lab

# Option A — Docker containers only (no Windows VMs, no Vagrant)
# Covers Log4Shell → JNDI → Sliver C2 → Wazuh/Zeek detection
docker compose up -d
until docker exec dragonrx_wazuh pgrep wazuh-analysisd >/dev/null 2>&1; do sleep 5; done
docker cp siem/wazuh/rules/dragonrx_rules.xml dragonrx_wazuh:/var/ossec/etc/rules/
docker exec dragonrx_wazuh /var/ossec/bin/wazuh-control restart
# → Kibana: http://localhost:5601

# Option B — Full lab (Docker + Windows VMs + Ansible)
bash scripts/deploy.sh        # one script, ~45 min
# or: make up
```

> **Zeek note:** Zeek runs with `network_mode: host` (no fixed IP). Logs live inside the `dragonrx_zeek` container: `docker exec dragonrx_zeek ls /usr/local/zeek/logs/current/`

---

## One-Script Deployment

For environments without `make`, or when a self-contained deploy is needed:

```bash
# Full deployment (identical to 'make up' + 'make test')
bash scripts/deploy.sh

# Skip Windows VMs (reuse already-running VMs)
bash scripts/deploy.sh --skip-vms

# Skip Ansible reprovisioning (reuse already-provisioned state)
bash scripts/deploy.sh --skip-vms --skip-ansible

# Deploy without running the final test suite
bash scripts/deploy.sh --no-test
```

`deploy.sh` performs all steps in sequence:

| Step | Action |
|------|--------|
| 0 | Preflight — verify all binaries, plugins, pywinrm |
| 1 | Load VBoxDRV kernel modules (auto-fixes if not loaded) |
| 2 | Download missing Vagrant boxes if not cached |
| 3 | `docker compose up -d` — start all 8 containers; install Wazuh rules via `docker cp` |
| 4 | `setup_routing.sh` — bridge Docker + VirtualBox on 192.168.10.0/24 |
| 5 | `vagrant up` — boot DC01, FS01, WS01 |
| 6 | `ansible-playbook deploy.yml` — AD, users, Wazuh agents, data |
| 7 | `ansible-playbook test.yml` — connectivity, services, detection validation |

Prints a formatted access summary on completion with elapsed time.

---

## Prerequisites

```bash
# Hardware minimum
CPU:  8 cores (VT-x/AMD-V required)
RAM:  32 GB  (Docker ~10 GB + 3 Windows VMs ~18 GB + headroom)
Disk: 250 GB SSD

# Software — install before running make up
docker >= 24.0
docker compose >= 2.20
vagrant >= 2.4.0
virtualbox >= 7.0
ansible >= 2.16
python3 >= 3.10

# Ansible collections + Python deps
pip3 install pywinrm requests
ansible-galaxy collection install -r ansible/requirements.yml
# requirements.yml covers:
#   ansible.windows, community.windows, microsoft.ad,
#   community.docker, community.general

# Vagrant plugins
vagrant plugin install vagrant-reload        # post-domain-join reboots
vagrant plugin install vagrant-hostmanager  # /etc/hosts management
```

---

## Vagrantfile

```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

WINDOWS_BOXES = {
  "DC01" => { box: "StefanScherer/windows_2019", ip: "192.168.10.10", memory: 4096, cpus: 2 },
  "FS01" => { box: "StefanScherer/windows_2019", ip: "192.168.10.20", memory: 4096, cpus: 2 },
  "WS01" => { box: "StefanScherer/windows_10",   ip: "192.168.10.50", memory: 4096, cpus: 2 },
}

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vagrant.plugins = ["vagrant-reload", "vagrant-hostmanager"]

  config.hostmanager.enabled      = true
  config.hostmanager.manage_host  = true
  config.hostmanager.manage_guest = true

  WINDOWS_BOXES.each do |name, cfg|
    config.vm.define name do |node|
      node.vm.box      = cfg[:box]
      node.vm.hostname = name.downcase

      # WinRM — Vagrant enables this automatically for Windows boxes
      node.vm.communicator         = "winrm"
      node.winrm.username          = "vagrant"
      node.winrm.password          = "vagrant"
      node.winrm.transport         = :negotiate
      node.winrm.basic_auth_only   = false

      # NIC 1: NAT (internet access for Windows Update / Vagrant)
      # NIC 2: host-only on 192.168.10.0/24 — lab network
      node.vm.network "private_network",
        ip:                  cfg[:ip],
        virtualbox__intnet:  false,
        name:                "vboxnet0"

      node.vm.provider "virtualbox" do |vb|
        vb.name   = "dragonrx_#{name.downcase}"
        vb.memory = cfg[:memory]
        vb.cpus   = cfg[:cpus]
        vb.gui    = false
        vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
        vb.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
      end

      # WinRM connectivity check — no shell provisioner needed;
      # Ansible handles all configuration post-boot.
      node.vm.provision "shell",
        inline:       "Write-Host 'VM #{name} ready for Ansible'",
        privileged:   true,
        powershell_elevated_interactive: false
    end
  end
end
```

**Vagrant boxes used:**
- `StefanScherer/windows_2019` — Windows Server 2019 Datacenter, WinRM pre-enabled, ~9 GB download
- `StefanScherer/windows_10` — Windows 10 22H2, ~8 GB download
- First `vagrant up` downloads boxes; subsequent runs use local cache

---

## docker-compose.yml

```yaml
version: "3.9"

networks:
  attacker_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.0.0/24
  target_net:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.10.0/24
          gateway: 192.168.10.254

services:

  # ── ATTACKER SIDE ───────────────────────────────────────────────────

  kali:
    image: kalilinux/kali-rolling:latest
    container_name: dragonrx_kali
    hostname: kali
    networks:
      attacker_net:
        ipv4_address: 10.0.0.5
      target_net:
        ipv4_address: 192.168.10.5
    tty: true
    stdin_open: true
    volumes:
      - ./attacker/tools:/opt/tools
      - ./attacker/loot:/opt/loot
    cap_add: [NET_ADMIN, NET_RAW]
    sysctls:
      net.ipv4.ip_forward: 1

  sliver_c2:
    build:
      context: ./c2
      dockerfile: Dockerfile.sliver
    image: dragonrx_sliver:local
    container_name: dragonrx_c2
    hostname: c2
    networks:
      attacker_net:
        ipv4_address: 10.0.0.10
    ports:
      - "31337:31337"   # Sliver multiplayer port (internal)
    volumes:
      - ./c2/configs:/root/.sliver
      - ./c2/loot:/opt/loot
    restart: unless-stopped

  jndi_server:
    build:
      context: ./jndi
      dockerfile: Dockerfile.jndi
    container_name: dragonrx_jndi
    hostname: jndi
    networks:
      attacker_net:
        ipv4_address: 10.0.0.20
    ports:
      - "1389:1389"   # LDAP relay (marshalsec)
      - "8888:8080"   # HTTP payload delivery

  # ── TARGET SIDE ─────────────────────────────────────────────────────

  web01:
    image: ghcr.io/christophetd/log4shell-vulnerable-app:latest
    container_name: dragonrx_web01
    hostname: web01
    networks:
      attacker_net:
        ipv4_address: 10.0.0.100
      target_net:
        ipv4_address: 192.168.10.100
    ports:
      - "8080:8080"
    environment:
      - DOMAIN_CONTROLLER=192.168.10.10
      - LDAP_USER=svc_ldap
      - LDAP_PASS=NovaTech2021!
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- --header='X-Api-Version: health' http://localhost:8080/ >/dev/null 2>&1 || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 5

  # ── SOC / DETECTION SIDE ────────────────────────────────────────────

  wazuh:
    image: wazuh/wazuh-manager:4.7.0
    container_name: dragonrx_wazuh
    hostname: wazuh
    networks:
      target_net:
        ipv4_address: 192.168.10.200
    ports:
      - "1514:1514/udp"   # agent syslog
      - "1515:1515"       # agent enrollment
      - "55000:55000"     # REST API
    volumes:
      - wazuh_data:/var/ossec/data
      # Custom rules are installed post-startup via docker cp (see Makefile / deploy.sh)
    healthcheck:
      test: ["CMD-SHELL", "pgrep wazuh-analysisd > /dev/null && pgrep wazuh-remoted > /dev/null"]
      interval: 20s
      retries: 5

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: dragonrx_elastic
    hostname: elastic
    networks:
      target_net:
        ipv4_address: 192.168.10.202
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms4g -Xmx4g
    volumes:
      - elastic_data:/usr/share/elasticsearch/data
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health | grep -v red"]
      interval: 20s
      retries: 10

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: dragonrx_kibana
    hostname: kibana
    networks:
      target_net:
        ipv4_address: 192.168.10.203
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://192.168.10.202:9200
    depends_on:
      elasticsearch:
        condition: service_healthy

  zeek:
    image: zeek/zeek:6.2.1
    container_name: dragonrx_zeek
    hostname: zeek
    network_mode: host
    volumes:
      - ./siem/zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro
      - zeek_logs:/usr/local/zeek/logs
    cap_add: [NET_ADMIN, NET_RAW]
    command: zeek -i any /usr/local/zeek/share/zeek/site/local.zeek

volumes:
  wazuh_data:
  elastic_data:
  zeek_logs:
```

---

## Ansible

### ansible/requirements.yml

```yaml
collections:
  - name: ansible.windows
    version: ">=2.3.0"
  - name: community.windows
    version: ">=2.2.0"
  - name: microsoft.ad
    version: ">=1.5.0"
  - name: community.docker
    version: ">=3.6.0"
  - name: community.general
    version: ">=8.0.0"
```

### ansible/ansible.cfg

```ini
[defaults]
inventory          = inventory/hosts.ini
roles_path         = roles
stdout_callback    = yaml
timeout            = 60
host_key_checking  = False

[winrm]
transport          = basic
server_cert_validation = ignore
```

### ansible/inventory/hosts.ini

```ini
[docker_linux]
web01    ansible_host=192.168.10.100  ansible_connection=docker  ansible_docker_extra_args="-u root"  ansible_container=dragonrx_web01
kali     ansible_host=10.0.0.5       ansible_connection=docker  ansible_container=dragonrx_kali

[windows]
dc01     ansible_host=192.168.10.10
fs01     ansible_host=192.168.10.20
ws01     ansible_host=192.168.10.50

[all:vars]
domain_name=novatech.local
domain_netbios=NOVATECH
domain_controller_ip=192.168.10.10
```

### ansible/inventory/group_vars/windows.yml

```yaml
ansible_user: vagrant
ansible_password: vagrant
ansible_connection: winrm
ansible_winrm_transport: basic
ansible_winrm_server_cert_validation: ignore
ansible_winrm_port: 5985
ansible_winrm_read_timeout_sec: 120
ansible_winrm_operation_timeout_sec: 90
ansible_become: false

domain_admin_user: Administrator
domain_admin_password: "NovaTech_Admin2024!"
safe_mode_password: "DragonRx2024!"
```

> **WinRM transport note:** `basic` is required. pywinrm 0.4.x lists `ntlm` (not `negotiate`) in its supported auth types, and OpenSSL 3.x removed the MD4 hash that NTLM depends on. `basic` over plain HTTP port 5985 works reliably with the StefanScherer Vagrant boxes.

### ansible/inventory/group_vars/all.yml

```yaml
# Lab user accounts (intentionally weak — simulation only)
lab_users:
  - name: jsmith
    password: "Research#2024"
    department: "R&D"
    local_admin_on: ws01

  - name: svc_ldap
    password: "NovaTech2021!"
    description: "LDAP service account — creds leaked in context.xml"
    password_never_expires: true

  - name: svc_backup
    password: "Backup_Svc99!"
    description: "Kerberoastable backup service account"
    password_never_expires: true
    spn: "MSSQLSvc/fs01.novatech.local:1433"
    member_of: "Backup Operators"

wazuh_manager_ip: 192.168.10.200
```

---

## Ansible Roles

### roles/dc01/tasks/main.yml

```yaml
---
- name: Install AD DS role
  ansible.windows.win_feature:
    name: AD-Domain-Services
    include_management_tools: true
    state: present
  register: ad_feature

- name: Reboot after AD DS install
  ansible.windows.win_reboot:
    reboot_timeout: 300
    post_reboot_delay: 30
  when: ad_feature.reboot_required

- name: Set local Administrator password (required before DC promotion)
  ansible.windows.win_user:
    name: Administrator
    password: "{{ domain_admin_password }}"
    state: present

- name: Promote to Domain Controller
  microsoft.ad.domain:
    dns_domain_name: "{{ domain_name }}"
    domain_netbios_name: "{{ domain_netbios }}"
    safe_mode_password: "{{ safe_mode_password }}"
    reboot: false
  register: domain_result

- name: Reboot after domain promotion
  ansible.windows.win_reboot:
    reboot_timeout: 1200
    post_reboot_delay: 120
    connect_timeout: 60
  when: domain_result.changed or domain_result.reboot_required | default(false)

- name: Wait for AD web services
  ansible.windows.win_wait_for:
    port: 389
    host: 127.0.0.1
    timeout: 120

- name: Create domain users
  microsoft.ad.user:
    name: "{{ item.name }}"
    sam_account_name: "{{ item.name }}"
    password: "{{ item.password }}"
    password_never_expires: "{{ item.password_never_expires | default(false) }}"
    description: "{{ item.description | default(omit) }}"
    enabled: true
    state: present
  loop: "{{ lab_users }}"

- name: Set SPN on svc_backup (Kerberoastable)
  ansible.windows.win_powershell:
    script: |
      $spn  = "{{ item.spn }}"
      $acct = "{{ domain_netbios }}\{{ item.name }}"
      $existing = & setspn -L "{{ item.name }}" 2>&1
      if ($existing -notmatch [regex]::Escape($spn)) {
          & setspn -S $spn $acct
          Write-Output "SPN set: $spn on $acct"
      } else {
          Write-Output "SPN already present: $spn"
      }
  loop: "{{ lab_users | selectattr('spn', 'defined') | list }}"

- name: Add svc_backup to Backup Operators
  ansible.windows.win_powershell:
    script: |
      $members = (Get-ADGroupMember "Backup Operators").SamAccountName
      if ($members -notcontains "svc_backup") {
          Add-ADGroupMember -Identity "Backup Operators" -Members "svc_backup"
          Write-Output "Added svc_backup to Backup Operators"
      } else {
          Write-Output "svc_backup already in Backup Operators"
      }

- name: Enable Directory Service Access auditing (required for DCSync EID 4662)
  ansible.windows.win_command: >
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

- name: Set SACL on domain NC for DCSync detection
  ansible.windows.win_powershell:
    script: |
      $rootDSE   = [ADSI]"LDAP://RootDSE"
      $defaultNC = $rootDSE.defaultNamingContext
      $acl       = (Get-Acl "AD:\$defaultNC")
      $identity  = [System.Security.Principal.NTAccount]"Everyone"
      $adRights  = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
      $type      = [System.Security.AccessControl.AccessControlType]"Success"
      $inherit   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
      $guidAll   = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
      $ace = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
          $identity, $adRights, $type, $guidAll, $inherit)
      $acl.AddAuditRule($ace)
      Set-Acl "AD:\$defaultNC" $acl
      Write-Output "SACL configured for DCSync detection (EID 4662)"

- name: Set DNS forwarder
  ansible.windows.win_powershell:
    script: |
      Set-DnsServerForwarder -IPAddress "8.8.8.8" -PassThru
```

> **DC promotion notes:**
> - The `reboot` flag is set to `false` so Ansible controls the reboot window. `reboot_timeout: 1200` is needed — DC promotion + AD DS initialization takes several minutes post-reboot.
> - `microsoft.ad.domain` does not accept a `state` parameter; idempotency is handled by the module internally.
> - The local Administrator password must be set before `DCPromo` or promotion exits with code 94 (blank password rejected).

### roles/fs01/tasks/main.yml

```yaml
---
- name: Wait for DC01 LDAP
  ansible.windows.win_wait_for:
    host: "{{ domain_controller_ip }}"
    port: 389
    timeout: 300

- name: Set DNS to DC01 on target_net NIC (required for domain join)
  ansible.windows.win_powershell:
    script: |
      $defIdx = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
                 Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
      $nic2 = Get-NetAdapter |
              Where-Object { $_.InterfaceIndex -ne $defIdx -and $_.Status -eq 'Up' } |
              Select-Object -First 1
      if ($nic2) {
          Set-DnsClientServerAddress -InterfaceIndex $nic2.InterfaceIndex `
              -ServerAddresses "{{ domain_controller_ip }}"
          Write-Output "DNS set to {{ domain_controller_ip }} on $($nic2.Name)"
      } else {
          throw "NIC2 not found — cannot set DNS"
      }

- name: Join domain
  microsoft.ad.membership:
    dns_domain_name: "{{ domain_name }}"
    domain_admin_user: "{{ domain_netbios }}\\{{ domain_admin_user }}"
    domain_admin_password: "{{ domain_admin_password }}"
    state: domain
  register: domain_join

- name: Reboot after domain join
  ansible.windows.win_reboot:
    reboot_timeout: 300
  when: domain_join.changed

- name: Create crown jewel directories
  ansible.windows.win_file:
    path: "{{ item }}"
    state: directory
  loop:
    - C:\Research
    - C:\Manufacturing
    - C:\SYSVOL_backup

- name: Generate dummy Phase III trial data
  ansible.windows.win_powershell:
    script: |
      1..30 | ForEach-Object {
        $content = "Phase III Antiviral Trial Data - Subject ID: $_ - Visit: $(Get-Date -Format yyyy-MM-dd)"
        $content | Out-File "C:\Research\clinical_data_record_$_.csv" -Encoding UTF8
      }
      1..15 | ForEach-Object {
        $content = "Proprietary Synthesis Process v2.3 - Batch $_ - CONFIDENTIAL"
        $content | Out-File "C:\Manufacturing\synthesis_process_$_.docx" -Encoding UTF8
      }
      "NovaTech Phase III NDA Filing 2026 - RESTRICTED" | Out-File "C:\Research\NDA_filing_2026.pdf" -Encoding UTF8
      Write-Output "Crown jewel data created"

- name: Create SMB shares
  ansible.windows.win_share:
    name: "{{ item.name }}"
    path: "{{ item.path }}"
    full: "{{ item.full }}"
    read: "{{ item.read }}"
    state: present
  loop:
    - name: Research
      path: C:\Research
      full: "NOVATECH\\jsmith"
      read: "NOVATECH\\Domain Users"
    - name: Manufacturing
      path: C:\Manufacturing
      full: "NOVATECH\\Administrator"
      read: "NOVATECH\\jsmith"
```

> **DNS pre-join note:** NIC2 (the host-only 192.168.10.0/24 adapter) must resolve `novatech.local` before the domain join module runs. Setting DNS to DC01 on NIC2 before calling `microsoft.ad.membership` is required — without it the join fails with "domain does not exist or could not be contacted."

### roles/ws01/tasks/main.yml

```yaml
---
- name: Wait for DC01 LDAP
  ansible.windows.win_wait_for:
    host: "{{ domain_controller_ip }}"
    port: 389
    timeout: 300

- name: Set DNS to DC01 on target_net NIC (required for domain join)
  ansible.windows.win_powershell:
    script: |
      $defIdx = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
                 Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
      $nic2 = Get-NetAdapter |
              Where-Object { $_.InterfaceIndex -ne $defIdx -and $_.Status -eq 'Up' } |
              Select-Object -First 1
      if ($nic2) {
          Set-DnsClientServerAddress -InterfaceIndex $nic2.InterfaceIndex `
              -ServerAddresses "{{ domain_controller_ip }}"
          Write-Output "DNS set to {{ domain_controller_ip }} on $($nic2.Name)"
      } else {
          throw "NIC2 not found — cannot set DNS"
      }

- name: Join domain
  microsoft.ad.membership:
    dns_domain_name: "{{ domain_name }}"
    domain_admin_user: "{{ domain_netbios }}\\{{ domain_admin_user }}"
    domain_admin_password: "{{ domain_admin_password }}"
    state: domain
  register: domain_join

- name: Reboot after domain join
  ansible.windows.win_reboot:
    reboot_timeout: 300
  when: domain_join.changed

- name: Enable SMB and set target_net NIC to Private profile
  ansible.windows.win_powershell:
    script: |
      Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
      $defIdx = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
                 Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
      $nic2 = Get-NetAdapter |
              Where-Object { $_.InterfaceIndex -ne $defIdx -and $_.Status -eq 'Up' } |
              Select-Object -First 1
      if ($nic2) {
          Set-NetConnectionProfile -InterfaceIndex $nic2.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue
      }

- name: Add jsmith as local administrator
  ansible.windows.win_group_membership:
    name: Administrators
    members: ["NOVATECH\\jsmith"]
    state: present

- name: Create C:\Temp for staging artifacts
  ansible.windows.win_file:
    path: C:\Temp
    state: directory
```

> **SMB firewall note:** Windows 10 disables File and Printer Sharing by default, and the Docker bridge NIC gets a "Public" network profile which blocks SMB. `Enable-NetFirewallRule` opens the rule for all profiles; `Set-NetConnectionProfile` downgrades the lab NIC to Private so Windows Security Center stops complaining.

### roles/wazuh_agent/tasks/main.yml

```yaml
---
- name: Ensure C:\Temp exists
  ansible.windows.win_file:
    path: C:\Temp
    state: directory

- name: Download Wazuh agent MSI
  ansible.windows.win_get_url:
    url: "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi"
    dest: C:\Temp\wazuh-agent.msi

- name: Install Wazuh agent
  ansible.windows.win_package:
    path: C:\Temp\wazuh-agent.msi
    product_id: "{54E68B4D-3C4E-4D9C-8E65-C4A62C6B9E7A}"
    arguments: >-
      WAZUH_MANAGER="{{ wazuh_manager_ip }}"
      WAZUH_REGISTRATION_SERVER="{{ wazuh_manager_ip }}"
      WAZUH_AGENT_NAME="{{ inventory_hostname }}"
    state: present

- name: Start and enable Wazuh agent
  ansible.windows.win_service:
    name: WazuhSvc
    state: started
    start_mode: auto
```

---

## Master Deploy Playbook

### ansible/playbooks/deploy.yml

```yaml
---
# Operation DragonRx — Full Lab Deploy
# Usage: ansible-playbook ansible/playbooks/deploy.yml
# Run after: docker compose up -d && vagrant up

- name: "Phase 1 — Verify Docker services healthy"
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Wait for Wazuh manager API
      ansible.builtin.wait_for:
        host: 127.0.0.1
        port: 55000
        timeout: 120

    - name: Wait for Kibana (implicitly confirms Elasticsearch)
      ansible.builtin.uri:
        url: http://localhost:5601/api/status
        status_code: 200
      register: kibana_health
      until: kibana_health.status == 200
      retries: 30
      delay: 10

- name: "Phase 2 — Configure DC01 (Active Directory)"
  hosts: dc01
  gather_facts: true
  pre_tasks:
    - name: Set computer name to DC01
      ansible.windows.win_hostname:
        name: DC01
      register: dc01_name
    - name: Reboot if hostname changed
      ansible.windows.win_reboot:
        reboot_timeout: 300
        post_reboot_delay: 30
      when: dc01_name.reboot_required
  roles:
    - dc01
    - wazuh_agent

- name: "Phase 3 — Configure FS01 (File Server)"
  hosts: fs01
  gather_facts: true
  pre_tasks:
    - name: Set computer name to FS01
      ansible.windows.win_hostname:
        name: FS01
      register: fs01_name
    - name: Reboot if hostname changed
      ansible.windows.win_reboot:
        reboot_timeout: 300
        post_reboot_delay: 30
      when: fs01_name.reboot_required
  roles:
    - fs01
    - wazuh_agent

- name: "Phase 4 — Configure WS01 (Workstation)"
  hosts: ws01
  gather_facts: true
  pre_tasks:
    - name: Set computer name to WS01
      ansible.windows.win_hostname:
        name: WS01
      register: ws01_name
    - name: Reboot if hostname changed
      ansible.windows.win_reboot:
        reboot_timeout: 300
        post_reboot_delay: 30
      when: ws01_name.reboot_required
  roles:
    - ws01
    - wazuh_agent

- name: "Phase 5 — Configure SIEM indexes"
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Create Kibana index pattern for Wazuh
      ansible.builtin.uri:
        url: http://localhost:5601/api/saved_objects/index-pattern
        method: POST
        headers:
          Content-Type: application/json
          kbn-xsrf: "true"
        body_format: json
        body:
          attributes:
            title: "wazuh-alerts-*"
            timeFieldName: "@timestamp"
        status_code: [200, 409]

    - name: Create Kibana index pattern for Zeek
      ansible.builtin.uri:
        url: http://localhost:5601/api/saved_objects/index-pattern
        method: POST
        headers:
          Content-Type: application/json
          kbn-xsrf: "true"
        body_format: json
        body:
          attributes:
            title: "zeek-*"
            timeFieldName: "@timestamp"
        status_code: [200, 409]

- name: "Phase 6 — Run smoke tests"
  import_playbook: test.yml
```

---

## Test Playbook

### ansible/playbooks/test.yml

```yaml
---
# Smoke tests + detection validation
# Usage: ansible-playbook ansible/playbooks/test.yml

- name: "Test 1 — Network connectivity"
  hosts: localhost
  gather_facts: false
  vars:
    connectivity_checks:
      - {host: 127.0.0.1,       port: 8080, name: "WEB01 patient portal"}
      - {host: 192.168.10.10,   port: 389,  name: "DC01 LDAP"}
      - {host: 192.168.10.10,   port: 445,  name: "DC01 SMB"}
      - {host: 192.168.10.20,   port: 445,  name: "FS01 SMB"}
      - {host: 192.168.10.50,   port: 445,  name: "WS01 SMB"}
      - {host: 127.0.0.1,       port: 1515, name: "Wazuh enrollment"}
      - {host: 192.168.10.202,  port: 9200, name: "Elasticsearch"}
      - {host: 127.0.0.1,       port: 5601, name: "Kibana"}
      - {host: 127.0.0.1,       port: 1389, name: "JNDI LDAP server"}
      - {host: 127.0.0.1,       port: 8888, name: "JNDI payload server"}
  tasks:
    - name: Check TCP connectivity to all services
      ansible.builtin.wait_for:
        host: "{{ item.host }}"
        port: "{{ item.port }}"
        timeout: 30
      loop: "{{ connectivity_checks }}"
      loop_control:
        label: "{{ item.name }}"

- name: "Test 2 — Windows services"
  hosts: windows
  gather_facts: false
  tasks:
    - name: Verify Wazuh agent running
      ansible.windows.win_service_info:
        name: WazuhSvc
      register: wazuh_info
      failed_when: wazuh_info.services | length == 0 or wazuh_info.services[0].state != "started"

- name: "Test 3 — Active Directory state"
  hosts: dc01
  gather_facts: false
  tasks:
    - name: Verify domain functional
      ansible.windows.win_powershell:
        script: |
          $domain = Get-ADDomain -ErrorAction Stop
          if ($domain.DNSRoot -ne "novatech.local") {
            Write-Error "Domain mismatch: $($domain.DNSRoot)"; exit 1
          }
          Write-Output "Domain OK: $($domain.DNSRoot)"

    - name: Verify all lab users present
      ansible.windows.win_powershell:
        script: |
          $users = @("jsmith", "svc_ldap", "svc_backup")
          foreach ($u in $users) {
            if (-not (Get-ADUser $u -ErrorAction SilentlyContinue)) {
              Write-Error "Missing user: $u"; exit 1
            }
          }
          Write-Output "All lab users present"

    - name: Verify svc_backup SPN set (Kerberoastable)
      ansible.windows.win_powershell:
        script: |
          $spns = (Get-ADUser svc_backup -Properties ServicePrincipalNames).ServicePrincipalNames
          if ($spns -notcontains "MSSQLSvc/fs01.novatech.local:1433") {
            Write-Error "Kerberoastable SPN missing"; exit 1
          }
          Write-Output "SPN OK: $spns"

    - name: Verify Directory Service Access auditing enabled
      ansible.windows.win_powershell:
        script: |
          $result = auditpol /get /subcategory:"Directory Service Access"
          if ($result -notmatch "Success") {
            Write-Error "DS Access auditing not enabled — EID 4662 will not fire"; exit 1
          }
          Write-Output "Audit policy OK"

- name: "Test 4 — Detection validation (fire test payloads)"
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Fire JNDI DNS probe (benign — no code execution)
      ansible.builtin.uri:
        url: http://192.168.10.100:8080/api/login
        method: POST
        headers:
          X-Api-Version: "${jndi:dns://10.0.0.20/test-probe}"
          Content-Type: application/json
        body: '{"username":"test","password":"probe"}'
        body_format: raw
        validate_certs: false
        status_code: [200, 400, 401, 500]
      register: probe_result

    - name: Wait 10 seconds for Zeek to process
      ansible.builtin.pause:
        seconds: 10

    - name: Check Zeek logged the JNDI pattern
      ansible.builtin.shell: |
        grep -rl "jndi" \
          /var/lib/docker/volumes/dragonrx-lab_zeek_logs/_data/current/ 2>/dev/null \
          | head -1
      register: zeek_detection
      delegate_to: localhost
      failed_when: zeek_detection.stdout == ""
      changed_when: false

    - name: Check Elasticsearch received Wazuh alerts (last 5 min)
      ansible.builtin.uri:
        url: "http://192.168.10.202:9200/wazuh-alerts-*/_search"
        method: POST
        headers:
          Content-Type: application/json
        body_format: json
        body:
          query:
            bool:
              must:
                - range:
                    "@timestamp":
                      gte: "now-5m"
          size: 1
        status_code: 200
      register: wazuh_alerts
      failed_when: wazuh_alerts.json.hits.total.value == 0

    - name: "DETECTION REPORT"
      ansible.builtin.debug:
        msg:
          - "JNDI probe HTTP status : {{ probe_result.status }}"
          - "Zeek detection log     : {{ zeek_detection.stdout | default('NOT DETECTED') }}"
          - "Wazuh alerts (5m)      : {{ wazuh_alerts.json.hits.total.value }}"
```

---

## Zeek Config

### siem/zeek/local.zeek

```zeek
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/smb

# Log4Shell JNDI detection
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( is_orig && /\$\{[a-zA-Z0-9_\-:\/\.]*jndi[a-zA-Z0-9_\-:\/\.]*:/ in value ) {
        NOTICE([$note=Notice::LOG, $conn=c,
                $msg=fmt("Log4Shell JNDI in header %s: %s", name, value),
                $identifier=cat(c$id)]);
    }
}

# DNS tunnel heuristic — labels >40 chars are characteristic of data-exfil tunnels
# (legitimate public labels rarely exceed 30 chars)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local parts = split_string(query, /\./);
    if ( |parts| > 0 ) {
        local first_label = parts[0];
        if ( |first_label| > 40 )
            NOTICE([$note=Notice::LOG, $conn=c,
                    $msg=fmt("Suspicious long DNS label (tunnel?): %s", query),
                    $identifier=cat(c$id)]);
    }
}
```

---

## Host Networking Setup

### scripts/setup_routing.sh

```bash
#!/usr/bin/env bash
# Bridges Docker target_net and VirtualBox vboxnet0 so containers and VMs can communicate.
# Run once after `docker compose up -d` and before `vagrant up`.

set -euo pipefail

echo "[*] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.d/99-dragonrx.conf >/dev/null

echo "[*] Finding Docker target_net bridge..."
DOCKER_NET_ID=$(docker network ls --filter name=dragonrx --format "{{.ID}}" | head -1)
if [[ -z "$DOCKER_NET_ID" ]]; then
    echo "[!] Docker network not found — run 'docker compose up -d' first"
    exit 1
fi
DOCKER_BRIDGE="br-${DOCKER_NET_ID:0:12}"
echo "    Bridge: $DOCKER_BRIDGE"

echo "[*] Ensuring vboxnet0 exists..."
if ! ip link show vboxnet0 &>/dev/null; then
    VBoxManage hostonlyif create
    VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.10.1 --netmask 255.255.255.0
fi

# Remove stale kernel route that may point 192.168.10.0/24 at a dead interface
if ip route show 192.168.10.0/24 | grep -q vboxnet0; then
    sudo ip route del 192.168.10.0/24 dev vboxnet0 2>/dev/null || true
fi

echo "[*] Adding iptables FORWARD rules..."
sudo iptables -I FORWARD -i "$DOCKER_BRIDGE" -o vboxnet0       -j ACCEPT
sudo iptables -I FORWARD -i vboxnet0       -o "$DOCKER_BRIDGE" -j ACCEPT
sudo iptables -t nat -I POSTROUTING -s 192.168.10.0/24 -j MASQUERADE

echo "[*] Setting promiscuous mode on bridge..."
sudo ip link set "$DOCKER_BRIDGE" promisc on

echo "[+] Routing configured. Docker target_net ↔ VirtualBox vboxnet0 bridged."
```

---

## Makefile

```makefile
.PHONY: up down reset test attack status logs shell

ANSIBLE_DIR    := ansible
PLAYBOOK_FLAGS := -v

# ─────────────────────────────────────────────────────────────────
# Primary targets
# ─────────────────────────────────────────────────────────────────

up: deps
	@echo "==> Starting Docker services..."
	docker compose up -d
	@echo "==> Configuring host routing..."
	bash scripts/setup_routing.sh
	@echo "==> Starting Windows VMs..."
	vagrant up --provider virtualbox
	@echo "==> Running Ansible provisioning..."
	ansible-galaxy collection install -r $(ANSIBLE_DIR)/requirements.yml
	ansible-playbook $(ANSIBLE_DIR)/playbooks/deploy.yml $(PLAYBOOK_FLAGS)
	@echo ""
	@echo "==> Lab ready. Access points:"
	@echo "    Kibana   : http://localhost:5601"
	@echo "    Kali     : make shell"
	@echo "    Sliver   : docker exec -it dragonrx_c2 sliver"

down:
	@echo "==> Stopping VMs..."
	vagrant halt
	@echo "==> Stopping Docker services..."
	docker compose down
	@echo "==> Lab stopped (data volumes preserved)"

reset:
	@echo "==> Full reset — destroying all state..."
	vagrant destroy -f
	docker compose down -v
	@echo "==> Reset complete. Run 'make up' to redeploy."

test:
	@echo "==> Running smoke tests and detection validation..."
	ansible-playbook $(ANSIBLE_DIR)/playbooks/test.yml $(PLAYBOOK_FLAGS)

attack:
	@echo "==> Launching attack simulation from Kali..."
	docker exec -it dragonrx_kali bash /opt/tools/run_attack.sh

# ─────────────────────────────────────────────────────────────────
# Utility targets
# ─────────────────────────────────────────────────────────────────

status:
	@echo "--- Docker ---"
	@docker compose ps
	@echo ""
	@echo "--- Vagrant ---"
	@vagrant status

logs:
	docker compose logs -f --tail=50

shell:
	docker exec -it dragonrx_kali /bin/bash

deps:
	@command -v docker    >/dev/null || (echo "docker not found"    && exit 1)
	@command -v vagrant   >/dev/null || (echo "vagrant not found"   && exit 1)
	@command -v ansible   >/dev/null || (echo "ansible not found"   && exit 1)
	@command -v VBoxManage >/dev/null || (echo "VBoxManage not found" && exit 1)
	@python3 -c "import winrm" 2>/dev/null || pip3 install pywinrm -q
	@echo "[+] All prerequisites satisfied"
```

---

## Deploy Sequence

```
make up
  │
  ├─ deps                           check docker / vagrant / ansible / VBoxManage
  ├─ docker compose up -d           start Linux containers (Kali, Sliver, JNDI, Web01, SIEM)
  ├─ scripts/setup_routing.sh       bridge Docker target_net ↔ VirtualBox vboxnet0
  ├─ vagrant up                     boot DC01 + FS01 + WS01 (downloads boxes on first run ~25 GB)
  └─ ansible-playbook deploy.yml
        │
        ├─ Phase 1  verify Docker services healthy (Wazuh API + Kibana)
        ├─ Phase 2  DC01: set hostname → AD DS install → reboot → set admin password →
        │           domain promotion → reboot → users → SPNs → audit policy → SACL → Wazuh agent
        ├─ Phase 3  FS01: set hostname → set DNS → domain join → reboot →
        │           crown jewel data → SMB shares → Wazuh agent
        ├─ Phase 4  WS01: set hostname → set DNS → domain join → reboot →
        │           SMB firewall → jsmith local admin → C:\Temp → Wazuh agent
        ├─ Phase 5  SIEM: Kibana index patterns (wazuh-alerts-*, zeek-*)
        └─ Phase 6  test.yml: connectivity, Wazuh service, AD state, detection validation
```

**Expected duration:**

| Step | Time |
|------|------|
| `docker compose up -d` | 2–3 min |
| `vagrant up` (boxes cached) | 8–12 min |
| `vagrant up` (first run, box download) | 30–60 min |
| Ansible provisioning | 10–15 min |
| **Total (boxes cached)** | **~25 min** |
| **Total (first run)** | **~90 min** |

---

## VM Specifications

Three Windows VMs managed by Vagrant and VirtualBox. All use WinRM for Ansible communication; no manual RDP setup required.

| VM | Box | vCPU | RAM | Disk | Role |
|----|-----|------|-----|------|------|
| DC01 | StefanScherer/windows_2019 | 2 | 4 GB | 60 GB | Domain Controller, DNS |
| FS01 | StefanScherer/windows_2019 | 2 | 4 GB | 60 GB | File Server (crown jewels) |
| WS01 | StefanScherer/windows_10   | 2 | 4 GB | 60 GB | Researcher Workstation |

**DC01 — Domain Controller (`192.168.10.10`)**
Runs AD DS for `novatech.local`. Ansible configures: domain promotion, DNS, user accounts (`jsmith`, `svc_ldap`, `svc_backup`), Kerberoastable SPN (`MSSQLSvc/fs01.novatech.local:1433`), Directory Service Access audit policy, SACL on the domain naming context (EID 4662 for DCSync detection), Wazuh agent enrollment.

**FS01 — File Server (`192.168.10.20`)**
Joined to `novatech.local`. Hosts two SMB shares:
- `\\FS01\Research` — synthetic Phase III clinical trial documents (CSVs, PDFs)
- `\\FS01\Manufacturing` — synthetic formulation data (DOCX)

Crown jewel data is generated by Ansible via PowerShell. This is the primary collection and exfiltration target.

**WS01 — Researcher Workstation (`192.168.10.50`)**
Windows 10 joined to the domain. User `jsmith` has local admin rights. Used as a lateral movement pivot target (Pass-the-Hash / Pass-the-Ticket from DC01 credential dump).

---

## Full Lab Environment Summary

| Layer | Component | Count | Purpose |
|-------|-----------|-------|---------|
| Docker containers | Kali, Sliver C2, JNDI server, WEB01, Wazuh, Elasticsearch, Kibana, Zeek | 8 | Attacker tooling + Linux target + SIEM/SOC |
| Vagrant VMs | DC01, FS01, WS01 | 3 | Windows AD environment (crown jewels) |
| Networks | `attacker_net` 10.0.0.0/24 · `target_net` 192.168.10.0/24 | 2 | Isolated attacker ↔ target segments |
| Detection | Wazuh 4.7 · Elastic 8.x · Zeek 6.2 | — | SIEM, NIDS, Windows Security event telemetry |
| Exploitation | Log4Shell CVE-2021-44228 · Marshalsec LDAP relay | — | Initial access chain |
| C2 | Sliver v1.7.3 (custom build) | — | Post-exploitation framework |
| Custom malware | RxPhage (Go RAT) | — | PlugX-lite beacon, DLL sideloading |

**Minimum host requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 16 GB | 24 GB |
| vCPU | 8 cores | 12 cores |
| Disk | 80 GB free | 120 GB SSD |
| OS | Linux (kernel ≥ 5.15) | Ubuntu 22.04 / Debian 12 |
| Software | Docker ≥ 24, VirtualBox ≥ 7.0, Vagrant ≥ 2.4, Ansible ≥ 2.16 | — |

**Access points once deployed:**

| Service | URL / Command | Credentials |
|---------|--------------|-------------|
| Kibana SIEM | `http://localhost:5601` | — (no auth, xpack.security disabled) |
| Wazuh API | `http://localhost:55000` | `wazuh-wui` / `MyS3cr37P450r.*-` |
| Sliver C2 | `docker exec -it dragonrx_c2 sliver` | — |
| Kali shell | `docker exec -it dragonrx_kali bash` | — |
| WEB01 (Log4Shell) | `http://localhost:8080/` | — |
| DC01 RDP | `192.168.10.10:3389` | `NOVATECH\Administrator` / `NovaTech_Admin2024!` |
| FS01 RDP | `192.168.10.20:3389` | `NOVATECH\Administrator` / `NovaTech_Admin2024!` |
| WS01 RDP | `192.168.10.50:3389` | `NOVATECH\jsmith` / `Research#2024` |

---

*Next: [attack-playbook.md](attack-playbook.md) — phase-by-phase attack commands.*
