---
layout: default
title: Hunting Exercise - 113
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Linux Privileged Container HostPID Escape Dataset

This hunt uses a simulated Kubernetes audit and node-level auditd dataset (`k8s_hostpid_escape_2022-12-04T101500.json`) capturing **T1611: Escape to Host**, where a pod deployed with `hostPID: true` and elevated capabilities enumerates and interacts with host-namespace processes via `/proc/<pid>/root` or `nsenter`, breaking container isolation to execute commands directly on the underlying node.

#### Step 1: Hypothesis Formation
**Hypothesis**: A pod is created with `hostPID: true` and/or `privileged: true` in its security context, and its container process subsequently accesses `/proc/1/root/` (the host's root filesystem as seen through PID 1) or invokes `nsenter` targeting a host PID, indicating deliberate container-escape activity rather than a legitimate need for host-process visibility. Indicators:
- Kubernetes audit log shows pod creation with `spec.hostPID: true` combined with `securityContext.privileged: true` or elevated `capabilities.add` (e.g., `SYS_ADMIN`, `SYS_PTRACE`).
- Node-level auditd shows the container's process performing `open`/`chroot` syscalls against `/proc/1/root/*` paths.
- Execution of `nsenter --target 1 --mount --uts --ipc --net --pid` or equivalent namespace-joining commands from within the container's process tree.
- The pod's originating namespace/workload has no documented operational requirement (e.g., a legitimate node-monitoring DaemonSet) for host-PID visibility.

**Null Hypothesis**: The pod is an approved node-monitoring or logging DaemonSet (e.g., Falco, Datadog agent, node-exporter) that legitimately requires `hostPID` to observe host-level processes as part of its documented function. Invalidate by checking the pod's namespace/service-account against the approved privileged-workload inventory.

**Rationale**: `hostPID`/`privileged` pods are sometimes legitimately required for infrastructure tooling, so the presence of the capability alone is not sufficient evidence of compromise; the decisive signal is the container process actually using that capability to traverse into the host's process/filesystem namespace via `/proc/1/root` or `nsenter`, which has no purpose other than breaking out of the container boundary.

#### Step 2: Data Sources and Scope
- **Sources**: Kubernetes API audit logs; node-level auditd/Falco runtime telemetry; privileged-workload approval inventory (admission-controller exceptions).
- **Scope**: ~2022-12-04T10:15:00-10:17:40 UTC; Cluster: `prod-cluster-east`; Pod: `debug-tools-7f9c` (namespace `default`); Node: `node-worker-14`.
- **SIEM Queries** (Splunk/ELK):
  - `index=k8s_audit verb=create objectRef.resource=pods requestObject.spec.hostPID=true`
  - Escape-attempt detection (Falco-style): `index=falco rule="Container Root Directory via HostPID Escape" OR rule="Launch Privileged Container"`
  - Namespace-join detection: `index=auditd exe="/usr/bin/nsenter" args="*--target 1*"`

#### Step 3: Key Findings
Parsed events (5 shown) confirm a pod named to resemble a debugging utility was deployed with `hostPID: true` and `SYS_ADMIN` capability in the `default` namespace (not an approved system namespace), and its container process used `nsenter` to obtain a root shell on the underlying node.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-12-04 10:15:03 | k8s-api-server | K8s Audit Log | `verb=create`, `pod=debug-tools-7f9c`, `namespace=default`, `spec.hostPID=true`, `capabilities.add=["SYS_ADMIN"]` | **Configuration IOC**: this combination of `hostPID` and `SYS_ADMIN` in the unrestricted `default` namespace, rather than a controlled system namespace, has no legitimate application justification and directly enables host-namespace traversal. |
| 2022-12-04 10:15:03 | k8s-api-server | (Admission-controller check) | Pod is not covered by any entry in the approved-privileged-workload exception list | **Unauthorized-Privilege IOC**: no policy exception authorizes this specific pod/namespace combination for privileged/hostPID access. |
| 2022-12-04 10:16:18 | node-worker-14 | Falco (Runtime Alert) | Rule `Launch Privileged Container` triggered for container `debug-tools-7f9c` | **Runtime-Confirmation IOC**: independent runtime telemetry corroborates the privileged configuration was actively used, not merely declared. |
| 2022-12-04 10:16:41 | node-worker-14 | auditd (execve) | `nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash` executed inside the container's process namespace | **Escape-Execution IOC**: this is the canonical container-escape command, using PID 1 (the host's init process) as the namespace target to obtain a full host-context shell. |
| 2022-12-04 10:16:42 | node-worker-14 | auditd (execve) | Resulting shell executed `cat /etc/shadow` and `id` - output showed `uid=0(root)` in the **host's** namespace | **Impact Confirmation**: successful read of the host's shadow file and root UID confirms full container-escape to host-level root access was achieved. |

**Validation**:
- **Timeline**: an unauthorized privileged/hostPID pod deployment, runtime confirmation of privileged execution, and an `nsenter`-based namespace escape yielding host-root shell access form a complete container-escape chain.
- **False Positives**: no admission-controller exception or approved-workload inventory entry covers this pod.
- **Correlation**: unauthorized configuration, runtime-alert corroboration, and explicit escape-tooling execution jointly confirm a successful container-to-host escape.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Cordon and drain node-worker-14, delete the offending pod and investigate the deploying service account/CI-CD pipeline for compromise, and treat the underlying node as fully compromised (rebuild rather than clean) given confirmed host-root access.
- **Detection**: Sigma-style rule: `title: Container Namespace Escape via Nsenter Targeting PID 1` → `selection: exe="/usr/bin/nsenter" args="*--target 1*"` → `condition: selection`.
- **Pro Tip**: Enforce a Pod Security Admission policy (`restricted` profile) cluster-wide that denies `hostPID`, `hostNetwork`, `privileged: true`, and dangerous capabilities by default, with narrow, explicitly-reviewed exceptions only for verified system-namespace DaemonSets - this prevents the escape prerequisite from ever being deployable outside a tightly controlled allow-list.

Hypothesis **confirmed**-an unauthorized privileged pod deployed with `hostPID` and `SYS_ADMIN` in the default namespace used `nsenter` to escape into the underlying node's namespace, confirming full host-root access!
