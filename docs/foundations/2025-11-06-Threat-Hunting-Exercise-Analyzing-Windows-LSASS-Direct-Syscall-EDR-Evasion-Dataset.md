---
layout: default
title: Hunting Exercise - 107
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Windows LSASS Direct Syscall EDR Evasion Dataset

This hunt uses a simulated EDR/kernel-telemetry dataset (`win_lsass_directsyscall_2022-11-22T153000.json`) capturing **T1055 / T1003.001: OS Credential Dumping: LSASS Memory via Direct/Indirect Syscalls**, where an attacker tool (e.g., a custom Nighthawk or Cobalt Strike BOF loader) invokes `NtOpenProcess`/`NtReadVirtualMemory` directly rather than through the monitored `ntdll.dll` API, evading user-mode EDR hooks entirely.

#### Step 1: Hypothesis Formation
**Hypothesis**: A non-security process obtains a handle to `lsass.exe` and reads its memory, but EDR user-mode API-hook telemetry shows no corresponding `ntdll!NtOpenProcess`/`ntdll!NtReadVirtualMemory` call logged for that process - while kernel-level (ETW-TI or driver-based) telemetry confirms the syscalls did occur - indicating the process used direct or indirect syscalls to bypass user-mode hooking. Indicators:
- Kernel/ETW-Threat-Intelligence telemetry shows a process obtained a handle with `PROCESS_VM_READ`/`PROCESS_QUERY_INFORMATION` access to `lsass.exe`.
- Corresponding user-mode API-hook telemetry (typically the primary detection layer) shows no matching `NtOpenProcess` call from that process for the same timestamp - a detection gap specific to direct-syscall tooling.
- The process image has unusually few imported Windows API functions in its Import Address Table (IAT), consistent with a syscall-stub-only loader.
- Process was recently written to disk or reflectively loaded, with no legitimate business justification for LSASS access (not `Task Manager`, `Process Explorer`, or an approved EDR/backup agent).

**Null Hypothesis**: The LSASS access originates from a legitimate security or diagnostic tool (e.g., the EDR agent itself, a memory-dump utility used for authorized incident response) whose direct-syscall usage is a known, approved behavior. Invalidate by checking the process hash/signature against the approved-security-tooling inventory.

**Rationale**: Direct/indirect syscall techniques are specifically engineered to defeat the user-mode API hooking that most EDR products rely on for LSASS-access detection, so identifying this technique requires comparing kernel-level ground-truth telemetry (ETW-TI, minifilter/driver events) against user-mode hook telemetry and flagging the discrepancy itself as the indicator.

#### Step 2: Data Sources and Scope
- **Sources**: EDR kernel-driver/ETW-Threat-Intelligence provider telemetry; EDR user-mode API-hook telemetry; approved-security-tooling inventory; process IAT/import analysis.
- **Scope**: ~2022-11-22T15:30:00-15:31:10 UTC; Host: WKS-SEC-004 (10.19.8.55); Process: `svcupd.exe` (unsigned, dropped to `%TEMP%`).
- **SIEM Queries** (Splunk/ELK):
  - `index=edr_kernel event_type="process_access" target_process="lsass.exe" access_mask="0x1410" | table _time src_process pid`
  - Hook-gap correlation: `index=edr_usermode api="NtOpenProcess" target_process="lsass.exe" src_process="svcupd.exe"` (expect zero results for the matching timestamp)
  - IAT analysis: `index=edr file_hash="<svcupd.exe hash>" | table imported_functions_count`

#### Step 3: Key Findings
Parsed events (4 shown) confirm `svcupd.exe` obtained a memory-read handle to `lsass.exe` via kernel-level telemetry, with a complete absence of the corresponding user-mode API-hook event, and an IAT containing only 3 imported functions.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-22 15:30:52 | WKS-SEC-004 | EDR Kernel/ETW-TI | `svcupd.exe` (PID 7740) obtained handle to `lsass.exe` (PID 692), access mask `0x1410` (`PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION`) | **Kernel-Ground-Truth IOC**: kernel-level telemetry, which cannot be bypassed by user-mode syscall tricks, confirms the access genuinely occurred. |
| 2022-11-22 15:30:52 | WKS-SEC-004 | EDR User-Mode Hooks | No `NtOpenProcess`/`NtReadVirtualMemory` hook event recorded for PID 7740 at this timestamp | **Detection-Gap IOC**: the absence of the expected user-mode hook event, despite confirmed kernel-level access, is the specific signature of direct/indirect syscall usage bypassing EDR hooks. |
| 2022-11-22 15:30:40 | WKS-SEC-004 | (Static/IAT analysis) | `svcupd.exe` Import Address Table contains only `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc` | **Syscall-Stub IOC**: an unusually minimal IAT is characteristic of loaders that resolve and invoke syscalls directly (via hand-crafted stubs or the `Sysllwhispers`/`Hell's Gate` technique) rather than calling documented Windows APIs. |
| - | - | (Tool-inventory check) | `svcupd.exe` hash does not match any entry in the approved EDR-agent or IR-tooling inventory; file is unsigned | Confirms this is not a sanctioned security or diagnostic tool. |

**Validation**:
- **Timeline**: an unsigned, minimal-IAT process obtained a read-handle to LSASS confirmed only at the kernel level, with the user-mode hook layer showing no corresponding event - a complete direct-syscall EDR-evasion chain.
- **False Positives**: no approved-tooling inventory entry or valid code signature covers this binary.
- **Correlation**: kernel-vs-user-mode telemetry discrepancy, minimal IAT, and unsigned/unapproved binary status jointly confirm direct-syscall LSASS credential-dumping activity.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate WKS-SEC-004, assume credential compromise for all accounts with active sessions on the host at the time (force password resets/Kerberos ticket invalidation), and preserve `svcupd.exe` for reverse engineering to identify the specific syscall-resolution technique used.
- **Detection**: Sigma-style rule: `title: LSASS Access Visible in Kernel Telemetry but Missing from User-Mode Hooks` → `selection1: kernel_event="process_access" target="lsass.exe"` correlated against `selection2: usermode_hook_event="NtOpenProcess" target="lsass.exe"` matching src_process/pid/timestamp → `condition: selection1 and not selection2`.
- **Pro Tip**: Prioritize EDR/kernel-driver-based (ETW-TI, minifilter) telemetry as the authoritative detection source for LSASS access rather than relying solely on user-mode API hooking - pair it with LSASS Protected Process Light (PPL) enforcement and Credential Guard, which raise the bar even for direct-syscall techniques by requiring signed-driver-level access to succeed at all.

Hypothesis **confirmed**-an unsigned loader with a minimal syscall-stub import table accessed LSASS memory using direct syscalls, successfully evading the EDR's user-mode API hooks while still being caught by kernel-level ETW-TI telemetry!
