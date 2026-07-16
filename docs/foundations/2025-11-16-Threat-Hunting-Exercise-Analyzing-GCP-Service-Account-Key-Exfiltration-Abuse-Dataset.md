---
layout: default
title: Hunting Exercise - 117
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing GCP Service Account Key Exfiltration Abuse Dataset

This hunt uses a simulated Google Cloud Audit Log dataset (`gcp_sakey_exfil_2022-12-12T151000.json`) capturing **T1552.005: Unsecured Credentials: Cloud Instance Metadata API** combined with **T1078.004: Valid Accounts: Cloud Accounts**, where an attacker who has compromised a GCE instance or CI/CD pipeline creates and downloads a long-lived service-account JSON key, then uses it from an external IP to persist access even after the initial foothold is remediated.

#### Step 1: Hypothesis Formation
**Hypothesis**: A `google.iam.admin.v1.CreateServiceAccountKey` event occurs for a high-privilege service account, followed by API calls authenticated with that new key originating from an IP address geographically or organizationally inconsistent with the project's normal infrastructure (i.e., not a GCE/Cloud Build IP range), indicating the key was exfiltrated and is being used for external, persistent access. Indicators:
- Cloud Audit Log entry for `CreateServiceAccountKey` on a service account with broad IAM roles (e.g., `roles/editor`, `roles/owner`, or custom roles with wide `storage`/`compute` permissions).
- The creating principal is a compromised user account, a CI/CD service account with unexpectedly broad key-creation rights, or an instance service account exceeding its expected scope.
- Subsequent API activity authenticated by the new key originates from a non-Google-Cloud IP range (i.e., not GCE, Cloud Functions, or Cloud Build egress ranges).
- The key is used for data-plane operations (e.g., `storage.objects.list`/`get` across multiple buckets) shortly after creation, rather than the narrow operational purpose the service account was originally provisioned for.

**Null Hypothesis**: A developer legitimately created a service-account key for local development or a documented third-party integration, following the organization's approved (if imperfect) key-management process. Invalidate by checking for a corresponding change ticket or entry in the service-account key inventory/rotation tracker.

**Rationale**: Service-account JSON keys are long-lived, bearer-token-equivalent credentials that, once exfiltrated, work from anywhere with no MFA and no expiration unless explicitly revoked, so the creation event itself combined with subsequent off-platform usage is a far stronger signal than monitoring the service account's ongoing activity alone.

#### Step 2: Data Sources and Scope
- **Sources**: Google Cloud Audit Logs (Admin Activity and Data Access logs); VPC Flow Logs / Cloud IP-range reference lists; service-account key inventory and rotation tracker.
- **Scope**: ~2022-12-12T15:10:00-15:45:00 UTC; Project: `prod-data-platform`; Service Account: `data-pipeline-sa@prod-data-platform.iam.gserviceaccount.com`.
- **SIEM Queries** (Splunk/ELK, GCP Log Explorer syntax):
  - `protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey" protoPayload.resourceName="*data-pipeline-sa*"`
  - Off-platform usage: `protoPayload.authenticationInfo.principalEmail="data-pipeline-sa@..." AND NOT sourceIP IN (gcp_egress_ranges)`
  - Key-inventory check: `| lookup sa_key_inventory key_id OUTPUT is_approved | where is_approved=false`

#### Step 3: Key Findings
Parsed events (5 shown) confirm a new key was created for a high-privilege data-pipeline service account by a compromised CI/CD principal, then used from a residential/VPN IP to enumerate and download objects from multiple storage buckets outside the pipeline's normal scope.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-12-12 15:10:44 | GCP Audit Log | `CreateServiceAccountKey` | Principal: `ci-runner@prod-data-platform.iam.gserviceaccount.com`, target: `data-pipeline-sa`, new key ID `a1b2c3...` | **Unexpected-Key-Creation IOC**: the CI/CD runner service account creating a *new* key for a *different*, higher-privilege service account is outside its documented function of triggering pipeline builds. |
| 2022-12-12 15:10:44 | (Key-inventory check) | - | Key ID `a1b2c3...` has no corresponding entry in the approved service-account key tracker | **Unauthorized IOC**: confirms this key creation bypassed the organization's key-management/approval process entirely. |
| 2022-12-12 15:18:02 | GCP Audit Log | `storage.objects.list` | Authenticated via key `a1b2c3...`, source IP `71.19.204.88` (residential ISP, not any GCE/Cloud Build range) | **Off-Platform IOC**: legitimate use of this service account should originate exclusively from within GCP infrastructure (GCE/Cloud Build egress IPs); a residential-ISP source confirms the key was exfiltrated and is being used externally. |
| 2022-12-12 15:19:15 - 15:44:30 | GCP Audit Log | `storage.objects.get` (aggregate) | 1,847 object-download operations across 6 storage buckets, including `customer-pii-archive` - a bucket unrelated to the pipeline's documented function | **Scope-Excess IOC**: the pipeline service account's normal operation touches exactly one staging bucket; access to five additional, unrelated buckets - including one containing customer PII - indicates the key is being used for broad data exfiltration, not its intended purpose. |
| - | - | (IAM policy review) | `data-pipeline-sa` holds `roles/storage.objectAdmin` at the project level rather than a narrowly-scoped bucket-level role | Confirms the over-privileged IAM grant is what made this broad data access possible once the key was stolen. |

**Validation**:
- **Timeline**: an unexpected key creation by a compromised CI/CD principal, immediate off-platform (non-GCP-IP) usage of that key, and broad multi-bucket data access - including a PII-containing bucket outside the account's documented scope - form a complete key-exfiltration-and-abuse chain.
- **False Positives**: no key-inventory entry or change ticket authorizes this key.
- **Correlation**: unauthorized key creation, off-platform source IP, and scope-excessive data access jointly confirm service-account key exfiltration and abuse.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Immediately disable/delete key `a1b2c3...`, rotate the service account entirely (delete and recreate if key history is uncertain), review CI/CD pipeline configuration and secrets for the initial compromise vector, and issue a data-breach assessment for the accessed `customer-pii-archive` bucket contents.
- **Detection**: Sigma/GCP-style rule: `title: Service Account Key Used From Non-GCP IP Range` → `selection: protoPayload.authenticationInfo.principalEmail=<service_account> AND sourceIP NOT IN (gcp_egress_ranges)` → `condition: selection`.
- **Pro Tip**: Enforce an Organization Policy Constraint disabling service-account key creation entirely (`iam.disableServiceAccountKeyCreation`) in favor of Workload Identity Federation for CI/CD and short-lived, automatically-rotated credentials for workloads - this removes long-lived bearer-token-equivalent JSON keys from the environment altogether, closing the exfiltration vector at its root rather than only detecting misuse after the fact.

Hypothesis **confirmed**-a compromised CI/CD service account created an unauthorized key for a high-privilege data-pipeline service account, which was then used from a residential IP to download nearly 1,900 objects across six storage buckets, including one containing customer PII!
