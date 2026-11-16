# MedDefense Backup Architecture

**Version:** 1.0  
**Classification:** Confidential / Audit Review  
**Governing Standard:** NIST CSF 2.0 & HIPAA Security Rule 164.308(a)(7)  

---

## Strategy Overview

This document translates the recovery objectives established in `business_impact_analysis.md` into an implementable, secure, and dependency-aware backup architecture for all Tier 1 and Tier 2 systems. It directly addresses the five audit findings from the backup log review and enforces mathematical compliance between declared Recovery Point Objectives (RPO) and actual backup execution frequencies.

### 3-2-1 Backup Strategy Rationale
To guarantee survivability against site-wide power loss, ransomware attacks, and hardware failure, MedDefense enforces the strict **3-2-1 Backup Strategy** across all critical workloads:
* **3 Copies:** One primary production copy and two distinct backup copies.
* **2 Media Types:** High-performance local SAN storage arrays and immutable cloud object storage.
* **1 Off-Site Copy:** Geographically isolated storage (CloudVault Medical) to ensure site-loss resilience.

### Dependency-Aware Design
Backup and recovery workflows cannot operate in isolation. Because downstream clinical systems (Epic EHR, LIS, Pharmacy Dispensing) depend entirely on foundational infrastructure (Network Core, Active Directory, and Backup/DR Infrastructure), the restoration sequence and backup verification protocols strictly respect technical dependencies to prevent cascading failures or database corruption.

### Verification Standards Beyond Completion Logs
To correct historical logging deficiencies (Finding 4), backup success is never determined by passive completion logs alone. Every backup execution requires:
1. **Cryptographic Integrity:** Automated SHA-256 hash generation and verification against backup manifests.
2. **Automated Test Restores:** Weekly staging restores into an isolated sandbox environment.
3. **Record-Count & Referential Integrity Checks:** Automated execution of row-count and database consistency verifications (`PRAGMA integrity_check`).
4. **Mandatory Accountability:** Every verified restore must include named tester sign-off and timestamped audit logs.

---

## RPO Compliance Verification

To satisfy James Chen's directive and audit requirements, achievable RPO can never exceed backup frequency. The table below demonstrates mathematical compliance for every Tier 1 and Tier 2 system:

| System Name | Tier | Declared RPO | Backup Frequency & Type | Max Potential Data Loss | RPO Compliant? |
|---|---|---|---|---|---|
| **Network Core** | Tier 1 | 1 hour | Hourly config snapshot / differential | ≤ 1 hour | **YES** |
| **Active Directory** | Tier 1 | 1 hour | Hourly system state snapshot | ≤ 1 hour | **YES** |
| **Epic EHR** | Tier 1 | 1 hour | Hourly transaction log backup + nightly full | ≤ 1 hour | **YES** |
| **Laboratory Information System (LIS)** | Tier 1 | 1 hour | Hourly transaction log backup + nightly full | ≤ 1 hour | **YES** |
| **Pharmacy Dispensing System** | Tier 1 | 1 hour | Hourly transaction log backup + nightly full | ≤ 1 hour | **YES** |
| **Backup and DR Infrastructure** | Tier 1 | 2 hours | Hourly catalog & config backup | ≤ 2 hours | **YES** |
| **PACS / RIS** | Tier 2 | 1 hour | Hourly DICOM metadata snapshot + continuous replication | ≤ 1 hour | **YES** |
| **Medical Device Integration Gateway** | Tier 2 | 4 hours | 4-hour incremental backup + nightly full | ≤ 4 hours | **YES** |
| **Security Operations Platform** | Tier 2 | 4 hours | 4-hour SIEM log archive + snapshot | ≤ 4 hours | **YES** |

---

## Per-System Backup Specifications

### 1. Network Core
* **Backup type:** Full weekly, differential hourly snapshots.
* **Schedule:** Full backup every Sunday at 01:00; hourly differential snapshots 24/7.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years for audit logs).
* **Primary destination:** On-site SAN Storage Array (Primary DC, Rack 4).
* **Secondary destination:** CloudVault Medical Off-Site Vault (Region: `eu-west-1`).
* **Encryption at rest:** AES-256 using hardware-backed KMS with annual key rotation.
* **Encryption in transit:** TLS 1.2+ mandatory for all replication traffic.
* **Integrity verification:** Automated SHA-256 hash validation and monthly config restore test.
* **Restoration sequence:** Step 1 in Full Data Center Loss sequence.
* **Responsible role:** Network Engineering Lead (Executes), Senior Systems Engineer (Verifies).

### 2. Active Directory
* **Backup type:** System state snapshot & incremental database backup.
* **Schedule:** Hourly system state snapshots; daily full backup at 02:00.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years).
* **Primary destination:** On-site Local Backup Appliance (Primary DC, Rack 2).
* **Secondary destination:** CloudVault Medical Off-Site Vault.
* **Encryption at rest:** AES-256 with dedicated KMS key and escrowed recovery keys.
* **Encryption in transit:** TLS 1.2+ for replication and transit.
* **Integrity verification:** SHA-256 verification and weekly automated non-authoritative restore test.
* **Restoration sequence:** Step 2 in Full Data Center Loss sequence.
* **Responsible role:** Identity & Access Management Admin (Executes), IT Security Officer (Verifies).

### 3. Epic EHR
* **Backup type:** Combination (Nightly full database backup + hourly transaction log backups).
* **Schedule:** Full backup daily at 00:00; transaction logs every 60 minutes.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years HIPAA ePHI retention).
* **Primary destination:** On-site Enterprise SAN (Tier 1 Storage Tier).
* **Secondary destination:** CloudVault Medical Off-Site Immutable Vault.
* **Encryption at rest:** AES-256 (database level & storage volume level) with hardware KMS.
* **Encryption in transit:** TLS 1.2+ with certificate pinning.
* **Integrity verification:** SHA-256 manifest check, automated staging restore, and record count validation.
* **Restoration sequence:** Step 4 in Full Data Center Loss sequence.
* **Responsible role:** Database Administrator (Executes), Clinical Systems Lead (Verifies).

### 4. Laboratory Information System (LIS)
* **Backup type:** Combination (Nightly full SQL dump + hourly transaction log backups).
* **Schedule:** Full backup nightly at 01:30; transaction logs every 60 minutes.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years).
* **Primary destination:** On-site Laboratory Server Rack NAS.
* **Secondary destination:** CloudVault Medical Off-Site Secure Vault.
* **Encryption at rest:** AES-256 with isolated KMS key.
* **Encryption in transit:** TLS 1.2+.
* **Integrity verification:** SHA-256 hash validation, weekly test restore (`sqlite3` check), and record validation.
* **Restoration sequence:** Step 4 (Parallel with Epic) in Full Data Center Loss sequence.
* **Responsible role:** Lab Systems Specialist (Executes), Laboratory Director (Verifies).

### 5. Pharmacy Dispensing System
* **Backup type:** Combination (Nightly full backup + hourly transaction logs).
* **Schedule:** Full backup nightly at 02:00; transaction logs every 60 minutes.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years).
* **Primary destination:** On-site Pharmacy Server Array.
* **Secondary destination:** CloudVault Medical Off-Site Vault.
* **Encryption at rest:** AES-256 with dedicated KMS key.
* **Encryption in transit:** TLS 1.2+.
* **Integrity verification:** SHA-256 check and weekly automated test restore.
* **Restoration sequence:** Step 4 (Parallel with Epic/LIS) in Full Data Center Loss sequence.
* **Responsible role:** Pharmacy IT Specialist (Executes), Director of Pharmacy (Verifies).

### 6. Backup and DR Infrastructure
* **Backup type:** Full catalog and configuration backup.
* **Schedule:** Hourly catalog backups; nightly full infrastructure state backup.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years).
* **Primary destination:** Isolated Backup Server Local Storage.
* **Secondary destination:** CloudVault Medical Air-Gapped Vault.
* **Encryption at rest:** AES-256 with air-gapped Master Key.
* **Encryption in transit:** TLS 1.2+.
* **Integrity verification:** SHA-256 hash verification and bi-weekly platform recovery rehearsal.
* **Restoration sequence:** Step 3 in Full Data Center Loss sequence.
* **Responsible role:** Senior Backup Engineer (Executes), CISO (Verifies).

### 7. PACS / RIS
* **Backup type:** DICOM metadata snapshot & incremental backup of image archives.
* **Schedule:** Hourly DICOM catalog snapshot; daily incremental; weekly full.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years medical imaging mandate).
* **Primary destination:** PACS On-Site Storage Silo.
* **Secondary destination:** CloudVault Medical Long-Term Archive Tier.
* **Encryption at rest:** AES-256.
* **Encryption in transit:** TLS 1.2+.
* **Integrity verification:** SHA-256 verification and monthly image retrieval integrity test.
* **Restoration sequence:** Step 5 in Full Data Center Loss sequence.
* **Responsible role:** Radiology Systems Admin (Executes), Chief Radiologist (Verifies).

### 8. Medical Device Integration Gateway
* **Backup type:** Incremental backup and configuration snapshot.
* **Schedule:** Every 4 hours incremental; nightly full backup at 03:00.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years).
* **Primary destination:** Biomedical Engineering Local Storage.
* **Secondary destination:** CloudVault Medical Off-Site Vault (Resolves Finding 2).
* **Encryption at rest:** AES-256.
* **Encryption in transit:** TLS 1.2+.
* **Integrity verification:** SHA-256 verification and quarterly off-site restore test.
* **Restoration sequence:** Step 5 (Parallel with PACS) in Full Data Center Loss sequence.
* **Responsible role:** Biomedical Engineering Lead (Executes), Clinical Engineering Director (Verifies).

### 9. Security Operations Platform
* **Backup type:** SIEM log archive snapshot and configuration backup.
* **Schedule:** Every 4 hours log snapshot; nightly full configuration backup.
* **Retention:** Recent (30 days), monthly (12 months), archive (7 years compliance retention).
* **Primary destination:** SecOps Local Storage Vault.
* **Secondary destination:** CloudVault Medical Secure Archive.
* **Encryption at rest:** AES-256 with restricted Security Operations KMS key.
* **Encryption in transit:** TLS 1.2+.
* **Integrity verification:** SHA-256 hash verification and monthly SIEM log integrity check.
* **Restoration sequence:** Step 6 in Full Data Center Loss sequence.
* **Responsible role:** Security Operations Lead (Executes), CISO (Verifies).

---

## Full Data Center Loss: Restoration Sequence

To prevent database corruption and cascading failures, restoration follows a strict dependency-based sequence (never alphabetical):

1. **Phase 1: Foundational Network Core**
   * *Action:* Restore network routing, switching configurations, VLANs, and firewall rulebases from the most recent verified hourly snapshot.
   * *Verification:* End-to-end network ping tests and gateway reachability confirmation.
2. **Phase 2: Identity & Access Management (Active Directory)**
   * *Action:* Perform authoritative/non-authoritative system state restoration of Active Directory (`DC01` / `DC02`).
   * *Verification:* Run `dcdiag /v` and confirm replication convergence across all domain controllers.
3. **Phase 3: Backup & DR Infrastructure Control Plane**
   * *Action:* Restore the backup management catalog, scheduler database, and encryption key escrow services.
   * *Verification:* Verify catalog accessibility and test read-access to CloudVault Medical storage vaults.
4. **Phase 4: Core Clinical Tier 1 Applications (Parallel Execution)**
   * *Action:* Simultaneously restore databases and application state for **Epic EHR**, **Laboratory Information System (LIS)**, and **Pharmacy Dispensing System** using verified nightly full dumps followed by hourly transaction logs.
   * *Verification:* Run database integrity checks (`PRAGMA integrity_check` for SQLite, DBCC CHECKDB for SQL Server), verify row counts, and confirm critical patient record accessibility.
5. **Phase 5: Supporting Clinical & Operational Tier 2 Systems**
   * *Action:* Restore **PACS / RIS** and **Medical Device Integration Gateway** from off-site cloud vaults.
   * *Verification:* Verify DICOM image retrieval and biomedical telemetry feed ingestion.
6. **Phase 6: Security & Monitoring Infrastructure**
   * *Action:* Restore **Security Operations Platform** and SIEM log collectors.
   * *Verification:* Confirm log ingestion pipelines and threat detection rule execution.

---

## Dependency Restore Constraints

* **Strict Dependency Enforcement:** No Tier 1 clinical application (Epic, LIS, Pharmacy) may be brought online before Active Directory and Network Core are fully restored and verified. Attempting to start clinical databases without active directory authentication services results in catastrophic session failures and authorization corruption.
* **Network Isolation During Restore:** All systems during Phase 1 through Phase 4 must remain isolated on an out-of-band management VLAN until integrity verification and transaction log replay are fully completed.
* **Concurrent Log Replay Limit:** To prevent resource exhaustion on backup storage nodes, transaction log replays for Epic, LIS, and Pharmacy must be managed sequentially or throttled via resource pools.
