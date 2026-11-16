# MedDefense Identity at Scale: Master Engineering & Audit Report

**Module:** `grc/6x02_iam_scale`  
**Author:** Nargiz Naghiyeva, Cybersecurity Engineer  
**Reviewer:** James Chen, SOC Lead  
**Date:** 16 November 2026  
**Classification:** Confidential  

---

## 1. Executive Introduction & Context

Following the simulated Cobalt Strike post-incident review targeting identity risks, backup gaps, and over-privileged access, MedDefense Health Systems undertook a comprehensive engineering and audit overhaul of its identity and access management (IAM) posture. The initial breach demonstrated that attackers moved from initial compromise to Domain Admin in under two hours by exploiting neglected service accounts (`svc_epic_int`), standing privileged credentials, and weak federation.

This master report consolidates all core components developed for the `grc/6x02_iam_scale` module:
1. **SAML 2.0 SSO Integration Reference** (Keycloak realm `meddefense`).
2. **Cloud IAM Least-Privilege Remediation** (AWS policy analysis and corrections).
3. **On-Premises IAM Audit Report** (Active Directory privileged account analysis).
4. **Cloud Security Assessment** (CIS AWS Foundations Benchmark v3.0.0 mapping).

---

## Part I: SAML SSO Configuration Reference

### Realm Configuration Summary (`meddefense`)
- **Display Name:** MedDefense Health Systems
- **Session Idle Timeout:** 1,800 seconds (30 minutes)
- **Brute Force Protection:** Enabled (Failure Factor: 5 attempts)

### Client Configuration Summary (`meddefense-portal`)
- **Protocol:** SAML 2.0 Web Browser SSO Profile
- **ACS URL:** `http://localhost:5000/saml/acs`
- **NameID Format:** Email (`saml_force_name_id_format: true`)
- **Signatures:** Both Assertions (`saml.assertion.signature: true`) and Responses (`saml.server.signature: true`) are digitally signed by the IdP.

### Test Users and Role Mapping
| Username | Email | Enabled | MedDefenseRole |
|---|---|---|---|
| `d.walsh` | `d.walsh@meddefense.internal` | `true` | `clinical_staff` |
| `r.kim` | `r.kim@meddefense.internal` | `true` | `it_security` |

Centralizing authentication via Keycloak eliminates per-system credential management across Epic, PACS, and pharmacy systems, ensuring that a single off-boarding action in the IdP instantly revokes access across all integrated services.

---

## Part II: Cloud IAM Least-Privilege Remediation

Three critical AWS IAM policies originally optimized for deployment speed were restructured to enforce strict least-privilege principles:

1. **`iam_policies/siem_reader_policy.json`:**
   - *Original:* `s3:*`, `logs:*`, `cloudwatch:*` on `Resource: *`.
   - *Corrected:* Scoped `s3:GetObject` and `s3:ListBucket` strictly to `meddefense-siemlog-prod`, and CloudWatch Logs write access exclusively to `/aws/lambda/siem-log-reader`.
2. **`iam_policies/ehr_backup_policy.json`:**
   - *Original:* `s3:*` and `kms:*` on `Resource: *`.
   - *Corrected:* Scoped S3 actions (`PutObject`, `GetObject`, etc.) to `meddefense-ehr-backup-prod` and KMS actions (`Encrypt`, `Decrypt`, `GenerateDataKey`) to the specific backup key `mrk-abc123def456`.
3. **`iam_policies/break_glass_policy.json`:**
   - *Original:* Unconditional `Allow *` on `Resource: *`.
   - *Corrected:* Preserved emergency admin capabilities conditioned on `aws:MultiFactorAuthPresent: true` and corporate source IP `198.51.100.0/24`, backed by explicit `Deny` rules for missing MFA, outside IPs, and self-entrenchment actions (`iam:DeleteRole`, `organizations:*`).

---

## Part III: On-Premises IAM Audit Report Summary

A full audit of the 20 privileged Active Directory accounts (`accounts.csv`) produced **22 findings** (5 Critical, 9 High, 3 Medium, 5 Low):
- **`svc_epic_int` (IAM-003, IAM-004):** Dormant for 1,156 days with Domain Admin rights and no identified function. **Action:** Disable immediately and delete within 30 days.
- **`t.morrison` (IAM-001):** Departed contractor (engagement ended September 2025) retaining active Domain Admin rights without MFA. **Action:** Disable immediately and strip groups.
- **`svc_helpdesk` & `svc_backup` (IAM-002, IAM-005):** Automation accounts holding excessive Domain Admin privileges. **Action:** Strip Domain Admin and re-scope to minimum operational permissions.

### Remediation Roadmap Summary
| Priority | Action Items | Owner | Target |
|---|---|---|---|
| **P1** | Disable orphaned/dormant accounts (`svc_epic_int`, `t.morrison`, `l.okafor`) | SOC Lead / IT Director | Immediate |
| **P2** | Strip Domain/Server Admin from service accounts (`svc_helpdesk`, `svc_backup`) | Systems Admin | 7 days |
| **P3** | Enforce MFA across all enabled privileged user accounts | IT Security | 7 days |
| **P4** | Implement HashiCorp Vault JIT dynamic database secrets | Cloud Engineering | 60 days |

---

## Part IV: Cloud Security Assessment (CIS AWS FSB v3.0.0)

Review of Helena Reyes's 10-point environment walkthrough against CIS benchmarks revealed severe compliance gaps:

1. **Root Account (Obs 1):** Root account lacks MFA and retains unrotated access keys from March 2022. (**Critical** — Enable MFA, delete root keys).
2. **Public ePHI Backup S3 Bucket (Obs 6):** `meddefense-clinical-backup-2022` has Block Public Access disabled and allows anonymous `s3:GetObject` via `"Principal": "*"`. (**Critical** — Enable Block Public Access immediately; assess potential notification requirements under HIPAA 45 CFR 164.402).
3. **Logging & Organizations (Obs 5, 8, 10):** CloudTrail missing in DR region (`us-east-2`), VPC Flow Logs disabled, and AWS Organizations/SCPs not configured. (**High/Medium** — Enable multi-region logging and deploy baseline SCP guardrails).

---

