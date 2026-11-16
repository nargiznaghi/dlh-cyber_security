# MedDefense IAM Policy Analysis

Review and correction of three MedDefense AWS IAM policies originally written for deployment speed rather than least privilege. Source evidence: `original_siem_reader_policy.json`, `original_ehr_backup_policy.json`, `original_break_glass_policy.json`, `aws_environment_observations.md` (observations 7 and 9), and `cis_aws_control_map.md`.

## Policy 1: MedDefenseSIEMLogReader Violations

Original grants:
- `s3:*` on `Resource: *`: full S3 control over every bucket in the account, including `meddefense-clinical-backup-2022` which holds ePHI archives.
- `logs:*` and `cloudwatch:*` on `Resource: *`: full CloudWatch Logs and CloudWatch control, including deleting log streams, altering alarms, and modifying retention.

Violations and corrections:

| # | Violation | Attack surface created | Correction applied |
|---|---|---|---|
| 1 | `s3:*` on `*` | A compromised SIEM reader role could delete or alter forensic log objects or sabotage the clinical backup bucket | Scoped to `s3:GetObject` on `meddefense-siemlog-prod/*` and `s3:ListBucket` on `meddefense-siemlog-prod` only |
| 2 | `logs:*` on `*` | Ability to delete or modify arbitrary log groups, destroying evidence and SIEM coverage | Scoped to `logs:CreateLogStream` and `logs:PutLogEvents` on the `siem-log-reader` lambda log group only |
| 3 | `cloudwatch:*` on `*` | Ability to silence alarms and change dashboards | CloudWatch actions removed entirely |

## Policy 2: MedDefenseEHRBackupRole Violations

Original grants:
- `s3:*` on `Resource: *`: full S3 control over all buckets.
- `kms:*` on `Resource: *`: full KMS control over every key in the account.

Violations and corrections:

| # | Violation | Attack surface created | Correction applied |
|---|---|---|---|
| 1 | `s3:*` on `*` | Account-wide S3 control lets a compromised automation role delete or exfiltrate unrelated buckets | S3 scoped to `meddefense-ehr-backup-prod` with required backup actions only |
| 2 | `kms:*` on `*` | Full KMS control includes key deletion and rewriting key policies (effective data destruction) | KMS scoped to specific backup key `mrk-abc123def456` with `Encrypt`, `Decrypt`, `GenerateDataKey` |

## Policy 3: MedDefenseBreakGlassAdmin Violations

Original grants:
- `Action: *` on `Resource: *` with no conditions: unconditional, standing administrator access.

Violations and corrections:

| # | Violation | Attack surface created | Correction applied |
|---|---|---|---|
| 1 | Unconditional `Allow *` on `*` | Functions as a second root credential with programmatic assumption and no friction | Conditioned on `aws:MultiFactorAuthPresent: true` and `aws:SourceIp` within `198.51.100.0/24` |
| 2 | Compromise path | Long-lived session tokens without MFA could bypass intended security bounds | Added explicit `Deny` statements for missing MFA or outside IP range |
| 3 | Self-perpetuating takeover | Ability to delete the break-glass role or policy or escape guardrails | Explicit `Deny` on `iam:DeletePolicy`, `iam:DeleteRole`, `iam:UpdateAssumeRolePolicy`, and `organizations:*` |

## Least Privilege Summary

| Policy | Original footprint | Corrected footprint |
|---|---|---|
| SIEM reader | `s3:*`, `logs:*`, `cloudwatch:*` on `*` | Read-only on one log bucket; append-only writes to one lambda log group |
| EHR backup | `s3:*`, `kms:*` on `*` | Backup-object write/read on one bucket; encrypt/decrypt on one KMS key |
| Break-glass | `*` on `*`, unconditional | `*` on `*` gated by MFA and source IP, with backstop explicit denies |

## Residual Risk and Operational Notes

- Break-glass wildcard allows remain broad by design but are gated by MFA and source IP.
- Ensure S3 object immutability or Object Lock is evaluated for logs.
- Bucket-level public access settings on clinical backup buckets must be audited separately.
