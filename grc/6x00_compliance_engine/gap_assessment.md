# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** 2026-11-11  
**Assessor:** Nargiz Naghiyeva  
**Framework version:** NIST CSF 2.0  
**Regulatory context:** HIPAA Security Rule, 45 CFR Part 164  

## Gap Assessment Matrix

| CSF Function & ID | Subcategory Title | Status | Evidence Reference | Gap Severity | Gap Description |
|---|---|---|---|---|---|
| GOVERN: GV.OC-01 | Organizational mission and objectives understood | Implemented | `risk_treatment_plan.md` | Low | Mission defined but lacks formal annual board review documentation. |
| GOVERN: GV.PO-01 | Organizational cybersecurity policies established | Not Implemented | `prior_policy_inventory.md` | Critical | Core policies (AUP, Data Classification, Vendor Management) are missing or outdated (2021 draft only). |
| GOVERN: GV.SC-04 | Supply chain risk management plan | Not Implemented | `baa_status_note.md` | Critical | CloudVault Medical lacks an executed BAA and handles clinical backup ePHI archives. |
| GOVERN: GV.SC-07 | Supplier and vendor due diligence | Partial | `cloudvault_security_questionnaire.md` | High | Vendor questionnaire exists but has no formal risk sign-off or executed agreement. |
| IDENTIFY: ID.AM-01 | Hardware and software inventories maintained | Partial | `endpoint_hardening_baseline.md` | High | Workstation inventory covers 280 clinical systems, but unmanaged medical devices and biomedical systems are missing. |
| IDENTIFY: ID.RA-01 | Vulnerabilities and risks identified | Partial | `risk_register_updates.yaml` | Medium | Risk register tracks post-incident items but lacks continuous automated vulnerability scanning. |
| IDENTIFY: ID.RA-06 | Threat intelligence utilized for risk analysis | Implemented | `sigma_detection_catalog.md` | Low | Threat intel integrated into Sigma rules but lacks formal threat-sharing membership. |
| PROTECT: PR.AA-01 | Identity management and credential controls | Implemented | `endpoint_hardening_baseline.md` | Low | Domain GPO enforces password controls and local admin restrictions on hardened endpoints. |
| PROTECT: PR.AA-05 | Access permissions managed and reviewed | Implemented | `endpoint_hardening_baseline.md` | Low | Role-based access established on file shares with regular audit logs. |
| PROTECT: PR.AT-01 | Security awareness training conducted | Not Implemented | `security_awareness_training_status.md` | Critical | Training status shows deficient completion tracking and lack of remediation for non-compliant staff. |
| PROTECT: PR.DS-01 | Data-at-rest and in-transit protection | Partial | `endpoint_hardening_baseline.md` | High | BitLocker confirmed on 173/280 Windows endpoints; gaps remain on administrative laptops and backups. |
| PROTECT: PR.PS-01 | Personnel security and vetting procedures | Partial | `security_awareness_training_status.md` | Medium | Background checks performed at onboarding but lack periodic re-screening. |
| PROTECT: PR.PS-04 | Personnel departure and transfer handling | Implemented | `ir_playbook_index.md` | Low | Account revocation runbooks exist for offboarding but manual coordination is required. |
| DETECT: DE.CM-01 | Networks and endpoints monitored for anomalies | Partial | `endpoint_hardening_baseline.md` | Medium | Sysmon deployed to only 198 of 280 clinical workstations; coverage is below 80%. |
| DETECT: DE.CM-06 | Monitoring activities and logs analyzed | Implemented | `forensic_findings_summary.md` | None | Security logs systematically analyzed and correlated across proxy, EDR, and file server logs. |
| DETECT: DE.AE-02 | Anomalous events evaluated for impact | Implemented | `forensic_findings_summary.md` | None | Incident response playbooks successfully executed for triage and impact assessment. |
| RESPOND: RS.MA-01 | Incident management plan executed | Implemented | `ir_playbook_index.md` | None | Well-defined IR playbooks tested and validated during active incident response. |
| RESPOND: RS.AN-03 | Associated forensic analysis conducted | Implemented | `forensic_findings_summary.md` | None | Full DFIR investigation conducted across memory, disk, proxy, and Sysmon artifacts. |
| RESPOND: RS.CO-02 | Stakeholders notified per requirements | Implemented | `hipaa_security_rule_crosswalk.md` | Low | HIPAA breach notification procedures established but formal templates need legal sign-off. |
| RECOVER: RC.RP-01 | Incident recovery plan executed | Implemented | `recovery_validation_summary.md` | None | Recovery validation scripts and eradication checklists proven effective. |
| RECOVER: RC.CO-01 | Public relations and communications managed | Partial | `ocr_audit_letter.md` | Medium | Executive briefs prepared for leadership but lacks pre-scripted public/media communication templates. |

## Summary

**Implementation counts:**
- Implemented: 9
- Partial: 9
- Not Implemented: 4

**Top 3 pre-audit priorities:**
1. GV.PO-01 (Critical): Core organizational policies (AUP, Data Classification, Vendor Management) are missing or restricted to outdated 2021 drafts (`prior_policy_inventory.md`).
2. GV.SC-04 (Critical): Critical backup vendor CloudVault Medical lacks an executed Business Associate Agreement despite receiving ePHI (`baa_status_note.md`).
3. PR.AT-01 (Critical): Security awareness training status reveals deficient completion tracking and lack of mandatory remedial phishing training (`security_awareness_training_status.md`).

**Connection to upcoming governance work:**
The Critical and High gaps above are not incidental. They represent the exact control areas this project and the governance work that follows are designed to close by drafting enforceable baseline policies, executing vendor BAAs, establishing formal risk management procedures, and packaging verifiable compliance evidence for the upcoming HHS OCR audit.
