# Identity Program Brief for Dr. Morales

**To:** Dr. Morales, Chief Information Security Officer  
**From:** Nargiz Naghiyeva, Cybersecurity Engineer  
**Date:** 16 November 2026  
**Subject:** Identity Program Posture, Incident Correlation, and Board Risk Committee Roadmap  
**Classification:** Confidential / Board Material  

---

## Identity Posture Summary

Following our recent post-incident review, a comprehensive security audit of our Active Directory environment (20 privileged accounts) and AWS cloud infrastructure (10 core observations) uncovered significant systemic risk. We identified **5 Critical and 9 High findings** in our on-premises identity inventory, alongside **2 Critical and 4 High findings** in our cloud environment. Our identity layer—not our perimeter—remains our most vulnerable surface due to legacy administrative accounts, dormant service credentials, and over-privileged cloud roles.

## Connection to the Incident

The findings directly recreate the lateral movement path of our recent Cobalt Strike intrusion: an initial endpoint foothold yielding a standing static credential from memory that instantly grants domain-wide control. Specifically, `svc_epic_int` (**IAM-003, IAM-004**) is an enabled service account holding Domain Admin rights that has been dormant for 1,156 days with no documented function. Much like the account abused in the prior breach, its static password was never rotated post-migration, providing an unmonitored back door to full domain takeover. Similarly, public S3 ePHI backup exposure (**Obs 6**) and un-MFA'd privileged accounts (`t.morrison`, **IAM-001**) left our clinical data and admin gates unprotected.

## What Has Been Completed

- **Active Directory Audit:** Evaluated 20 privileged accounts using deterministic audit tooling (`audit_iam.py`), establishing an unassailable baseline of 22 total findings.
- **Cloud IAM Least-Privilege Remediation:** Rewrote and analyzed over-privileged AWS policies for SIEM logging, EHR backups (`iam_policies/ehr_backup_policy.json`), and break-glass access (`iam_policies/break_glass_policy.json`).
- **Cloud Security Baseline Assessment:** Mapped all 10 environment observations against the CIS AWS Foundations Benchmark v3.0.0 (`cloud_security_assessment.md`).
- **Identity Architecture Roadmap:** Designed a comprehensive remediation plan transitioning from standing passwords to dynamic, short-lived credentials.

## What Must Be Completed Before the Next Board Meeting

1. **Disable Dormant & Orphaned Accounts:** Disable `svc_epic_int`, `t.morrison`, and `l.okafor` immediately. *(Owner: SOC Lead / IT Director — Target: Immediate)*
2. **Strip Over-Privileged Service Rights:** Remove Domain/Server Admin membership from active automation accounts (`svc_helpdesk`, `svc_backup`) and verify workflow continuity. *(Owner: Systems Administration — Target: 7 days)*
3. **Enforce Privilege MFA:** Enroll and enforce MFA across all remaining enabled privileged user accounts, closing our un-MFA gap. *(Owner: IT Security — Target: 7 days)*

## What Requires Board Authorization or Budget

To permanently eliminate the class of credential-theft attacks that compromised our network, we require Board authorization and capital allocation to implement **HashiCorp Vault Just-In-Time (JIT) dynamic secret management** across all database and integration workloads. This replaces static standing passwords with automatically rotated, short-lived credentials.

## Board Resolution Requested

*“Resolved, that the Board Risk Committee authorizes executive management to immediately execute the identity remediation roadmap, allocate necessary engineering resources, and approve funding for enterprise dynamic secrets management to ensure full HIPAA technical safeguard compliance by Q1 2027.”*
