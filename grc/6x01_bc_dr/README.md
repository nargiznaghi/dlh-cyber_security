# When Everything Fails — MedDefense Disaster Recovery & BC/DR Engineering

**Author:** Nargiz Naghiyeva  
**Date:** 2026-11-12  
**Level:** Novice / Professional GRC & BC/DR Track  
**Weight:** 1  

---

## Introduction

At 2:47 AM on a Tuesday, MedDefense's data center power fails. When cooling fails and critical clinical servers drop offline, written recovery plans meet operational reality. Healthcare organizations that do not test recovery procedures discover that the gap between theory and practice is measured in clinical risk and patient safety.

This project closes that gap. It transitions MedDefense from unverified legacy disaster recovery plans to a defensible, tested, and evidence-backed Business Continuity and Disaster Recovery (BC/DR) framework aligned with **NIST CSF 2.0**, **HIPAA Security Rule (164.308(a)(7))**, and Joint Commission standards.

---

## Project Structure & Deliverables

The repository is organized into structured GRC and engineering components:

- **`business_impact_analysis.md`** — A comprehensive BIA classifying 10 critical MedDefense systems by patient safety consequence (1hr, 4hr, 24hr thresholds), regulatory obligations, revenue exposure, and defining defensible RTO, RPO, and MTD values.
- **`meddefense-dr-test/`** — Containerized lab test environment containing LIS database backup (`lis_backup.sql.gz`), integrity manifests (`backup_manifest.sha256`), and environment configuration (`app_config.env`).
- **`audit_evidence_package.md`** — Compliance mapping addressing HHS OCR desk audit requirements.

---

## Key Technical Objectives

1. **Defensible BIA:** Establishes priority tiers (Tier 1 to Tier 4) based on clinical impact and strict mathematical consistency ($RPO < RTO < MTD$).
2. **Dependency Sequencing:** Maps foundational infrastructure (Network Core, Active Directory, Backup/DR) to ensure clinical restoration follows correct technical dependencies.
3. **Timed LIS Recovery Test:** Executes command-level database restoration against simulated LIS failure within the containerized lab environment, measuring wall-clock performance against the 30-minute target (`LIS_RTO_MINUTES=30`).
4. **Audit Readiness:** Translates technical recovery findings into board-ready documentation for the CISO and Board Risk Committee.

---
