# HEALTHBANE Incident Reconstruction

> *"The investigator who can only see one piece of the puzzle will draw the wrong picture every time."*

## Introduction
Six weeks after the initial phishing lure, investigations across phishing, network forensics, threat intelligence, malware triage, and proactive threat hunting have uncovered critical pieces of the **HEALTHBANE** campaign against MedDefense. However, individual investigations left gaps. This final reconstruction phase integrates all multi-domain evidence—including new Incident Response data from `WS-RECV-03`—into a unified, chronological attack narrative.

## Repository Structure
* **`ir_evidence/`**: Volatile memory forensics, disk image analysis, firewall session logs, and IR team notes.
* **`previous_findings/`**: Consolidated summaries from projects 4x00 through 4x04.
* **`reference/`**: Network topology, master IOC database, ATT&CK Navigator layers, and asset inventories.

## Objectives
* Cross-evidence correlation and timestamp resolution.
* Comprehensive attack timeline reconstruction.
* Full MITRE ATT&CK mapping with confidence levels.
* HIPAA impact assessment and executive reporting.
