# MedDefense Health Systems - HEALTHBANE Stage 4 Threat Hunt

Proactive threat hunting project investigating the detection gap left by automated security controls during the HEALTHBANE campaign.

## Overview
While automated detection posture achieved 55% MITRE ATT&CK coverage, Stage 4 bypassed alerts entirely by leveraging Living Off The Land (LotL) tools (`PsExec`, `WMI`, `PowerShell`) and compromised service accounts. This project analyzes 14 days of SIEM and Sysmon logs to uncover unauthorized lateral movement disguised as normal IT operations.

## Repository Structure
4x04/
├── baseline/              # Legitimate administrator behavior datasets
├── reference/             # HC3 advisories, network topology, schedules & authorization matrix
└── siem_export/           # 14-day Wazuh alerts and raw Sysmon-style logs

## Objectives
* Execute hypothesis-driven threat hunting using command-line tools (`jq`, `grep`, `sort`, `uniq`).
* Profile and separate legitimate administrative actions from adversary lateral movement using contextual filters (time, host, user, target).
* Correlate findings into an attack timeline and translate discoveries into actionable detection rules.
