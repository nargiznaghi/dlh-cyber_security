# 3x02 - The Alert Factory

## Overview
This repository contains the detection catalog and automation tooling built for MedDefense Health Systems. It leverages Sigma rules, Python evaluation logic, and custom runners to analyze normalized security logs from the 3x00 handoff and 3x01 baseline package.

## Project Structure
- `0-detection_matrix.sh`: Analyzes log sources to determine supported detection types, stable fields, and cardinalities.
- `detection_matrix.json`: Output matrix defining detection capabilities across all ingested data sources.

## Requirements & Environment Variables
The scripts run on Ubuntu 22.04 LTS and rely on the following environment variables:
- `HANDOFF_DIR`: Path to 3x00 evidence handoff directory (Default: `~/3x00_handoff/evidence_handoff`)
- `BASELINE_PKG`: Path to 3x01 baseline package directory (Default: `~/3x01_package/baseline_package`)
- `CATALOG_DIR`: Path to 3x02 detection catalog output directory (Default: `~/3x02_package/detection_catalog`)
- `ASSETS_DIR`: Path to 3x02 assets directory containing `risk_register.json`
