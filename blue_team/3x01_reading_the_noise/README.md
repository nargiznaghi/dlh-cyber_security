# 3x01: Reading the Noise — Baseline & Anomaly Detection Pipeline

This repository contains the CLI toolkit and automated baseline analysis scripts for the **3x01 Reading the Noise** module. The pipeline operates strictly via command-line against the standardized handoff evidence pack produced in 3x00.

---

## 📌 Project Overview

The core objective of this module is to analyze 8 days of unified telemetry, establish statistical baselines across endpoint and network sources for the first 7 days, and flag anomalies occurring in the 8th day (evaluation window) without relying on external SIEM platforms or APIs.

---
## 🛠 Prerequisites & Environment Setup
The scripts are designed to run on Ubuntu 22.04 LTS and rely on environment variables to locate inputs and output directories.
