# 4x01 Wireshark Territory — Network Forensics & PCAP Investigation

> *"The network never lies. People lie. Logs can be tampered with. But the packets on the wire are physics, not policy."*  
> — **Richard Bejtlich, The Tao of Network Security Monitoring**

---

## Executive Summary & Background

Following the phishing investigation (**4x00**), which confirmed a nurse workstation contacted a credential-harvesting domain at **MedDefense Health Systems**, this repository contains the network forensic analysis of the subsequent attack phases. 

While endpoint logs can be cleared and SIEM alerts can misfire, raw packet captures (PCAPs) preserve unalterable ground-truth evidence. This project reconstructs the post-compromise attack chain—including initial access, C2 beaconing, DNS exfiltration, and internal lateral movement—purely from packet captures using `tshark` and automated shell tools.

---
