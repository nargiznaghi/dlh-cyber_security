# Structured Environment Summary: MedDefense Health Systems

## 1. Organization Overview

### Sites and Locations
*   **MedDefense Central Hospital**
    *   **Location Type:** Downtown location, 6 floors + basement level.
    *   **Function:** 350-bed acute care facility. Departments include Emergency, Surgery, Cardiology, Radiology, Oncology, Pediatrics, Maternity, Pharmacy, Laboratory, and Administration[cite: 1]. The mechanical/server room is located in the basement[cite: 1].
    *   **Headcount:** Approximate staff of 1,400 (clinical + support)[cite: 1].
*   **Westside Clinic**
    *   **Location Type:** Suburban location (12-minute drive from Central), 2-story medical office complex[cite: 1].
    *   **Function:** Outpatient facility providing primary care, diagnostic imaging (X-ray, ultrasound, blood work - no MRI), minor procedures, and physical therapy[cite: 1]. Shares some IT services with Central but has a local server closet[cite: 1].
    *   **Headcount:** Approximate staff of 180[cite: 1].
*   **Corporate HQ**
    *   **Location Type:** Leased office space, occupies the 3rd floor of a 5-story commercial building in Greenfield Business Park[cite: 1].
    *   **Function:** Administrative offices hosting Finance, HR, Legal, Marketing, Executive Leadership, and the IT department[cite: 1]. No on-premise servers; relies on cloud services and site-to-site VPN to Central[cite: 1].
    *   **Headcount:** Approximate staff of 220, including 12 IT staff members[cite: 1].

### Departments and Reporting Structure
*   **Executive Leadership:** CEO (Dr. Patricia Morales), CFO (Robert Kim), COO (Angela Torres), and General Counsel (David Park)[cite: 1].
*   **Security Structure:** The CISO position is currently vacant[cite: 1]. James Chen serves as the Deputy CISO (acting CISO)[cite: 1]. In practice, James reports directly to the CEO, though formally aligned under the vacant CISO role[cite: 1]. The Security Analyst (New Hire) reports directly to James Chen[cite: 1].
*   **IT Operations Structure:** Sarah Park serves as the IT Director and is a peer to James Chen[cite: 1]. Sarah manages an IT team consisting of 3x System Administrators, 2x Network Technicians, 1x Database Administrator, 2x Helpdesk Analysts (including lead Mike Torres), 2x Desktop Support Technicians, and 1x vacant IT Intern position[cite: 1].
*   **Operational Friction:** James Chen has authority over security policy but no authority over IT operations[cite: 1]. Sarah Park manages IT infrastructure, creating operational friction between policy enforcement and infrastructure execution[cite: 1].

---

## 2. IT Infrastructure Identified

### Servers
*   **Central Hospital (Basement Server Room):**
    *   `ehr-srv-01`: Ubuntu 20.04 LTS | EHR Application Server | Accessible over the network[cite: 1].
    *   `ehr-db-01`: Ubuntu 20.04 LTS | EHR Database (PostgreSQL) | Accessible from the entire 10.10.0.0/16 range[cite: 1].
    *   `pacs-srv-01`: Windows Server 2016 | PACS Imaging Server | Used by the Radiology department[cite: 1].
    *   `billing-srv-01`: Windows Server 2019 | Billing/Claims Processing | Suffers from performance issues and experienced a ransomware incident in January[cite: 1].
    *   `ad-dc-01`: Windows Server 2019 | Primary Domain Controller[cite: 1].
    *   `ad-dc-02`: Ubuntu 18.04 LTS | Secondary Domain Controller[cite: 1].
    *   `file-srv-01`: Windows Server 2016 | Department File Shares[cite: 1].
    *   `print-srv-01`: Windows Server 2012R2 | Print Server | **[UNVERIFIED]** and End of Support since October 2023[cite: 1].
    *   `backup-srv-01`: Ubuntu 22.04 LTS | Backup Server running Veeam agent | Backs up nightly to a local NAS located in the same network, rack, and server room[cite: 1].
    *   `web-srv-01`: Ubuntu 20.04 LTS | Public Website + Patient Portal | Positioned in the DMZ[cite: 1].
*   **Westside Clinic (Server Closet):**
    *   `ws-srv-01`: Windows Server 2016 | Local file server + scheduling[cite: 1].
*   **Corporate HQ:**
    *   No on-premise servers[cite: 1].

### Network Equipment
*   **Central Hospital:** 1x Fortinet FortiGate 100F Firewall[cite: 1], 1x Cisco core switch (model unknown)[cite: 1], 2x Cisco access switches per floor (12 switches total across 6 floors)[cite: 1], and 12x Ubiquiti UniFi Access Points (APs)[cite: 1]. Network runs as a completely flat network domain (`10.10.0.0/16`) with no configured VLANs[cite: 1].
*   **Westside Clinic:** 1x Netgear Nighthawk consumer-grade router (terminates the IPSec VPN connection to Central)[cite: 1] and 1x unmanaged switch (brand unknown)[cite: 1]. WiFi infrastructure is unknown[cite: 1].
*   **Corporate HQ:** Network infrastructure is managed by the building landlord[cite: 1]. MedDefense is allocated its own VLAN, which connects via site-to-site VPN to Central's FortiGate firewall[cite: 1].

### Endpoints
*   **Central Hospital:** ~320 Windows 10 workstations and ~60 thin clients in clinical areas[cite: 1].
*   **Westside Clinic:** ~45 Windows 10 workstations[cite: 1].
*   **Corporate HQ:** ~120 Windows 10/11 workstations and ~30 laptops with remote capability[cite: 1].
*   **Mobile / Tablets:** ~25 iPads used by physicians for clinical rounds (management state is unclear)[cite: 1].
*   *Note: Endpoint counts are based on an Active Directory report from 8 months ago and are not physically confirmed[cite: 1].*

### Medical Devices (IoT)
*   **Connected Patient Monitors:** ~80 units (Philips IntelliVue) across Central, running on the flat 10.10.0.0/16 network[cite: 1].
*   **Infusion Pumps:** ~120 units (BD Alaris), network-connected for dosage updates, accessible from anywhere on the internal network[cite: 1].
*   **MRI Scanner:** 1x Siemens MAGNETOM located in Central Hospital Radiology department, running on an obsolete Windows XP operating system[cite: 1].
*   **CT Scanner:** 1x GE Revolution located at Central Hospital, operating system unknown[cite: 1].
*   **Nurse Call System:** IP-based system integrated directly with the phone system[cite: 1].
*   **Physical Badge/Access System:** HID Global system, connected to Active Directory for some doors[cite: 1].

---

## 3. Data and Services

### Types of Data Handled
*   **Electronic Health Records (EHR) & Protected Health Information (PHI):** Patient clinical records, medical histories, and health documentation handled by `ehr-srv-01` and `ehr-db-01`[cite: 1].
*   **Medical Imaging Data:** Diagnostic imagery (X-rays, ultrasounds, etc.) stored and managed via the `pacs-srv-01` server[cite: 1].
*   **Financial and Billing Data:** Claims processing, medical billing data, and transactional information stored on `billing-srv-01`[cite: 1].
*   **Personally Identifiable Information (PII):** Staff credentials, HR onboarding records, and administrative details handled at Corporate HQ and stored on Active Directory (`ad-dc-01/02`) and `file-srv-01`[cite: 1].
*   **Public/Patient Portal Data:** Patient-facing interactions via the public website (`web-srv-01`)[cite: 1].

### Critical Services & Dependencies
*   **Clinical EHR Application:** Crucial for hospital clinical functions; depends on `ehr-srv-01` and `ehr-db-01`[cite: 1]. Used by clinical staff (doctors, nurses, pharmacy) across Central and Westside[cite: 1].
*   **PACS Imaging:** Required for radiology visualization; depends on `pacs-srv-01`[cite: 1]. Used primarily by Radiology staff[cite: 1].
*   **Billing and Claims Processing:** Keeps the business financially operational; depends on `billing-srv-01`[cite: 1]. Used by the Finance and Administration teams[cite: 1].
*   **Authentication and Directory Services:** Controls access to all domain-joined endpoints and network assets; depends on Active Directory (`ad-dc-01/02`)[cite: 1]. Used by all employees[cite: 1].
*   **Patient Rounding / Mobility Xidmətləri:** Facilitated by iPads for real-time physician access during hospital rounds[cite: 1].
*   **Corporate Email & Collaboration:** Handled globally via Microsoft O365 E3 cloud services[cite: 1]. Used by all administrative and clinical staff[cite: 1].

---

## 4. Known Unknowns

### Missing & Incomplete Information
*   **Endpoint Inventory:** Precise count, operating system patches, and locations of workstations, thin clients, laptops, and tablets are missing (current data relies on an 8-month-old AD report)[cite: 1].
*   **Antivirus Deployment Status:** It is unknown if the Sophos Endpoint Protection agent is active, properly configured, or running updated definitions across all enterprise machines[cite: 1].
*   **Westside Network Infrastructure:** The vendor, model, and patch level of the unmanaged switch at Westside Clinic are unknown[cite: 1]. The specific wireless network infrastructure (APs) at Westside is completely undocumented[cite: 1].
*   **CT Scanner Operating System:** The operating system running on the GE Revolution CT Scanner at Central Hospital is unspecified[cite: 1].
*   **Cisco Core Switch:** The specific model and firmware version of the Cisco core switch at Central Hospital are missing[cite: 1].
*   **Cloud Infrastructure Inventory:** Outside of Microsoft O365, there is no formal catalog of what other cloud services or Shadow IT apps are used by individual departments[cite: 1].
*   **Guest WiFi Isolation:** It is unverified whether the Central Hospital Guest WiFi SSID is truly logically isolated from the internal production network[cite: 1].

### Contradictions and Gaps
*   **The Unconfirmed Westside Server:** The asset list shows one server (`ws-srv-01`) at Westside[cite: 1], but Marcus's notes indicate that Mike Torres mentioned a *second* unconfirmed server hidden in the clinic's server closet[cite: 1].
*   **`print-srv-01` Status:** Marked as `[UNVERIFIED]` in the asset ticketing log and has not been physically checked for over a year[cite: 1], yet Marcus's notes reveal it is actively running an obsolete, unsupported OS (Windows Server 2012 R2)[cite: 1].
*   **Network Diagram vs. Documented Reality:** The network diagram shows an incomplete draft representation of a flat topology[cite: 1]. It fails to explicitly represent how Westside's internal network connects to its unmanaged switch or how its local endpoints interact[cite: 1].
*   **Legal vs. Actual Compliance Status:** The Legal department claims MedDefense is HIPAA compliant, yet there has never been a formal HIPAA Security Rule assessment, and the organization lacks an Incident Response Plan, Business Continuity Plan, or Disaster Recovery Plan[cite: 1].
*   **Physical Security Discrepancies:** The asset control system claims secure badge entry is utilized, but Marcus's notes confirm that the server room door uses a generic building badge accessible by any employee, and the Westside server closet does not lock at all[cite: 1].
