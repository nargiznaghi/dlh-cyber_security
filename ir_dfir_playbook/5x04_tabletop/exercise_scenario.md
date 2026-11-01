# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** November 5, 2026  
**Classification:** Internal - Exercise Use Only  
**Facilitator:** Nargiz Naghiyeva  
**Scenario Version:** 1.0  

## Organization background
MedDefense operates three healthcare sites (Main Campus, West Campus, and North Site) handling approximately 3,500 patient-facing interactions per week. As a covered entity under HIPAA, MedDefense processes ePHI including patient demographic and insurance eligibility data. The organization is bound by strict HIPAA reporting deadlines and clinical continuity requirements across all operational locations.

## Vendor background
Nexus Patient Scheduling (Nexus Health Technologies, Inc., Austin, TX) is a cloud-hosted multi-tenant SaaS platform used for outpatient scheduling and pre-registration since August 2023. 

- **Integration Topology:** Integrates with Epic via HL7 FHIR R4 over HTTPS using an OAuth2 client credentials flow bound to service principal `svc-nexus-prod`.
- **Network Path:** MedDefense queries Nexus at `https://fhir.nexushealth.io/v1/`, while Nexus calls `https://ehr-ingest.meddefense.local/nexus-inbound/` over a site-to-site IPsec tunnel.
- **Software Updates:** Automatic deployment of agent updates to an on-prem component (`nexus-agent`) installed on dedicated server `SCHED-SVR-01` at Main Campus, signed by "Nexus Health Technologies, Inc."
- **BAA & SLAs:** Active BAA (amended May 2025) mandating breach notification to MedDefense within 24 hours of discovery.
- **Vendor Risk Context:** A security review conducted on November 14, 2025, identified key residual risks: reliance solely on code-signing certificate validation without client-side hash pinning, lack of a Software Bill of Materials (SBOM) for npm dependencies, and an untested joint incident communication path.

## Opening situation
Three days ago, Nexus's build infrastructure in `us-east-1` was compromised by a threat actor who injected a malicious payload into the agent software pipeline. A cryptographically signed update was automatically distributed and installed on `SCHED-SVR-01`. The backdoor has been executing silently on MedDefense's network since deployment. Today, exactly 45 minutes ago, the SOC flagged an automated alert showing unauthorized, periodic outbound beaconing from `SCHED-SVR-01` to an unknown external IP address at four-hour intervals.

### Design Ambiguities & Organizational Tensions
- **Vendor Trust vs. Isolation:** The malicious update carries a valid code-signing certificate from "Nexus Health Technologies, Inc." Internal teams must resolve whether vendor trust allows for waiting on a patch or if immediate network segment isolation (severing the IPsec tunnel and FHIR API) is required.
- **Patient Safety & Clinical Integrity:** Outbound exfiltration telemetry indicates potential tampering with inbound HL7 FHIR data flows, creating an unresolved tension over whether active appointment rosters across all three sites can be trusted for clinical operations.
- **HIPAA Regulatory Obligations:** Under the BAA, Nexus is obligated to notify MedDefense within 24 hours of discovery. However, with exfiltration detected locally before official vendor notification, Legal Counsel must evaluate whether MedDefense's independent HIPAA breach notification timeline is immediately triggered.
