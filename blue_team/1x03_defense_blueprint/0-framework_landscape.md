# 0. The Framework Landscape

## Part 1 - Three-Framework Summary

### NIST Cybersecurity Framework (CSF) 2.0
NIST CSF 2.0 is a voluntary risk management framework published by the National Institute of Standards and Technology (NIST), a non-regulatory agency of the U.S. Department of Commerce. It is designed to help organizations of any size or sector manage, understand, and reduce cybersecurity risks in alignment with business goals. The framework is structured around six Core Functions: Govern, Identify, Protect, Detect, Respond, and Recover, which break down into Categories and Subcategories mapped to implementation outcomes. It is widely used by executive teams, CISOs, and enterprise risk managers to establish baseline security postures, communicate risk to non-technical stakeholders, and align security investments with organizational priorities.

### CIS Critical Security Controls (v8)
The CIS Controls v8 is a prioritized set of actionable cybersecurity safeguards published by the Center for Internet Security (CIS), a non-profit community-driven organization. It is designed to provide specific, technical guidance on defending against the most common real-world cyber threats by offering a practical roadmap for security implementation. The framework is structured into 18 Controls containing 153 Safeguards, categorized into three Implementation Groups (IG1, IG2, IG3) based on organizational capacity and resource constraints. It is typically used by IT administrators, security engineers, and operational blue teams who need step-by-step technical blueprints for hardening systems and managing enterprise assets.

### ISO/IEC 27001:2022
ISO/IEC 27001 is an internationally recognized standard for Information Security Management Systems (ISMS), jointly published by the International Organization for Standardization (ISO) and the International Electrotechnical Commission (IEC). Its primary purpose is to specify requirements for establishing, implementing, maintaining, and continually improving a formalized information security governance model. The standard is structured into 11 main management clauses (Clauses 4 through 10) covering leadership, risk, and continuous improvement, alongside Annex A, which references 93 granular security controls organized into four themes (Organizational, People, Physical, Technological). It is predominantly used by compliance officers, auditors, and enterprises seeking formal certification to demonstrate security posture to third parties, clients, and regulators.

---

## Part 2 - Relationship Map

NIST CSF 2.0, CIS Controls v8, and ISO 27001 are complementary frameworks that serve distinct operational functions within an enterprise security strategy. A helpful mental model to understand their synergy is that **NIST CSF answers "What should we do?", CIS Controls answers "How should we do it?", and ISO 27001 answers "Can we prove we are doing it?"** An organization uses NIST CSF as its high-level strategic compass to identify business risks, categorize capabilities, and define target outcomes across its executive leadership. It then maps these high-level CSF outcomes directly to CIS Controls—specifically Implementation Group 1 (IG1) for basic cyber hygiene—to gain technical, step-by-step configuration guidance for its engineering teams. Finally, ISO 27001 provides the overarching audit and management structure needed to evaluate policy compliance, enforce continuous improvement, and obtain formal certification. Rather than choosing one over the others, mature security programs leverage NIST CSF for strategic positioning, CIS for tactical execution, and ISO 27001 for operational proof and regulatory assurance.

---

## Part 3 - MedDefense Framework Selection

### Strategic Recommendation
MedDefense should adopt **NIST CSF 2.0 as its strategic operational backbone**, paired with **CIS Controls v8 (Implementation Group 1)** as its tactical implementation guide.

### Justification
1. **Resource Constraints (2-Person Security Team):** MedDefense operates with a lean team consisting of a single Security Analyst and a Deputy CISO. Full compliance or immediate certification under ISO 27001 requires massive administrative overhead, formal policy documentation, and continuous auditing, which would overwhelm this limited staff.
2. **Actionable Implementation via CIS IG1:** Since MedDefense currently has no formal framework in place, starting directly with high-level policies will not secure clinical systems. CIS Implementation Group 1 (IG1) provides 56 foundational safeguards designed specifically for small-to-medium teams with limited expertise, giving the team a clear, prioritized checklist to achieve basic cyber hygiene without reinventing the wheel.
3. **Board & Regulatory Communication via NIST CSF 2.0:** As a regional hospital, MedDefense must communicate posture to both healthcare regulators and the Board of Directors. NIST CSF 2.0 offers a simple, widely recognized vocabulary across its six core functions (*Govern, Identify, Protect, Detect, Respond, Recover*). The Deputy CISO can use NIST CSF tiers and target profiles to present clear progress reports to the Board without burdening them with technical jargon.
4. **Future Scalability:** NIST CSF and CIS Controls map seamlessly into HIPAA compliance requirements and provide an ideal foundation. Should MedDefense grow in size or face future regulatory mandates requiring formal ISO 27001 certification, the controls established via NIST/CIS will easily translate into the ISO Annex A baseline without redundant effort.
