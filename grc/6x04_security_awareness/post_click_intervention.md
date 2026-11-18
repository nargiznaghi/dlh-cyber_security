# Post-Click Intervention Design: MedDefense Health Systems

**Prepared by:** Nargiz Naghiyeva, Cybersecurity Engineer
**Date:** 2026-11-18
**Version:** 1.0
**Classification:** Confidential
**Governing constraints:** `post_click_microtraining_reference.md`, `simulation_ethics_guidelines.md`, `hr_privacy_rules.md`, `metrics_baseline.csv`

---

## Design Principles

Standard phishing landing pages ("You were phished") induce anxiety without building competence. MedDefense microtraining replaces shaming with immediate, non-blaming instruction. Every intervention opens by confirming the simulation, teaches directly from the template's specific red flags, provides three pre-click verification steps, and completes in under 5 minutes. Individual results remain strictly confidential under HR privacy rules.

---

## 1. Landing Page Variants (LPV-01 through LPV-04)

### 1.0 Shared Wrapper (All Variants)

```text
[MedDefense logo]    SECURITY AWARENESS TRAINING — SIMULATION

This was a simulation.

The message you just interacted with was sent by MedDefense's security team as
part of our security awareness training. Nothing bad has happened, and no real
accounts, benefits, or records were affected.

Being convinced by realistic lures is not a failure — these techniques target
busy professionals daily. What you do in the next five minutes matters most.

Continue to your 5-minute training →
ext. 4-SECURITY · security@meddefense.org · HR: [HR_CONTACT_LINE]
1.1 LPV-01 — Epic EHR Lure (SEG-B)
Why it worked: Operational tone, 48-hour deadline, and shift-start urgency regarding patient record access.
Red flags: Sender domain (epic-healthsystems.net), email delivery of login tasks (real Epic notices appear in-portal), engineered shift-start urgency.
Next time: Open Epic via bookmark; verify sender domain; treat shift-start urgency as a cue to verify first.
1.2 LPV-02 — MFA / Compliance Lure (SEG-C)
Why it worked: Borrowed familiarity from routine IT compliance deadlines and MFA rollouts.
Red flags: Lookalike domain (meddefense-it-support.org), emailed links for compliance tasks (intranet-only), reassuring text ("will not ask you to reset password") designed to bypass scrutiny.
Next time: Access compliance tasks via intranet bookmark; verify deadlines via ext. 4-HELP.
1.3 LPV-03 — HR Benefits Lure (SEG-C & SEG-E)
Why it worked: Personal financial stakes and urgent deadlines ("Final notice").
Red flags: External domain (meddefense-benefits.org), email links for benefit elections (intranet portal only), manufactured scarcity.
Next time: Check status directly in the HR portal; treat financial deadlines as a prompt to verify via known channels.
1.4 LPV-04 — Executive Wire Fraud (SEG-E & SEG-F)
Why it worked: Authority, confidentiality ("keep this between us"), and pre-empted verification ("can't take calls").
Red flags: Secrecy demand (isolates you from verification), unavailable requester, external reply-to address (exec-mail-consult.com).
Next time: Independently call the requester via directory; never resolve requests inside email threads; treat secrecy as a red flag.
2. Microtraining Module Structure (MT-01 through MT-04)
Each module follows a 4-part structure and completes in under 5 minutes:
What you saw: Annotated breakdown of the specific deceptive lines.
What an attacker gains: Concrete operational impact (e.g., Q1 incident: credential compromise leading to Cobalt Strike beacons and IR activation).
What to do next time: Three concrete pre-click verification rules.
How to report (Shared 30-second walkthrough):
Select email in Outlook → Click Report Phishing.
Alternative: Forward to security@meddefense.org or call ext. 4-SECURITY.
Rule: Reporting after a click still provides valuable SOC early warning; false positives are welcomed and absorbed.
3. Repeat-Click Escalation Protocol
Evaluated across consecutive waves (not within a single wave). Individual data is shielded from managers to preserve a non-punitive culture.
Stage	Trigger	Action & Notification	What Employee is Told
R0	Single click	Logged for training; LPV + MT assigned	Training moment; data protected.
R1	MT uncompleted at 72h	Friction check; gentle reminders at 72h/144h	Training remains available.
R2	Click in 2 consecutive waves	Program manager + HR notified; refresher assigned	Non-punitive refresher & optional practice set.
R3	Formal HR coaching trigger	HR-coordinated coaching conversation; department manager notified only under strict HR conditions	HR coaching session focused on workflow support, not discipline.
Note: Simulation data never enters performance reviews (hr_privacy_rules.md). Retention is capped at 18 months.
4. Positive Reinforcement Design
Timing: Delivered within 60 seconds of a correct report.
Content: Immediate confirmation toast, followed by a personalized email thanking the employee, highlighting the specific cue they defeated, and assuring them that reports are positive training data only.
Metrics Connection: Feeds directly into report rate and mean time to report (MTTR) improvement targets.
