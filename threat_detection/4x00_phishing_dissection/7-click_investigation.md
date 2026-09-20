## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts
- Affected User: Diane Marsh
- Workstation ID: WS-NURSE-04
- Source Email: Email 2 (Motive: Portal re-verification lure)
- Target URL / Domain: hxxp://meddefense-portal[.]com/login/verify
- Related Malicious IP: 91.234.99.107
- Interaction Event: User reported clicking the link contained within Email 2

### Key Unknowns
- Whether user credentials (username and password) were actually submitted on the phishing landing page.
- Whether any secondary payload or malicious file was downloaded and executed upon visiting the page.
- Whether browser session tokens or cookies were harvested during the interaction.

### Endpoint Checks To Perform
- Browser History & Cache: Inspect browser history and web cache on WS-NURSE-04 for exact access timestamps and POST request submissions.
- Download History & File System Creation: Check Downloads folder and `%TEMP%` directory for downloaded executables, scripts, or PDF files.
- Process Execution Logs: Review process execution logs (e.g., PowerShell, cmd.exe, wscript.exe, mshta.exe) around the timestamp of the click event.
- Network Connection Logs: Inspect local outbound network connections to IP 91.234.99.107 or related C2 infrastructure.

### Account Checks To Perform
- Authentication & Sign-in Logs: Search Azure AD / Entra ID or Active Directory sign-in logs for successful or failed login attempts originating from untrusted IPs.
- Multi-Factor Authentication (MFA): Audit MFA prompt logs for unexpected push notifications, failed attempts, or newly registered MFA devices.
- Password & Session Activity: Check if password reset requests or credential changes occurred shortly after the click.
- Mailbox Audit: Check for newly created inbox forwarding rules, redirect rules, or suspicious API integrations on Diane Marsh's mailbox.

### Decision Matrix
| Outcome | Condition | Required Action |
|---|---|---|
| No Compromise Found | User clicked link but closed browser immediately; no credential POST request, no file download, no anomalous logins. | Close incident, conduct targeted phishing training for user. |
| Possible Credential Exposure | User visited credential harvesting page and likely entered credentials; no secondary endpoint malware detected. | Force password reset, revoke active MFA/session tokens, enable enhanced mailbox audit logging. |
| Confirmed Compromise | User submitted credentials and anomalous successful sign-in or endpoint malware execution was observed. | Isolate WS-NURSE-04 from network, revoke all access, reset credentials, launch full forensic incident response. |

### Recommended Containment
1. Immediate Credential Reset: Reset Diane Marsh's domain and cloud credentials immediately.
2. Revoke Active Sessions: Terminate all active OAuth tokens and user sessions across all systems.
3. User Interview: Interview Diane Marsh to confirm whether credentials were typed into the landing page.
4. Host Monitoring: Temporarily increase monitoring on WS-NURSE-04 and audit account activity for the next 14 days.

### Conclusion
A reported click on a credential-harvesting phishing link poses a high severity risk even prior to confirming credential entry. Executing targeted endpoint and identity checks allows analysts to accurately classify the incident outcome and prevent lateral movement or cloud account takeover.
