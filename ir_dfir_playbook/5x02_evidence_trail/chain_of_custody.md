# Chain of Custody: LH-2026-0414-01

## Case Header
- **Case number:** LH-2026-0414-01
- **Incident ID:** IR-2026-0414-01
- **Lead investigator:** Nargiz Naghiyeva
- **Date opened:** 2026-10-21
- **Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z

## Artifact Registry

| Artifact ID | Name | Format | Acquired By | Acquired At (UTC) | Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| ART-001 | wst-ws-031.dd | RAW | Mike Torres | 2026-04-14T06:14:00Z | FTK Imager | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | /evidence/wst-ws-031.dd | read-only, IR team only |
| ART-002 | wst-ws-031.mem | RAW | Mike Torres | 2026-04-14T03:02:00Z | WinPmem | 8743b123773f320d4f24823126f5348324e93011320392341238918239012891 | /evidence/wst-ws-031.mem | read-only, IR team only |
| ART-003 | wst-ws-017.mem | RAW | Mike Torres | 2026-04-14T03:38:00Z | WinPmem | a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef | /evidence/wst-ws-017.mem | read-only, IR team only |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool Used | Hash Verified | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-21T08:00:00Z | Nargiz Naghiyeva | ART-001 | hash_verify | sha256sum | yes | Baseline established; hash stored in registry |
| 2026-10-21T08:05:00Z | Nargiz Naghiyeva | ART-002 | hash_verify | sha256sum | yes | Baseline established; hash stored in registry |
| 2026-10-21T08:10:00Z | Nargiz Naghiyeva | ART-003 | hash_verify | sha256sum | yes | Baseline established; hash stored in registry |
| 2026-10-21T08:15:00Z | Nargiz Naghiyeva | ART-001 | DEVIATION_NOTE | FTK Imager | no | DEVIATION: Prior read-write mount by M.Torres altered original filesystem state before acquisition baseline |
