# LIS Recovery Test Record

**Test date:** 2026-11-16  
**Test conductor:** Nargiz Naghiyeva  
**Declared RTO:** 30 minutes  
**Test environment:** `/tmp/meddefense-dr-test`  

## Step Timing Log

```text
[STEP 01] Identify recovery target                   | Start: 09:14:32 | End: 09:15:15 | Duration: 0m 43s | PASS
[STEP 02] Verify backup integrity                    | Start: 09:15:15 | End: 09:16:02 | Duration: 0m 47s | PASS
[STEP 03] Create recovery workspace                  | Start: 09:16:02 | End: 09:16:20 | Duration: 0m 18s | PASS
[STEP 04] Decompress backup archive                  | Start: 09:16:20 | End: 09:17:45 | Duration: 1m 25s | PASS
[STEP 05] Restore SQL dump into SQLite               | Start: 09:17:45 | End: 09:19:30 | Duration: 1m 45s | PASS
[STEP 06] Check row count in patient_orders          | Start: 09:19:30 | End: 09:20:10 | Duration: 0m 40s | PASS
[STEP 07] Confirm critical results for MRN & config  | Start: 09:20:10 | End: 09:26:46 | Duration: 6m 36s | PASS

========================================================================
                   LIS RECOVERY TEST SUMMARY REPORT                     
========================================================================
Total Recovery Time: 12m 14s
Declared RTO Target: 30 minutes
RTO Compliance Status: YES (Passed within 30 minutes)
========================================================================
Conditions Encountered
Condition 1: Path mismatch
Discovered at: 09:16:20
Runbook specified: /recovery/lis_dump.sql
Actual path: /tmp/meddefense-dr-test/recovery/lis_dump.sql
Resolution: Corrected extraction and decompression paths to target /tmp/meddefense-dr-test/recovery/lis_dump.sql instead of root-level /recovery.
Time added: 2 minutes
Condition 2: Configuration artifact
Discovered at: 09:20:10
Expected: Local recovery database path for validation
Actual: DB_HOST=lis-db-prod.meddefense.internal found in /tmp/meddefense-dr-test/config/app_config.env
Resolution: Applied local recovery override by targeting the SQLite database file explicitly (/tmp/meddefense-dr-test/recovery/lis_recovered.db) rather than attempting TCP/socket connection to the production database host during offline recovery.
Time added: 3 minutes
Condition 3: Row count check
Query: SELECT COUNT(*) FROM patient_orders;
Expected: 5
Actual: 5
Outcome: PASS
Recovery Validation
Recovered database file:
Plaintext
-rw-r--r-- 1 student student 18432 Nov 16 09:19 /tmp/meddefense-dr-test/recovery/lis_recovered.db
Critical values accessible:
Plaintext
MRN-10043|LAB-8821|6.1 mEq/L|1
MRN-10045|LAB-9012|0.08 ng/mL|1
Test Result
Actual recovery time: 12m 14s
RTO met: YES
Test outcome: CONDITIONAL PASS (Deviations documented and resolved per James Chen's directive)
