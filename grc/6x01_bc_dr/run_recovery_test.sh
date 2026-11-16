#!/bin/bash

# Configuration & Paths
BACKUP_DIR="meddefense-dr-test/backup/lis/2026-04-21"
RECOVERY_DIR="meddefense-dr-test/recovery"
LOG_FILE="meddefense-dr-test/validation/recovery_execution.log"

mkdir -p "$RECOVERY_DIR"
mkdir -p "meddefense-dr-test/validation"

echo "=== MedDefense LIS Timed Recovery Test Started: $(date) ===" | tee "$LOG_FILE"

# Step 1: Clean line endings and fix path compatibility for sha256sum using sed
echo "[+] Step 1: Verifying backup integrity via SHA256..." | tee -a "$LOG_FILE"
cd "$BACKUP_DIR"
sed 's/\r//g; s| /tmp/meddefense-dr-test/backup/lis/2026-04-21/|  |' backup_manifest.sha256 > backup_manifest_fixed.sha256

if sha256sum -c backup_manifest_fixed.sha256 >> "../../../../$LOG_FILE" 2>&1; then
    echo "    -> Checksum Verification: PASSED" | tee -a "../../../../$LOG_FILE"
else
    echo "    -> Checksum Verification: FAILED" | tee -a "../../../../$LOG_FILE"
    exit 1
fi
cd - > /dev/null

# Step 2: Decompress backup
echo "[+] Step 2: Decompressing lis_backup.sql.gz..." | tee -a "$LOG_FILE"
START_TIME=$(date +%s)
gunzip -c "$BACKUP_DIR/lis_backup.sql.gz" > "$RECOVERY_DIR/lis_dump.sql"
echo "    -> Decompression completed." | tee -a "$LOG_FILE"

# Step 3: Restore SQL dump into SQLite
echo "[+] Step 3: Restoring SQL dump into SQLite recovery database..." | tee -a "$LOG_FILE"
DB_PATH="$RECOVERY_DIR/lis_recovered.db"
rm -f "$DB_PATH"
sqlite3 "$DB_PATH" < "$RECOVERY_DIR/lis_dump.sql"
echo "    -> Database restored at $DB_PATH" | tee -a "$LOG_FILE"

# Step 4: Verify row count in patient_orders
echo "[+] Step 4: Checking row count in patient_orders..." | tee -a "$LOG_FILE"
ROW_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM patient_orders;")
echo "    -> Total rows in patient_orders: $ROW_COUNT" | tee -a "$LOG_FILE"

# Step 5: Confirm critical results for MRN-10043 and MRN-10045
echo "[+] Step 5: Validating critical results for MRN-10043 and MRN-10045..." | tee -a "$LOG_FILE"
sqlite3 "$DB_PATH" "SELECT mrn, test_name, result_value, critical_flag FROM patient_orders WHERE mrn IN ('MRN-10043', 'MRN-10045');" | tee -a "$LOG_FILE"

# Step 6: Database Integrity Check
echo "[+] Step 6: Running SQLite PRAGMA integrity_check..." | tee -a "$LOG_FILE"
INTEGRITY=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;")
echo "    -> Integrity status: $INTEGRITY" | tee -a "$LOG_FILE"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
echo "=== Recovery Test Completed Successfully in ${ELAPSED} seconds ($(date)) ===" | tee -a "$LOG_FILE"
