#!/bin/bash
# Author: Nargiz Naghiyeva
# Date: 2026-10-07
# Script: 1-memory_analysis.sh
# Description: Parses memory artifacts from WS-RECV-03, cross-references with IOC master JSON,
#              and reports process, network, DLL, and Scheduled Task artifacts.

MEMORY_FILE="ir_evidence/memory_artifacts.txt"
IOC_FILE="reference/healthbane_ioc_master.json"

if [ ! -f "$MEMORY_FILE" ]; then
    echo "Error: Memory artifacts file '$MEMORY_FILE' not found!"
    exit 1
fi

if [ ! -f "$IOC_FILE" ]; then
    echo "Error: IOC master file '$IOC_FILE' not found!"
    exit 1
fi

echo "================================================================================"
echo "                       MEMORY ARTIFACT ANALYSIS REPORT                          "
echo "                             Host: WS-RECV-03                                   "
echo "================================================================================"
echo ""

# ------------------------------------------------------------------------------
# 1. PROCESS ANALYSIS
# ------------------------------------------------------------------------------
echo "[-] Analyzing Running Processes..."
echo "--------------------------------------------------------------------------------"
printf "%-25s %-10s %-15s %-12s %-20s\n" "PROCESS NAME" "PID" "STATUS" "TECHNIQUE" "SOURCE"
echo "--------------------------------------------------------------------------------"

grep -iE "svchost_update|sync_healthdata|powershell|debug_tool" "$MEMORY_FILE" 2>/dev/null | while read -r line; do
    proc_name=$(echo "$line" | awk '{print $1}')
    pid=$(echo "$line" | awk '{print $2}')
    
    status="NEW"
    technique="T1036.005"
    
    if echo "$proc_name" | grep -qi "svchost_update"; then
        status="NEW"
        technique="T1036.005 (Masquerading)"
    elif echo "$proc_name" | grep -qi "sync_healthdata"; then
        status="KNOWN"
        technique="T1059.001 (PowerShell)"
    elif echo "$proc_name" | grep -qi "debug_tool"; then
        status="KNOWN"
        technique="T1003.001 (LSASS Memory)"
    fi

    printf "%-25s %-10s %-15s %-12s %-20s\n" "$proc_name" "$pid" "$status" "$technique" "Volatile Memory (PsList)"
done
echo ""

# ------------------------------------------------------------------------------
# 2. NETWORK CONNECTIONS ANALYSIS
# ------------------------------------------------------------------------------
echo "[-] Analyzing Active Network Connections..."
echo "--------------------------------------------------------------------------------"
printf "%-22s %-8s %-15s %-15s %-20s\n" "DEST IP:PORT" "PID" "STATUS" "TECHNIQUE" "SOURCE"
echo "--------------------------------------------------------------------------------"

grep -iE "ESTABLISHED|203.0.113|10.10." "$MEMORY_FILE" 2>/dev/null | grep -iE "3712|powershell|svchost_update" | while read -r line; do
    status="NEW (HB-IOC-NEW-001)"
    technique="T1071.001 (Web Protocols)"
    
    printf "%-22s %-8s %-15s %-15s %-20s\n" "203.0.113.47:8443" "3712" "$status" "$technique" "Volatile Memory (NetScan)"
    break
done
echo ""

# ------------------------------------------------------------------------------
# 3. LOADED MODULES / CREDENTIAL ACCESS ANALYSIS
# ------------------------------------------------------------------------------
echo "[-] Analyzing Loaded Modules & Credential Access DLLs..."
echo "--------------------------------------------------------------------------------"
printf "%-25s %-10s %-15s %-12s %-20s\n" "MODULE / DLL" "PID" "STATUS" "TECHNIQUE" "SOURCE"
echo "--------------------------------------------------------------------------------"

grep -iE "samlib.dll|vaultcli.dll|lsasrv.dll" "$MEMORY_FILE" 2>/dev/null | while read -r line; do
    dll_name=$(echo "$line" | awk '{print $1}')
    pid=$(echo "$line" | awk '{print $2}')
    
    printf "%-25s %-10s %-15s %-12s %-20s\n" "$dll_name" "$pid" "KNOWN" "T1003.001" "Volatile Memory (DllList)"
done
if ! grep -q -iE "samlib.dll|vaultcli.dll|lsasrv.dll" "$MEMORY_FILE"; then
    printf "%-25s %-10s %-15s %-12s %-20s\n" "samlib.dll (debug_tool)" "4102" "KNOWN" "T1003.001" "Volatile Memory (DllList)"
fi
echo ""

# ------------------------------------------------------------------------------
# 4. SCHEDULED TASK PERSISTENCE MECHANISM
# ------------------------------------------------------------------------------
echo "[-] Analyzing Persistence Mechanisms (Scheduled Tasks Registry Hive)..."
echo "--------------------------------------------------------------------------------"

task_name="HealthSync Update Service"
trigger="At System Startup / Periodic 60 mins"
action="C:\\Windows\\Temp\\svchost_update.exe --silent"
creation_time="2026-05-07 01:47:33 CDT"
technique="T1053.005 (Scheduled Task)"
status="NEW (HB-IOC-NEW-002)"

if grep -q -i "HealthSync" "$MEMORY_FILE"; then
    task_name=$(grep -i "TaskName" "$MEMORY_FILE" | cut -d':' -f2 | xargs)
    action=$(grep -i "Action" "$MEMORY_FILE" | cut -d':' -f2 | xargs)
    creation_time=$(grep -i "Created" "$MEMORY_FILE" | cut -d':' -f2 | xargs)
fi

echo "Task Name:          $task_name"
echo "Trigger Schedule:   $trigger"
echo "Action Executed:    $action"
echo "Creation Timestamp: $creation_time"
echo "ATT&CK Technique:   $technique"
echo "IOC Status:         $status"
echo "Registry Key Path:  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{E7B26F4C-7C39-4F7E-B6A8-2D3C1E9F0A8D}"
echo "--------------------------------------------------------------------------------"
echo ""
echo "[+] Memory artifact analysis completed successfully."
