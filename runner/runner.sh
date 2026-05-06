#!/bin/bash

# ============================================================
# CIS SOC AUDIT ENGINE - RUNNER
# Ubuntu 22.04 / 24.04 (Enterprise Ready)
# ============================================================

BASE_DIR="$(pwd)"

# ------------------------------
# ENGINE & CORE LOADING
# ------------------------------
source engine/compliance.sh
source engine/core.sh 2>/dev/null

# ------------------------------
# MODULE LOADING
# ------------------------------
source checks/filesystem.sh
source checks/network.sh
source checks/logging.sh
source checks/auth.sh
source checks/kernel.sh
source checks/fim.sh
source checks/users.sh
source checks/exposure.sh
source checks/malware.sh
source checks/services.sh
source checks/cloud.sh
source checks/time.sh
source checks/compliance.sh

# ------------------------------
# INIT REPORT FILE
# ------------------------------
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%F_%H-%M-%S)

LOG_FILE="cis_report_${HOSTNAME}_${TIMESTAMP}.log"
JSON_FILE="cis_report_${HOSTNAME}_${TIMESTAMP}.json"

echo "===== CIS SOC AUDIT STARTED =====" | tee "$LOG_FILE"
echo "Host: $HOSTNAME | Time: $TIMESTAMP" | tee -a "$LOG_FILE"
echo "==================================" | tee -a "$LOG_FILE"

# ------------------------------
# START AUDIT FLOW
# ------------------------------
echo "[*] Running Filesystem Checks..." | tee -a "$LOG_FILE"
run_filesystem

echo "[*] Running Network Checks..." | tee -a "$LOG_FILE"
run_network

echo "[*] Running Logging Checks..." | tee -a "$LOG_FILE"
run_logging

echo "[*] Running Authentication Checks..." | tee -a "$LOG_FILE"
run_auth

echo "[*] Running Kernel Checks..." | tee -a "$LOG_FILE"
run_kernel

echo "[*] Running FIM Checks..." | tee -a "$LOG_FILE"
run_fim

echo "[*] Running User Checks..." | tee -a "$LOG_FILE"
run_users

echo "[*] Running Exposure Checks..." | tee -a "$LOG_FILE"
run_exposure

echo "[*] Running Malware Checks..." | tee -a "$LOG_FILE"
run_malware

echo "[*] Running Services Checks..." | tee -a "$LOG_FILE"
run_services

echo "[*] Running Cloud Checks..." | tee -a "$LOG_FILE"
run_cloud

echo "[*] Running Time Integrity Checks..." | tee -a "$LOG_FILE"
run_time

# ------------------------------
# FINAL SUMMARY
# ------------------------------
echo ""
echo "[*] Generating Compliance Summary..." | tee -a "$LOG_FILE"
generate_summary | tee -a "$LOG_FILE"

# ------------------------------
# JSON EXPORT (SIEM READY)
# ------------------------------
SCORE=$(calculate_score)

cat <<EOF > "$JSON_FILE"
{
  "host": "$HOSTNAME",
  "timestamp": "$TIMESTAMP",
  "total_checks": "$TOTAL_CHECKS",
  "passed": "$PASS_COUNT",
  "failed": "$FAIL_COUNT",
  "warnings": "$WARN_COUNT",
  "critical_fails": "$CRITICAL_FAILS",
  "high_fails": "$HIGH_FAILS",
  "compliance_score": "$SCORE"
}
EOF

echo "[*] JSON Report Generated: $JSON_FILE" | tee -a "$LOG_FILE"

# ------------------------------
# COMPLETION MESSAGE
# ------------------------------
echo ""
echo "===== CIS AUDIT COMPLETED ====="
echo "Log File : $LOG_FILE"
echo "JSON File: $JSON_FILE"
echo "==============================="