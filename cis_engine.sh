#!/bin/bash

# ============================================================
# CIS SECURITY ENGINE (SOC / ENTERPRISE FRAMEWORK)
# ============================================================

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------
# ROOT CHECK
# ------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[!] Please run as root (sudo required)"
    exit 1
fi

# ------------------------------
# GLOBAL VARIABLES
# ------------------------------
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%F_%H-%M-%S)

OUTPUT_DIR="$BASE_DIR/output"
LOG_DIR="$OUTPUT_DIR/logs"
JSON_DIR="$OUTPUT_DIR/json"
HTML_DIR="$OUTPUT_DIR/html"

mkdir -p "$LOG_DIR" "$JSON_DIR" "$HTML_DIR"

export HOSTNAME
export TIMESTAMP
export LOG_FILE="$LOG_DIR/cis_report_${HOSTNAME}_${TIMESTAMP}.log"
export JSON_DIR
export HTML_DIR

touch "$LOG_FILE"

# ------------------------------
# HEADER
# ------------------------------
echo "=====================================================" | tee -a "$LOG_FILE"
echo " CIS SECURITY ENGINE STARTED " | tee -a "$LOG_FILE"
echo " Host: $HOSTNAME " | tee -a "$LOG_FILE"
echo " Time: $TIMESTAMP " | tee -a "$LOG_FILE"
echo "=====================================================" | tee -a "$LOG_FILE"

# ------------------------------
# LOAD CORE
# ------------------------------
source "$BASE_DIR/engine/compliance.sh"
source "$BASE_DIR/engine/core.sh" 2>/dev/null

# ------------------------------
# LOAD CHECK MODULES
# ------------------------------
echo "[*] Loading CIS Modules..." | tee -a "$LOG_FILE"

source "$BASE_DIR/checks/filesystem.sh"
source "$BASE_DIR/checks/network.sh"
source "$BASE_DIR/checks/logging.sh"
source "$BASE_DIR/checks/auth.sh"
source "$BASE_DIR/checks/kernel.sh"
source "$BASE_DIR/checks/fim.sh"
source "$BASE_DIR/checks/users.sh"
source "$BASE_DIR/checks/exposure.sh"
source "$BASE_DIR/checks/malware.sh"
source "$BASE_DIR/checks/services.sh"
source "$BASE_DIR/checks/cloud.sh"
source "$BASE_DIR/checks/time.sh"

echo "[+] Modules Loaded Successfully" | tee -a "$LOG_FILE"

# ------------------------------
# EXECUTION
# ------------------------------
echo ""
echo "====================================================="
echo " RUNNING CIS COMPLIANCE AUDIT "
echo "====================================================="

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

echo "[*] Running File Integrity Checks..." | tee -a "$LOG_FILE"
run_fim

echo "[*] Running User Security Checks..." | tee -a "$LOG_FILE"
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
# FINAL REPORT
# ------------------------------
echo ""
echo "====================================================="
echo " GENERATING FINAL REPORT "
echo "====================================================="

source "$BASE_DIR/report/report.sh"

# ------------------------------
# END
# ------------------------------
echo ""
echo "====================================================="
echo " CIS SECURITY ENGINE COMPLETED "
echo "====================================================="
echo " Log File : $LOG_FILE"
echo "====================================================="