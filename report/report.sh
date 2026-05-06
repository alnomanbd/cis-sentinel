#!/bin/bash

# ============================================================
# CIS SECURITY ENGINE (SOC / ENTERPRISE FRAMEWORK)
# Ubuntu 22.04 / 24.04
# ============================================================

BASE_DIR="$(pwd)"

# ------------------------------
# ROOT CHECK
# ------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[!] Please run as root (sudo required)"
    exit 1
fi

# ------------------------------
# GLOBAL LOGGING SETUP
# ------------------------------
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%F_%H-%M-%S)

export LOG_FILE="cis_report_${HOSTNAME}_${TIMESTAMP}.log"

touch "$LOG_FILE"

echo "=====================================================" | tee -a "$LOG_FILE"
echo " CIS SECURITY ENGINE STARTED " | tee -a "$LOG_FILE"
echo " Host: $HOSTNAME " | tee -a "$LOG_FILE"
echo " Time: $TIMESTAMP " | tee -a "$LOG_FILE"
echo "=====================================================" | tee -a "$LOG_FILE"

# ------------------------------
# LOAD CORE ENGINE
# ------------------------------
source engine/compliance.sh
source engine/core.sh 2>/dev/null

# ------------------------------
# LOAD MODULES (CHECKS)
# ------------------------------
echo "[*] Loading CIS Modules..." | tee -a "$LOG_FILE"

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

echo "[+] Modules Loaded Successfully" | tee -a "$LOG_FILE"

# ------------------------------
# EXECUTION START
# ------------------------------
echo ""
echo "====================================================="
echo " RUNNING CIS COMPLIANCE AUDIT "
echo "====================================================="

# Filesystem
echo "[*] Running Filesystem Checks..." | tee -a "$LOG_FILE"
run_filesystem

# Network
echo "[*] Running Network Checks..." | tee -a "$LOG_FILE"
run_network

# Logging
echo "[*] Running Logging Checks..." | tee -a "$LOG_FILE"
run_logging

# Authentication
echo "[*] Running Authentication Checks..." | tee -a "$LOG_FILE"
run_auth

# Kernel
echo "[*] Running Kernel Checks..." | tee -a "$LOG_FILE"
run_kernel

# FIM
echo "[*] Running File Integrity Checks..." | tee -a "$LOG_FILE"
run_fim

# Users
echo "[*] Running User Security Checks..." | tee -a "$LOG_FILE"
run_users

# Exposure
echo "[*] Running Exposure Checks..." | tee -a "$LOG_FILE"
run_exposure

# Malware
echo "[*] Running Malware Checks..." | tee -a "$LOG_FILE"
run_malware

# Services
echo "[*] Running Services Checks..." | tee -a "$LOG_FILE"
run_services

# Cloud
echo "[*] Running Cloud Checks..." | tee -a "$LOG_FILE"
run_cloud

# Time Integrity
echo "[*] Running Time Integrity Checks..." | tee -a "$LOG_FILE"
run_time

# ------------------------------
# FINAL REPORT GENERATION
# ------------------------------
echo ""
echo "====================================================="
echo " GENERATING FINAL REPORT "
echo "====================================================="

source report.sh

# ------------------------------
# END MESSAGE
# ------------------------------
echo ""
echo "====================================================="
echo " CIS SECURITY ENGINE COMPLETED "
echo "====================================================="
echo " Log File : $LOG_FILE"
echo "====================================================="