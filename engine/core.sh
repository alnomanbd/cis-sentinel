#!/bin/bash

# ============================================================
# CIS SENTINEL CORE ENGINE
# Shared utilities for logging, formatting, helpers
# Ubuntu 22.04 / 24.04 SOC Framework
# ============================================================

# ------------------------------
# COLOR DEFINITIONS
# ------------------------------
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

# ------------------------------
# LOG FILE (fallback safety)
# ------------------------------
LOG_FILE="${LOG_FILE:-cis_default.log}"

# ------------------------------
# CENTRAL RESULT FUNCTION
# ------------------------------
result(){

    STATUS=$1
    CIS_ID=$2
    SEVERITY=$3
    MESSAGE=$4
    EVIDENCE=$5

    case "$STATUS" in
        PASS)
            COLOR=$GREEN
            ;;
        FAIL)
            COLOR=$RED
            ;;
        WARN)
            COLOR=$YELLOW
            ;;
        INFO)
            COLOR=$BLUE
            ;;
    esac

    # Console output
    echo -e "${COLOR}[${STATUS}] | ${CIS_ID} | ${SEVERITY} | ${MESSAGE}${RESET}"
    echo "  └─ Evidence: ${EVIDENCE}"

    # Log file output (structured)
    echo "[${STATUS}]|${CIS_ID}|${SEVERITY}|${MESSAGE}|${EVIDENCE}" >> "$LOG_FILE"
}

# ------------------------------
# SAFE COMMAND EXECUTOR
# (prevents script crash)
# ------------------------------
safe_run(){
    "$@" 2>/dev/null
}

# ------------------------------
# CHECK COMMAND EXISTS
# ------------------------------
command_exists(){
    command -v "$1" &>/dev/null
}

# ------------------------------
# SYSTEM INFO HELPER
# ------------------------------
get_hostname(){
    hostname 2>/dev/null
}

get_kernel(){
    uname -r 2>/dev/null
}

get_os(){
    cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"'
}

# ------------------------------
# TIME HELPER
# ------------------------------
get_timestamp(){
    date "+%F_%H-%M-%S"
}

# ------------------------------
# SIMPLE SCORE HELPERS (optional extension hook)
# ------------------------------
increment_pass(){
    PASS_COUNT=$((PASS_COUNT + 1))
}

increment_fail(){
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

increment_warn(){
    WARN_COUNT=$((WARN_COUNT + 1))
}

# ------------------------------
# HEADER PRINT
# ------------------------------
print_header(){
    echo "======================================================"
    echo " CIS SENTINEL ENGINE "
    echo " Host: $(get_hostname)"
    echo " OS  : $(get_os)"
    echo " Kernel: $(get_kernel)"
    echo "======================================================"
}