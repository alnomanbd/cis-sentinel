#!/bin/bash

# ============================================================
# CIS COMPLIANCE SCORING ENGINE
# Ubuntu 22.04 / 24.04 (SOC / Enterprise Ready)
# ============================================================

# ------------------------------
# GLOBAL SCORE VARIABLES
# ------------------------------
TOTAL_CHECKS=0
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

CRITICAL_FAILS=0
HIGH_FAILS=0

# ------------------------------
# RESULT HANDLER (USED BY ALL MODULES)
# ------------------------------
result(){

    STATUS=$1      # PASS / FAIL / WARN
    CIS_ID=$2
    SEVERITY=$3
    MESSAGE=$4
    EVIDENCE=$5

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "$STATUS" in
        PASS)
            PASS_COUNT=$((PASS_COUNT + 1))
            COLOR="\e[32m"
            ;;
        FAIL)
            FAIL_COUNT=$((FAIL_COUNT + 1))
            COLOR="\e[31m"
            ;;
        WARN)
            WARN_COUNT=$((WARN_COUNT + 1))
            COLOR="\e[33m"
            ;;
    esac

    # Severity tracking
    if [[ "$STATUS" == "FAIL" && "$SEVERITY" == "CRITICAL" ]]; then
        CRITICAL_FAILS=$((CRITICAL_FAILS + 1))
    fi

    if [[ "$STATUS" == "FAIL" && "$SEVERITY" == "HIGH" ]]; then
        HIGH_FAILS=$((HIGH_FAILS + 1))
    fi

    # Console Output
    echo -e "${COLOR}[${STATUS}] | ${CIS_ID} | ${SEVERITY} | ${MESSAGE}\e[0m"
    echo "  └─ Evidence: ${EVIDENCE}"

    # Log File Output
    echo "[${STATUS}] | ${CIS_ID} | ${SEVERITY} | ${MESSAGE} | ${EVIDENCE}" >> "$LOG_FILE"
}

# ------------------------------
# COMPLIANCE SCORE CALCULATOR
# ------------------------------
calculate_score(){

    if [[ "$TOTAL_CHECKS" -eq 0 ]]; then
        echo 0
        return
    fi

    SCORE=$(( (PASS_COUNT * 100) / TOTAL_CHECKS ))

    # Penalty system (SOC-grade weighting)
    SCORE=$(( SCORE - (CRITICAL_FAILS * 10) ))
    SCORE=$(( SCORE - (HIGH_FAILS * 5) ))

    if [[ "$SCORE" -lt 0 ]]; then
        SCORE=0
    fi

    echo "$SCORE"
}

# ------------------------------
# FINAL REPORT SUMMARY
# ------------------------------
generate_summary(){

    SCORE=$(calculate_score)

    echo ""
    echo "======================================================"
    echo "               CIS COMPLIANCE SUMMARY"
    echo "======================================================"
    echo "Host           : $(hostname)"
    echo "Date           : $(date)"
    echo "------------------------------------------------------"
    echo "Total Checks   : $TOTAL_CHECKS"
    echo "Passed         : $PASS_COUNT"
    echo "Failed         : $FAIL_COUNT"
    echo "Warnings       : $WARN_COUNT"
    echo "Critical Fails : $CRITICAL_FAILS"
    echo "High Fails     : $HIGH_FAILS"
    echo "------------------------------------------------------"
    echo "Compliance Score: ${SCORE}%"
    echo "------------------------------------------------------"

    # Risk classification
    if [[ "$SCORE" -ge 90 ]]; then
        echo "Status: 🟢 SECURE (CIS COMPLIANT)"
    elif [[ "$SCORE" -ge 75 ]]; then
        echo "Status: 🟡 MODERATE (NEEDS IMPROVEMENT)"
    elif [[ "$SCORE" -ge 50 ]]; then
        echo "Status: 🟠 HIGH RISK"
    else
        echo "Status: 🔴 CRITICAL RISK"
    fi

    echo "======================================================"
}

# ------------------------------
# RESET ENGINE (optional re-run support)
# ------------------------------
reset_engine(){
    TOTAL_CHECKS=0
    PASS_COUNT=0
    FAIL_COUNT=0
    WARN_COUNT=0
    CRITICAL_FAILS=0
    HIGH_FAILS=0
}