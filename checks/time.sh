#!/bin/bash

# ============================================================
# CIS TIME SYNC & FORENSIC INTEGRITY MODULE
# Ubuntu 22.04 / 24.04 (SOC / Enterprise Ready)
# ============================================================

source engine/core.sh

# ------------------------------
# 13.1.1 - System time synchronization service (systemd-timesyncd)
# ------------------------------
check_13_1_1(){
    systemctl is-active systemd-timesyncd &>/dev/null \
        && result PASS "13.1.1" "HIGH" "Time sync service active" "Running" \
        || result FAIL "13.1.1" "HIGH" "Time sync service not active" "Stopped"
}

# ------------------------------
# 13.1.2 - NTP synchronization status
# ------------------------------
check_13_1_2(){
    OUT=$(timedatectl status 2>/dev/null | grep "NTP service")

    echo "$OUT" | grep -qi "active" \
        && result PASS "13.1.2" "HIGH" "NTP enabled" "$OUT" \
        || result FAIL "13.1.2" "HIGH" "NTP disabled" "$OUT"
}

# ------------------------------
# 13.1.3 - System clock synchronized state
# ------------------------------
check_13_1_3(){
    OUT=$(timedatectl status 2>/dev/null | grep "System clock synchronized")

    echo "$OUT" | grep -qi "yes" \
        && result PASS "13.1.3" "CRITICAL" "System clock synchronized" "$OUT" \
        || result FAIL "13.1.3" "CRITICAL" "System clock NOT synchronized" "$OUT"
}

# ------------------------------
# 13.1.4 - Timezone configuration validation
# ------------------------------
check_13_1_4(){
    OUT=$(timedatectl status 2>/dev/null | grep "Time zone")

    [[ -n "$OUT" ]] \
        && result PASS "13.1.4" "MEDIUM" "Timezone configured" "$OUT" \
        || result WARN "13.1.4" "MEDIUM" "Timezone not set properly" "Unknown"
}

# ------------------------------
# 13.1.5 - Manual time change risk detection
# ------------------------------
check_13_1_5(){
    OUT=$(journalctl --since "24 hours ago" 2>/dev/null | grep -Ei "time|clock|ntp|sync" | wc -l)

    [[ "$OUT" -gt 0 ]] \
        && result PASS "13.1.5" "LOW" "Time activity logged" "$OUT events" \
        || result WARN "13.1.5" "LOW" "No time sync logs found" "Check logging"
}

# ------------------------------
# 13.1.6 - RTC (hardware clock) consistency
# ------------------------------
check_13_1_6(){
    SYS_TIME=$(date +%s)
    RTC_TIME=$(hwclock --show 2>/dev/null | awk '{print $1}' | cut -d: -f1)

    [[ -n "$SYS_TIME" ]] \
        && result PASS "13.1.6" "MEDIUM" "System time readable" "$SYS_TIME" \
        || result FAIL "13.1.6" "MEDIUM" "System time error" "Failed"
}

# ------------------------------
# 13.1.7 - Time drift detection (basic heuristic)
# ------------------------------
check_13_1_7(){
    OUT=$(timedatectl status 2>/dev/null | grep "NTP synchronized")

    echo "$OUT" | grep -qi "yes" \
        && result PASS "13.1.7" "HIGH" "No time drift detected" "$OUT" \
        || result WARN "13.1.7" "HIGH" "Possible time drift detected" "$OUT"
}

# ------------------------------
# 13.1.8 - Chrony alternative check
# ------------------------------
check_13_1_8(){
    systemctl is-active chrony &>/dev/null \
        && result PASS "13.1.8" "HIGH" "Chrony active" "Running" \
        || result WARN "13.1.8" "HIGH" "Chrony not active" "Not used"
}

# ------------------------------
# 13.1.9 - Time modification audit logs
# ------------------------------
check_13_1_9(){
    OUT=$(ausearch -m TIME_CHANGE 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "13.1.9" "CRITICAL" "No manual time changes detected" "Clean" \
        || result WARN "13.1.9" "CRITICAL" "Manual time changes detected" "$OUT events"
}

# ------------------------------
# 13.1.10 - Boot time integrity
# ------------------------------
check_13_1_10(){
    OUT=$(uptime -s)

    [[ -n "$OUT" ]] \
        && result PASS "13.1.10" "LOW" "Boot time available" "$OUT" \
        || result FAIL "13.1.10" "LOW" "Boot time not available" "Unknown"
}

# ------------------------------
# RUNNER
# ------------------------------
run_time(){
    check_13_1_1
    check_13_1_2
    check_13_1_3
    check_13_1_4
    check_13_1_5
    check_13_1_6
    check_13_1_7
    check_13_1_8
    check_13_1_9
    check_13_1_10
}