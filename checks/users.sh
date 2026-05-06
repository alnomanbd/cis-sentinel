#!/bin/bash

# ============================================================
# CIS USER & ACCOUNT SECURITY MODULE
# Ubuntu 22.04 / 24.04 (SOC / Enterprise Ready)
# ============================================================

source engine/core.sh

# ------------------------------
# 9.1.1 - UID 0 only root
# ------------------------------
check_9_1_1(){
    OUT=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null)

    COUNT=$(echo "$OUT" | wc -l)

    [[ "$COUNT" -eq 1 && "$OUT" == "root" ]] \
        && result PASS "9.1.1" "CRITICAL" "Only root has UID 0" "$OUT" \
        || result FAIL "9.1.1" "CRITICAL" "Multiple UID 0 accounts detected" "$OUT"
}

# ------------------------------
# 9.1.2 - Empty password accounts
# ------------------------------
check_9_1_2(){
    OUT=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)

    [[ -z "$OUT" ]] \
        && result PASS "9.1.2" "HIGH" "No empty password accounts" "Clean" \
        || result FAIL "9.1.2" "HIGH" "Empty password accounts found" "$OUT"
}

# ------------------------------
# 9.1.3 - Inactive users (never logged in)
# ------------------------------
check_9_1_3(){
    OUT=$(lastlog | grep "Never logged in" | wc -l)

    [[ "$OUT" -lt 10 ]] \
        && result PASS "9.1.3" "LOW" "Normal inactive users" "$OUT users" \
        || result WARN "9.1.3" "LOW" "High inactive users detected" "$OUT users"
}

# ------------------------------
# 9.1.4 - Users with UID < 1000 (non-system accounts)
# ------------------------------
check_9_1_4(){
    OUT=$(awk -F: '$3 < 1000 && $3 != 0 {print $1}' /etc/passwd)

    [[ -z "$OUT" ]] \
        && result PASS "9.1.4" "MEDIUM" "No suspicious low UID users" "Clean" \
        || result WARN "9.1.4" "MEDIUM" "Low UID non-system users detected" "$OUT"
}

# ------------------------------
# 9.1.5 - Users with login shells
# ------------------------------
check_9_1_5(){
    OUT=$(awk -F: '($7 !~ /(nologin|false)/){print $1}' /etc/passwd)

    [[ -n "$OUT" ]] \
        && result PASS "9.1.5" "LOW" "Valid login users present" "$OUT" \
        || result WARN "9.1.5" "LOW" "No valid login users detected" "Check needed"
}

# ------------------------------
# 9.1.6 - Duplicate UID detection
# ------------------------------
check_9_1_6(){
    OUT=$(cut -d: -f3 /etc/passwd | sort | uniq -d)

    [[ -z "$OUT" ]] \
        && result PASS "9.1.6" "HIGH" "No duplicate UIDs" "Clean" \
        || result FAIL "9.1.6" "HIGH" "Duplicate UID detected" "$OUT"
}

# ------------------------------
# 9.1.7 - Users with sudo access
# ------------------------------
check_9_1_7(){
    OUT=$(getent group sudo | awk -F: '{print $4}')

    [[ -n "$OUT" ]] \
        && result PASS "9.1.7" "HIGH" "Sudo users present" "$OUT" \
        || result WARN "9.1.7" "HIGH" "No sudo users found" "Check required"
}

# ------------------------------
# 9.1.8 - Root login shell check
# ------------------------------
check_9_1_8(){
    OUT=$(grep "^root" /etc/passwd | cut -d: -f7)

    [[ "$OUT" == "/bin/bash" || "$OUT" == "/bin/sh" ]] \
        && result PASS "9.1.8" "MEDIUM" "Root shell valid" "$OUT" \
        || result WARN "9.1.8" "MEDIUM" "Root shell unusual" "$OUT"
}

# ------------------------------
# 9.1.9 - Password aging enforcement
# ------------------------------
check_9_1_9(){
    OUT=$(grep PASS_MAX_DAYS /etc/login.defs)

    echo "$OUT" | grep -qE "[0-9]{1,2}" \
        && result PASS "9.1.9" "MEDIUM" "Password aging configured" "$OUT" \
        || result WARN "9.1.9" "MEDIUM" "Password aging not strict" "$OUT"
}

# ------------------------------
# 9.1.10 - Recently added users (basic heuristic)
# ------------------------------
check_9_1_10(){
    OUT=$(ls -l /home 2>/dev/null | wc -l)

    [[ "$OUT" -gt 0 ]] \
        && result PASS "9.1.10" "LOW" "User home directories present" "$OUT entries" \
        || result WARN "9.1.10" "LOW" "No user home directories found" "Check required"
}

# ------------------------------
# RUNNER
# ------------------------------
run_users(){
    check_9_1_1
    check_9_1_2
    check_9_1_3
    check_9_1_4
    check_9_1_5
    check_9_1_6
    check_9_1_7
    check_9_1_8
    check_9_1_9
    check_9_1_10
}