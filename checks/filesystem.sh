#!/bin/bash

# ============================================================
# CIS FILESYSTEM SECURITY MODULE (Ubuntu 22.04/24.04)
# ============================================================

# Load engine
source engine/core.sh

# ------------------------------
# 1.1.1 - Separate partition for /tmp
# ------------------------------
check_1_1_1(){
    OUT=$(findmnt -n /tmp 2>/dev/null)

    [[ -n "$OUT" ]] \
        && result PASS "1.1.1" "HIGH" "/tmp partition exists" "$OUT" \
        || result WARN "1.1.1" "HIGH" "/tmp not separate partition" "Not found"
}

# ------------------------------
# 1.1.2 - nodev on /tmp
# ------------------------------
check_1_1_2(){
    OUT=$(findmnt -n /tmp 2>/dev/null)

    echo "$OUT" | grep -q nodev \
        && result PASS "1.1.2" "HIGH" "nodev set on /tmp" "$OUT" \
        || result FAIL "1.1.2" "HIGH" "nodev missing on /tmp" "$OUT"
}

# ------------------------------
# 1.1.3 - nosuid on /tmp
# ------------------------------
check_1_1_3(){
    OUT=$(findmnt -n /tmp 2>/dev/null)

    echo "$OUT" | grep -q nosuid \
        && result PASS "1.1.3" "HIGH" "nosuid set on /tmp" "$OUT" \
        || result FAIL "1.1.3" "HIGH" "nosuid missing on /tmp" "$OUT"
}

# ------------------------------
# 1.1.4 - noexec on /tmp
# ------------------------------
check_1_1_4(){
    OUT=$(findmnt -n /tmp 2>/dev/null)

    echo "$OUT" | grep -q noexec \
        && result PASS "1.1.4" "HIGH" "noexec set on /tmp" "$OUT" \
        || result FAIL "1.1.4" "HIGH" "noexec missing on /tmp" "$OUT"
}

# ------------------------------
# 1.1.5 - /var separate partition
# ------------------------------
check_1_1_5(){
    OUT=$(findmnt -n /var 2>/dev/null)

    [[ -n "$OUT" ]] \
        && result PASS "1.1.5" "HIGH" "/var partition exists" "$OUT" \
        || result WARN "1.1.5" "HIGH" "/var not separate partition" "Not found"
}

# ------------------------------
# 1.1.6 - /home separate partition
# ------------------------------
check_1_1_6(){
    OUT=$(findmnt -n /home 2>/dev/null)

    [[ -n "$OUT" ]] \
        && result PASS "1.1.6" "MEDIUM" "/home partition exists" "$OUT" \
        || result WARN "1.1.6" "MEDIUM" "/home not separate partition" "Not found"
}

# ------------------------------
# 1.1.7 - /var/log separate partition
# ------------------------------
check_1_1_7(){
    OUT=$(findmnt -n /var/log 2>/dev/null)

    [[ -n "$OUT" ]] \
        && result PASS "1.1.7" "HIGH" "/var/log partition exists" "$OUT" \
        || result WARN "1.1.7" "HIGH" "/var/log not separate partition" "Not found"
}

# ------------------------------
# 1.1.8 - /var/log/audit separate partition
# ------------------------------
check_1_1_8(){
    OUT=$(findmnt -n /var/log/audit 2>/dev/null)

    [[ -n "$OUT" ]] \
        && result PASS "1.1.8" "HIGH" "/var/log/audit partition exists" "$OUT" \
        || result WARN "1.1.8" "HIGH" "/var/log/audit not separate partition" "Not found"
}

# ------------------------------
# 1.1.9 - sticky bit on /tmp
# ------------------------------
check_1_1_9(){
    OUT=$(stat -c "%a %n" /tmp 2>/dev/null)

    echo "$OUT" | grep -q "1777" \
        && result PASS "1.1.9" "HIGH" "Sticky bit set on /tmp" "$OUT" \
        || result FAIL "1.1.9" "HIGH" "Sticky bit missing on /tmp" "$OUT"
}

# ------------------------------
# 1.1.10 - world writable files
# ------------------------------
check_1_1_10(){
    OUT=$(find / -xdev -type f -perm -0002 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "1.1.10" "MEDIUM" "No world-writable files" "Clean" \
        || result WARN "1.1.10" "MEDIUM" "World-writable files found" "$OUT files"
}

# ------------------------------
# 1.1.11 - unowned files
# ------------------------------
check_1_1_11(){
    OUT=$(find / -xdev -nouser 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "1.1.11" "HIGH" "No unowned files" "Clean" \
        || result WARN "1.1.11" "HIGH" "Unowned files found" "$OUT files"
}

# ------------------------------
# 1.1.12 - ungrouped files
# ------------------------------
check_1_1_12(){
    OUT=$(find / -xdev -nogroup 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "1.1.12" "HIGH" "No ungrouped files" "Clean" \
        || result WARN "1.1.12" "HIGH" "Ungrouped files found" "$OUT files"
}

# ============================================================
# RUNNER FUNCTION
# ============================================================

run_filesystem(){
    check_1_1_1
    check_1_1_2
    check_1_1_3
    check_1_1_4
    check_1_1_5
    check_1_1_6
    check_1_1_7
    check_1_1_8
    check_1_1_9
    check_1_1_10
    check_1_1_11
    check_1_1_12
}