#!/bin/bash

# ============================================================
# CIS FILE INTEGRITY MONITORING MODULE (FIM)
# Ubuntu 22.04 / 24.04
# SOC / Enterprise Ready
# ============================================================

source engine/core.sh

# ------------------------------
# 8.1.1 - AIDE installed
# ------------------------------
check_8_1_1(){
    dpkg -l aide &>/dev/null \
        && result PASS "8.1.1" "HIGH" "AIDE installed" "Present" \
        || result FAIL "8.1.1" "HIGH" "AIDE not installed" "Missing"
}

# ------------------------------
# 8.1.2 - AIDE database exists
# ------------------------------
check_8_1_2(){
    [[ -f /var/lib/aide/aide.db ]] \
        && result PASS "8.1.2" "HIGH" "AIDE database exists" "Present" \
        || result WARN "8.1.2" "HIGH" "AIDE database missing" "Not initialized"
}

# ------------------------------
# 8.1.3 - /etc modification check (recent changes)
# ------------------------------
check_8_1_3(){
    OUT=$(find /etc -type f -mtime -1 2>/dev/null | wc -l)

    [[ "$OUT" -lt 50 ]] \
        && result PASS "8.1.3" "MEDIUM" "Normal config changes" "$OUT files modified" \
        || result WARN "8.1.3" "MEDIUM" "High config changes detected" "$OUT files"
}

# ------------------------------
# 8.1.4 - Critical binaries modification (/bin)
# ------------------------------
check_8_1_4(){
    OUT=$(find /bin -type f -mtime -1 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "8.1.4" "CRITICAL" "No /bin modification detected" "Clean" \
        || result FAIL "8.1.4" "CRITICAL" "Binary modification detected in /bin" "$OUT files"
}

# ------------------------------
# 8.1.5 - Critical binaries modification (/usr/bin)
# ------------------------------
check_8_1_5(){
    OUT=$(find /usr/bin -type f -mtime -1 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "8.1.5" "CRITICAL" "No /usr/bin modification detected" "Clean" \
        || result FAIL "8.1.5" "CRITICAL" "Binary modification detected in /usr/bin" "$OUT files"
}

# ------------------------------
# 8.1.6 - Suspicious file creation in /tmp
# ------------------------------
check_8_1_6(){
    OUT=$(find /tmp -type f -mtime -1 2>/dev/null | wc -l)

    [[ "$OUT" -lt 20 ]] \
        && result PASS "8.1.6" "HIGH" "Normal /tmp activity" "$OUT files" \
        || result WARN "8.1.6" "HIGH" "High activity in /tmp" "$OUT files"
}

# ------------------------------
# 8.1.7 - Hidden files in system directories
# ------------------------------
check_8_1_7(){
    OUT=$(find / -type f -name ".*" 2>/dev/null | wc -l)

    [[ "$OUT" -lt 100 ]] \
        && result PASS "8.1.7" "MEDIUM" "Normal hidden file count" "$OUT files" \
        || result WARN "8.1.7" "MEDIUM" "High hidden file count detected" "$OUT files"
}

# ------------------------------
# 8.1.8 - Unowned files detection
# ------------------------------
check_8_1_8(){
    OUT=$(find / -xdev -nouser 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "8.1.8" "HIGH" "No unowned files" "Clean" \
        || result WARN "8.1.8" "HIGH" "Unowned files detected" "$OUT files"
}

# ------------------------------
# 8.1.9 - System file permission drift (/etc/passwd)
# ------------------------------
check_8_1_9(){
    PERM=$(stat -c "%a" /etc/passwd 2>/dev/null)

    [[ "$PERM" == "644" ]] \
        && result PASS "8.1.9" "HIGH" "/etc/passwd permissions correct" "$PERM" \
        || result FAIL "8.1.9" "HIGH" "Weak permissions on /etc/passwd" "$PERM"
}

# ------------------------------
# 8.1.10 - System file permission drift (/etc/shadow)
# ------------------------------
check_8_1_10(){
    PERM=$(stat -c "%a" /etc/shadow 2>/dev/null)

    [[ "$PERM" == "640" || "$PERM" == "600" ]] \
        && result PASS "8.1.10" "CRITICAL" "/etc/shadow secure permissions" "$PERM" \
        || result FAIL "8.1.10" "CRITICAL" "Weak /etc/shadow permissions" "$PERM"
}

# ------------------------------
# RUNNER
# ------------------------------
run_fim(){
    check_8_1_1
    check_8_1_2
    check_8_1_3
    check_8_1_4
    check_8_1_5
    check_8_1_6
    check_8_1_7
    check_8_1_8
    check_8_1_9
    check_8_1_10
}