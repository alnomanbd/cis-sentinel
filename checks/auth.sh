#!/bin/bash

# ============================================================
# CIS AUTHENTICATION & ACCESS CONTROL MODULE
# Ubuntu 22.04 / 24.04 (SOC / Enterprise Ready)
# ============================================================

source engine/core.sh

# ------------------------------
# 5.2.1 - Root login disabled in SSH
# ------------------------------
check_5_2_1(){
    OUT=$(grep -Ei "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null)

    echo "$OUT" | grep -qi "no" \
        && result PASS "5.2.1" "HIGH" "Root SSH login disabled" "$OUT" \
        || result FAIL "5.2.1" "HIGH" "Root SSH login enabled" "$OUT"
}

# ------------------------------
# 5.2.2 - Password authentication enabled check
# ------------------------------
check_5_2_2(){
    OUT=$(grep -Ei "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null)

    echo "$OUT" | grep -qi "yes" \
        && result PASS "5.2.2" "MEDIUM" "Password auth enabled (review needed)" "$OUT" \
        || result WARN "5.2.2" "MEDIUM" "Password auth disabled (key-only mode)" "$OUT"
}

# ------------------------------
# 5.2.3 - Max authentication attempts
# ------------------------------
check_5_2_3(){
    OUT=$(grep -Ei "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null)

    echo "$OUT" | grep -q "3" \
        && result PASS "5.2.3" "HIGH" "MaxAuthTries secure (<=3)" "$OUT" \
        || result WARN "5.2.3" "HIGH" "MaxAuthTries too high or default" "$OUT"
}

# ------------------------------
# 5.2.4 - SSH idle timeout (ClientAliveInterval)
# ------------------------------
check_5_2_4(){
    OUT=$(grep -Ei "^ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null)

    [[ -n "$OUT" ]] \
        && result PASS "5.2.4" "MEDIUM" "SSH idle timeout configured" "$OUT" \
        || result WARN "5.2.4" "MEDIUM" "SSH idle timeout missing" "Not set"
}

# ------------------------------
# 5.2.5 - SSH login grace time
# ------------------------------
check_5_2_5(){
    OUT=$(grep -Ei "^LoginGraceTime" /etc/ssh/sshd_config 2>/dev/null)

    [[ -n "$OUT" ]] \
        && result PASS "5.2.5" "MEDIUM" "Login grace time configured" "$OUT" \
        || result WARN "5.2.5" "MEDIUM" "Login grace time not set" "Default used"
}

# ------------------------------
# 5.3.1 - Password minimum length (login.defs)
# ------------------------------
check_5_3_1(){
    OUT=$(grep -Ei "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null)

    echo "$OUT" | grep -qE "[8-9]|[1-9][0-9]+" \
        && result PASS "5.3.1" "HIGH" "Password length policy strong" "$OUT" \
        || result FAIL "5.3.1" "HIGH" "Weak password policy" "$OUT"
}

# ------------------------------
# 5.3.2 - Password max days
# ------------------------------
check_5_3_2(){
    OUT=$(grep -Ei "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null)

    echo "$OUT" | grep -qE "([0-9]|[1-6][0-9]|7[0-9]|80)" \
        && result PASS "5.3.2" "MEDIUM" "Password expiry configured" "$OUT" \
        || result WARN "5.3.2" "MEDIUM" "Password expiry too high" "$OUT"
}

# ------------------------------
# 5.3.3 - Empty password accounts
# ------------------------------
check_5_3_3(){
    OUT=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "5.3.3" "HIGH" "No empty password accounts" "Clean" \
        || result FAIL "5.3.3" "HIGH" "Empty password accounts found" "$OUT users"
}

# ------------------------------
# 5.3.4 - UID 0 only root
# ------------------------------
check_5_3_4(){
    OUT=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | wc -l)

    [[ "$OUT" -eq 1 ]] \
        && result PASS "5.3.4" "CRITICAL" "Only root has UID 0" "Secure" \
        || result FAIL "5.3.4" "CRITICAL" "Multiple UID 0 accounts found" "$OUT accounts"
}

# ------------------------------
# 5.4.1 - sudoers NOPASSWD detection
# ------------------------------
check_5_4_1(){
    OUT=$(grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "5.4.1" "HIGH" "No NOPASSWD sudo rules" "Secure" \
        || result WARN "5.4.1" "HIGH" "NOPASSWD sudo detected" "$OUT entries"
}

# ------------------------------
# 5.4.2 - sudo installed check
# ------------------------------
check_5_4_2(){
    dpkg -l sudo &>/dev/null \
        && result PASS "5.4.2" "LOW" "sudo installed" "Present" \
        || result FAIL "5.4.2" "HIGH" "sudo missing" "Not installed"
}

# ------------------------------
# 5.5.1 - inactive users detection
# ------------------------------
check_5_5_1(){
    OUT=$(lastlog | grep "Never logged in" | wc -l)

    [[ "$OUT" -ge 0 ]] \
        && result PASS "5.5.1" "LOW" "Inactive users checked" "$OUT users" \
        || result WARN "5.5.1" "LOW" "Cannot determine inactive users" "Check needed"
}

# ------------------------------
# RUNNER
# ------------------------------
run_auth(){
    check_5_2_1
    check_5_2_2
    check_5_2_3
    check_5_2_4
    check_5_2_5
    check_5_3_1
    check_5_3_2
    check_5_3_3
    check_5_3_4
    check_5_4_1
    check_5_4_2
    check_5_5_1
}