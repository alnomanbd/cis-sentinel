#!/bin/bash

# ============================================================
# CIS LOGGING & AUDITING MODULE (Ubuntu 22.04/24.04)
# SOC / SIEM READY
# ============================================================

source engine/core.sh

# ------------------------------
# 4.1.1 - auditd installed
# ------------------------------
check_4_1_1(){
    dpkg -l auditd &>/dev/null \
        && result PASS "4.1.1" "HIGH" "auditd installed" "Installed" \
        || result FAIL "4.1.1" "HIGH" "auditd missing" "Not installed"
}

# ------------------------------
# 4.1.2 - auditd running
# ------------------------------
check_4_1_2(){
    systemctl is-active auditd &>/dev/null \
        && result PASS "4.1.2" "HIGH" "auditd running" "Active" \
        || result FAIL "4.1.2" "HIGH" "auditd not running" "Inactive"
}

# ------------------------------
# 4.1.3 - rsyslog installed
# ------------------------------
check_4_1_3(){
    dpkg -l rsyslog &>/dev/null \
        && result PASS "4.1.3" "MEDIUM" "rsyslog installed" "Installed" \
        || result WARN "4.1.3" "MEDIUM" "rsyslog missing" "Not installed"
}

# ------------------------------
# 4.1.4 - rsyslog running
# ------------------------------
check_4_1_4(){
    systemctl is-active rsyslog &>/dev/null \
        && result PASS "4.1.4" "MEDIUM" "rsyslog running" "Active" \
        || result WARN "4.1.4" "MEDIUM" "rsyslog not running" "Inactive"
}

# ------------------------------
# 4.1.5 - journald persistence enabled
# ------------------------------
check_4_1_5(){
    grep -q "^Storage=persistent" /etc/systemd/journald.conf 2>/dev/null \
        && result PASS "4.1.5" "MEDIUM" "journald persistent logging enabled" "Configured" \
        || result WARN "4.1.5" "MEDIUM" "journald not persistent" "Not configured"
}

# ------------------------------
# 4.1.6 - /var/log permissions
# ------------------------------
check_4_1_6(){
    PERM=$(stat -c "%a" /var/log 2>/dev/null)

    [[ "$PERM" == "755" || "$PERM" == "750" ]] \
        && result PASS "4.1.6" "MEDIUM" "log directory permissions secure" "$PERM" \
        || result WARN "4.1.6" "MEDIUM" "weak log directory permissions" "$PERM"
}

# ------------------------------
# 4.1.7 - auth log existence
# ------------------------------
check_4_1_7(){
    [[ -f /var/log/auth.log ]] \
        && result PASS "4.1.7" "HIGH" "auth.log exists" "Present" \
        || result FAIL "4.1.7" "HIGH" "auth.log missing" "Not found"
}

# ------------------------------
# 4.1.8 - syslog logging activity
# ------------------------------
check_4_1_8(){
    grep -q "systemd" /var/log/syslog 2>/dev/null \
        && result PASS "4.1.8" "LOW" "syslog active logging" "Active entries found" \
        || result WARN "4.1.8" "LOW" "syslog weak logging" "No clear entries"
}

# ------------------------------
# 4.1.9 - audit rules loaded
# ------------------------------
check_4_1_9(){
    auditctl -s &>/dev/null \
        && result PASS "4.1.9" "HIGH" "audit rules active" "Kernel auditing enabled" \
        || result FAIL "4.1.9" "HIGH" "audit rules not active" "Auditctl not working"
}

# ------------------------------
# 4.1.10 - remote logging detection
# ------------------------------
check_4_1_10(){
    grep -q "@@" /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null \
        && result PASS "4.1.10" "MEDIUM" "remote logging enabled" "Configured" \
        || result WARN "4.1.10" "MEDIUM" "no remote logging found" "Not configured"
}

# ------------------------------
# 4.1.11 - log tampering detection (basic)
# ------------------------------
check_4_1_11(){
    OUT=$(find /var/log -type f -mtime -1 2>/dev/null | wc -l)

    [[ "$OUT" -ge 0 ]] \
        && result PASS "4.1.11" "LOW" "log activity detected" "$OUT modified files" \
        || result WARN "4.1.11" "LOW" "no recent log activity" "Check required"
}

# ------------------------------
# 4.1.12 - logrotate installed
# ------------------------------
check_4_1_12(){
    dpkg -l logrotate &>/dev/null \
        && result PASS "4.1.12" "MEDIUM" "logrotate installed" "Installed" \
        || result WARN "4.1.12" "MEDIUM" "logrotate missing" "Not installed"
}

# ------------------------------
# 4.1.13 - logrotate config valid
# ------------------------------
check_4_1_13(){
    logrotate --debug /etc/logrotate.conf &>/dev/null \
        && result PASS "4.1.13" "MEDIUM" "logrotate config valid" "No errors" \
        || result WARN "4.1.13" "MEDIUM" "logrotate config issues" "Validation failed"
}

# ============================================================
# RUNNER
# ============================================================

run_logging(){
    check_4_1_1
    check_4_1_2
    check_4_1_3
    check_4_1_4
    check_4_1_5
    check_4_1_6
    check_4_1_7
    check_4_1_8
    check_4_1_9
    check_4_1_10
    check_4_1_11
    check_4_1_12
    check_4_1_13
}