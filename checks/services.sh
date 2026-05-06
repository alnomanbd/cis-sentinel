#!/bin/bash

# ============================================================
# CIS SERVICES & ATTACK SURFACE MODULE
# Ubuntu 22.04 / 24.04 (SOC / Enterprise Ready)
# ============================================================

source engine/core.sh

# ------------------------------
# 2.1.1 - Avahi service check
# ------------------------------
check_2_1_1(){
    systemctl is-enabled avahi-daemon &>/dev/null \
        && result FAIL "2.1.1" "MEDIUM" "Avahi enabled (unnecessary)" "Enabled" \
        || result PASS "2.1.1" "MEDIUM" "Avahi disabled" "Safe"
}

# ------------------------------
# 2.1.2 - CUPS printing service
# ------------------------------
check_2_1_2(){
    systemctl is-enabled cups &>/dev/null \
        && result WARN "2.1.2" "MEDIUM" "CUPS enabled" "Enabled" \
        || result PASS "2.1.2" "MEDIUM" "CUPS disabled" "Safe"
}

# ------------------------------
# 2.1.3 - DHCP server service
# ------------------------------
check_2_1_3(){
    systemctl is-enabled isc-dhcp-server &>/dev/null \
        && result FAIL "2.1.3" "HIGH" "DHCP server enabled" "Enabled" \
        || result PASS "2.1.3" "HIGH" "DHCP server not enabled" "Safe"
}

# ------------------------------
# 2.1.4 - FTP service check
# ------------------------------
check_2_1_4(){
    systemctl is-enabled vsftpd &>/dev/null \
        && result FAIL "2.1.4" "CRITICAL" "FTP enabled (insecure)" "Enabled" \
        || result PASS "2.1.4" "CRITICAL" "FTP not enabled" "Safe"
}

# ------------------------------
# 2.1.5 - Telnet service check
# ------------------------------
check_2_1_5(){
    systemctl is-enabled telnet &>/dev/null \
        && result FAIL "2.1.5" "CRITICAL" "Telnet enabled (insecure)" "Enabled" \
        || result PASS "2.1.5" "CRITICAL" "Telnet not enabled" "Safe"
}

# ------------------------------
# 2.1.6 - SSH service status
# ------------------------------
check_2_1_6(){
    systemctl is-active ssh &>/dev/null \
        && result PASS "2.1.6" "HIGH" "SSH active" "Running" \
        || result FAIL "2.1.6" "HIGH" "SSH not running" "Stopped"
}

# ------------------------------
# 2.1.7 - RPC services check
# ------------------------------
check_2_1_7(){
    systemctl is-active rpcbind &>/dev/null \
        && result FAIL "2.1.7" "HIGH" "RPC service active" "Running" \
        || result PASS "2.1.7" "HIGH" "RPC service disabled" "Safe"
}

# ------------------------------
# 2.1.8 - NFS service check
# ------------------------------
check_2_1_8(){
    systemctl is-active nfs-server &>/dev/null \
        && result WARN "2.1.8" "HIGH" "NFS server active" "Running" \
        || result PASS "2.1.8" "HIGH" "NFS not active" "Safe"
}

# ------------------------------
# 2.1.9 - Apache web server check
# ------------------------------
check_2_1_9(){
    systemctl is-active apache2 &>/dev/null \
        && result WARN "2.1.9" "MEDIUM" "Apache active" "Running" \
        || result PASS "2.1.9" "MEDIUM" "Apache not active" "Safe"
}

# ------------------------------
# 2.1.10 - Nginx web server check
# ------------------------------
check_2_1_10(){
    systemctl is-active nginx &>/dev/null \
        && result WARN "2.1.10" "MEDIUM" "Nginx active" "Running" \
        || result PASS "2.1.10" "MEDIUM" "Nginx not active" "Safe"
}

# ------------------------------
# 2.1.11 - Database services exposure (MySQL)
# ------------------------------
check_2_1_11(){
    systemctl is-active mysql &>/dev/null \
        && result WARN "2.1.11" "CRITICAL" "MySQL active" "Running" \
        || result PASS "2.1.11" "CRITICAL" "MySQL not active" "Safe"
}

# ------------------------------
# 2.1.12 - PostgreSQL service check
# ------------------------------
check_2_1_12(){
    systemctl is-active postgresql &>/dev/null \
        && result WARN "2.1.12" "CRITICAL" "PostgreSQL active" "Running" \
        || result PASS "2.1.12" "CRITICAL" "PostgreSQL not active" "Safe"
}

# ------------------------------
# 2.1.13 - Docker daemon exposure
# ------------------------------
check_2_1_13(){
    systemctl is-active docker &>/dev/null \
        && result WARN "2.1.13" "HIGH" "Docker daemon active" "Running" \
        || result PASS "2.1.13" "HIGH" "Docker not active" "Safe"
}

# ------------------------------
# 2.1.14 - Redis service check
# ------------------------------
check_2_1_14(){
    systemctl is-active redis &>/dev/null \
        && result WARN "2.1.14" "MEDIUM" "Redis active" "Running" \
        || result PASS "2.1.14" "MEDIUM" "Redis not active" "Safe"
}

# ------------------------------
# 2.1.15 - Unnecessary remote services detection
# ------------------------------
check_2_1_15(){
    OUT=$(ss -tulnp | grep -E "telnet|ftp|rpc" | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "2.1.15" "CRITICAL" "No insecure remote services" "Clean" \
        || result FAIL "2.1.15" "CRITICAL" "Insecure services detected" "$OUT services"
}

# ------------------------------
# RUNNER
# ------------------------------
run_services(){
    check_2_1_1
    check_2_1_2
    check_2_1_3
    check_2_1_4
    check_2_1_5
    check_2_1_6
    check_2_1_7
    check_2_1_8
    check_2_1_9
    check_2_1_10
    check_2_1_11
    check_2_1_12
    check_2_1_13
    check_2_1_14
    check_2_1_15
}