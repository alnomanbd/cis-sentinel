#!/bin/bash

# ============================================================
# CIS NETWORK SECURITY MODULE (Ubuntu 22.04/24.04)
# ============================================================

source engine/core.sh

# ------------------------------
# 3.1.1 - IP forwarding disabled
# ------------------------------
check_3_1_1(){
    OUT=$(sysctl net.ipv4.ip_forward 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "3.1.1" "HIGH" "IPv4 forwarding disabled" "$OUT" \
        || result FAIL "3.1.1" "HIGH" "IPv4 forwarding enabled" "$OUT"
}

# ------------------------------
# 3.1.2 - IPv6 forwarding disabled
# ------------------------------
check_3_1_2(){
    OUT=$(sysctl net.ipv6.conf.all.forwarding 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "3.1.2" "HIGH" "IPv6 forwarding disabled" "$OUT" \
        || result FAIL "3.1.2" "HIGH" "IPv6 forwarding enabled" "$OUT"
}

# ------------------------------
# 3.2.1 - ICMP redirects disabled
# ------------------------------
check_3_2_1(){
    OUT=$(sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "3.2.1" "HIGH" "ICMP redirects disabled" "$OUT" \
        || result FAIL "3.2.1" "HIGH" "ICMP redirects enabled" "$OUT"
}

# ------------------------------
# 3.2.2 - Secure ICMP redirects disabled
# ------------------------------
check_3_2_2(){
    OUT=$(sysctl net.ipv4.conf.all.secure_redirects 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "3.2.2" "HIGH" "Secure redirects disabled" "$OUT" \
        || result WARN "3.2.2" "HIGH" "Secure redirects enabled" "$OUT"
}

# ------------------------------
# 3.2.3 - Source routed packets disabled
# ------------------------------
check_3_2_3(){
    OUT=$(sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "3.2.3" "HIGH" "Source routing disabled" "$OUT" \
        || result FAIL "3.2.3" "HIGH" "Source routing enabled" "$OUT"
}

# ------------------------------
# 3.2.4 - RP Filter enabled
# ------------------------------
check_3_2_4(){
    OUT=$(sysctl net.ipv4.conf.all.rp_filter 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "3.2.4" "HIGH" "RP filter enabled" "$OUT" \
        || result WARN "3.2.4" "HIGH" "RP filter disabled" "$OUT"
}

# ------------------------------
# 3.2.5 - TCP SYN cookies enabled
# ------------------------------
check_3_2_5(){
    OUT=$(sysctl net.ipv4.tcp_syncookies 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "3.2.5" "HIGH" "SYN cookies enabled" "$OUT" \
        || result FAIL "3.2.5" "HIGH" "SYN cookies disabled" "$OUT"
}

# ------------------------------
# 3.3.1 - ICMP broadcast ignore
# ------------------------------
check_3_3_1(){
    OUT=$(sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "3.3.1" "MEDIUM" "Broadcast ICMP ignored" "$OUT" \
        || result WARN "3.3.1" "MEDIUM" "Broadcast ICMP allowed" "$OUT"
}

# ------------------------------
# 3.3.2 - Bad error message protection
# ------------------------------
check_3_3_2(){
    OUT=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "3.3.2" "MEDIUM" "Bogus ICMP ignored" "$OUT" \
        || result WARN "3.3.2" "MEDIUM" "Bogus ICMP not ignored" "$OUT"
}

# ------------------------------
# 3.4.1 - Reverse path filtering (all interfaces)
# ------------------------------
check_3_4_1(){
    OUT=$(sysctl net.ipv4.conf.default.rp_filter 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "3.4.1" "HIGH" "Default RP filter enabled" "$OUT" \
        || result WARN "3.4.1" "HIGH" "Default RP filter disabled" "$OUT"
}

# ------------------------------
# 3.5.1 - Open listening ports baseline
# ------------------------------
check_3_5_1(){
    OUT=$(ss -tuln 2>/dev/null | wc -l)

    [[ "$OUT" -lt 100 ]] \
        && result PASS "3.5.1" "MEDIUM" "Reasonable open ports" "$OUT ports" \
        || result WARN "3.5.1" "MEDIUM" "High number of open ports" "$OUT ports"
}

# ------------------------------
# 3.5.2 - Suspicious listening services
# ------------------------------
check_3_5_2(){
    OUT=$(ss -tulnp 2>/dev/null | grep -E "nc|netcat|python|perl" | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "3.5.2" "HIGH" "No suspicious listeners" "Clean" \
        || result WARN "3.5.2" "HIGH" "Suspicious listeners detected" "$OUT found"
}

# ------------------------------
# 3.5.3 - Promiscuous mode detection
# ------------------------------
check_3_5_3(){
    OUT=$(ip link | grep PROMISC)

    [[ -z "$OUT" ]] \
        && result PASS "3.5.3" "HIGH" "No promiscuous interfaces" "Clean" \
        || result FAIL "3.5.3" "HIGH" "Promiscuous mode detected" "$OUT"
}

# ============================================================
# RUNNER
# ============================================================

run_network(){
    check_3_1_1
    check_3_1_2
    check_3_2_1
    check_3_2_2
    check_3_2_3
    check_3_2_4
    check_3_2_5
    check_3_3_1
    check_3_3_2
    check_3_4_1
    check_3_5_1
    check_3_5_2
    check_3_5_3
}