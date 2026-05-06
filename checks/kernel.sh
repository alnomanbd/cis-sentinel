#!/bin/bash

# ============================================================
# CIS KERNEL SECURITY MODULE (Ubuntu 22.04/24.04)
# SOC / Enterprise Ready
# ============================================================

source engine/core.sh

# ------------------------------
# 7.1.1 - ASLR enabled
# ------------------------------
check_7_1_1(){
    OUT=$(sysctl kernel.randomize_va_space 2>/dev/null)

    echo "$OUT" | grep -q "= 2" \
        && result PASS "7.1.1" "HIGH" "ASLR fully enabled" "$OUT" \
        || result FAIL "7.1.1" "HIGH" "ASLR not fully enabled" "$OUT"
}

# ------------------------------
# 7.1.2 - Core dumps disabled
# ------------------------------
check_7_1_2(){
    OUT=$(sysctl fs.suid_dumpable 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "7.1.2" "HIGH" "Core dumps disabled" "$OUT" \
        || result WARN "7.1.2" "HIGH" "Core dumps enabled" "$OUT"
}

# ------------------------------
# 7.1.3 - Kernel pointer restriction
# ------------------------------
check_7_1_3(){
    OUT=$(sysctl kernel.kptr_restrict 2>/dev/null)

    echo "$OUT" | grep -qE "= 1|= 2" \
        && result PASS "7.1.3" "HIGH" "Kernel pointers restricted" "$OUT" \
        || result FAIL "7.1.3" "HIGH" "Kernel pointers exposed" "$OUT"
}

# ------------------------------
# 7.1.4 - dmesg restriction
# ------------------------------
check_7_1_4(){
    OUT=$(sysctl kernel.dmesg_restrict 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "7.1.4" "HIGH" "dmesg restricted" "$OUT" \
        || result FAIL "7.1.4" "HIGH" "dmesg exposed" "$OUT"
}

# ------------------------------
# 7.1.5 - Kernel module loading restricted
# ------------------------------
check_7_1_5(){
    OUT=$(sysctl kernel.modules_disabled 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "7.1.5" "CRITICAL" "Kernel modules locked" "$OUT" \
        || result WARN "7.1.5" "CRITICAL" "Kernel modules still loadable" "$OUT"
}

# ------------------------------
# 7.1.6 - IP spoofing protection (rp_filter default)
# ------------------------------
check_7_1_6(){
    OUT=$(sysctl net.ipv4.conf.all.rp_filter 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "7.1.6" "HIGH" "Reverse path filtering enabled" "$OUT" \
        || result FAIL "7.1.6" "HIGH" "RP filter disabled" "$OUT"
}

# ------------------------------
# 7.1.7 - Secure sysctl redirects
# ------------------------------
check_7_1_7(){
    OUT=$(sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "7.1.7" "HIGH" "ICMP redirects disabled" "$OUT" \
        || result FAIL "7.1.7" "HIGH" "ICMP redirects enabled" "$OUT"
}

# ------------------------------
# 7.1.8 - Source routing disabled
# ------------------------------
check_7_1_8(){
    OUT=$(sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null)

    echo "$OUT" | grep -q "= 0" \
        && result PASS "7.1.8" "HIGH" "Source routing disabled" "$OUT" \
        || result FAIL "7.1.8" "HIGH" "Source routing enabled" "$OUT"
}

# ------------------------------
# 7.1.9 - SYN cookies enabled
# ------------------------------
check_7.1_9(){
    OUT=$(sysctl net.ipv4.tcp_syncookies 2>/dev/null)

    echo "$OUT" | grep -q "= 1" \
        && result PASS "7.1.9" "HIGH" "SYN cookies enabled" "$OUT" \
        || result FAIL "7.1.9" "HIGH" "SYN cookies disabled" "$OUT"
}

# ------------------------------
# 7.1.10 - Kernel tainted check
# ------------------------------
check_7_1_10(){
    OUT=$(cat /proc/sys/kernel/tainted 2>/dev/null)

    [[ "$OUT" == "0" ]] \
        && result PASS "7.1.10" "MEDIUM" "Kernel not tainted" "Clean state" \
        || result WARN "7.1.10" "MEDIUM" "Kernel tainted detected" "$OUT"
}

# ------------------------------
# 7.1.11 - Kernel version visibility
# ------------------------------
check_7_1_11(){
    OUT=$(uname -r)

    [[ -n "$OUT" ]] \
        && result PASS "7.1.11" "LOW" "Kernel version detected" "$OUT" \
        || result FAIL "7.1.11" "LOW" "Kernel version unknown" "Failed"
}

# ------------------------------
# RUNNER
# ------------------------------
run_kernel(){
    check_7_1_1
    check_7_1_2
    check_7_1_3
    check_7_1_4
    check_7_1_5
    check_7_1_6
    check_7_1_7
    check_7_1_8
    check_7.1_9
    check_7_1_10
    check_7_1_11
}