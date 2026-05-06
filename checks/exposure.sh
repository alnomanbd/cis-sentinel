#!/bin/bash

# ============================================================
# CIS EXPOSURE / ATTACK SURFACE MODULE
# Ubuntu 22.04 / 24.04 (SOC / Enterprise Ready)
# ============================================================

source engine/core.sh

# ------------------------------
# 10.1.1 - Listening ports baseline
# ------------------------------
check_10_1_1(){
    OUT=$(ss -tuln 2>/dev/null | wc -l)

    [[ "$OUT" -lt 100 ]] \
        && result PASS "10.1.1" "MEDIUM" "Normal number of listening ports" "$OUT ports" \
        || result WARN "10.1.1" "MEDIUM" "High number of listening ports" "$OUT ports"
}

# ------------------------------
# 10.1.2 - Public binding services (0.0.0.0)
# ------------------------------
check_10_1_2(){
    OUT=$(ss -tuln | grep "0.0.0.0" 2>/dev/null | wc -l)

    [[ "$OUT" -lt 5 ]] \
        && result PASS "10.1.2" "HIGH" "Limited public bindings" "$OUT services" \
        || result WARN "10.1.2" "HIGH" "Multiple services bound to public interface" "$OUT services"
}

# ------------------------------
# 10.1.3 - High-risk ports detection (Telnet, FTP, SSH alt)
# ------------------------------
check_10_1_3(){
    OUT=$(ss -tuln | grep -E ":21|:23|:3389" 2>/dev/null)

    [[ -z "$OUT" ]] \
        && result PASS "10.1.3" "CRITICAL" "No high-risk ports exposed" "Clean" \
        || result FAIL "10.1.3" "CRITICAL" "High-risk ports exposed" "$OUT"
}

# ------------------------------
# 10.1.4 - Docker exposed socket detection
# ------------------------------
check_10_1_4(){
    [[ -S /var/run/docker.sock ]] \
        && result WARN "10.1.4" "CRITICAL" "Docker socket exposed" "/var/run/docker.sock exists" \
        || result PASS "10.1.4" "CRITICAL" "Docker socket not exposed" "Secure"
}

# ------------------------------
# 10.1.5 - SSH exposed to all interfaces
# ------------------------------
check_10_1_5(){
    OUT=$(ss -tuln | grep ":22" | grep "0.0.0.0")

    [[ -z "$OUT" ]] \
        && result PASS "10.1.5" "MEDIUM" "SSH not exposed publicly" "Restricted" \
        || result WARN "10.1.5" "MEDIUM" "SSH exposed to all interfaces" "$OUT"
}

# ------------------------------
# 10.1.6 - Web server exposure check (HTTP/HTTPS)
# ------------------------------
check_10_1_6(){
    OUT=$(ss -tuln | grep -E ":80|:443")

    [[ -n "$OUT" ]] \
        && result WARN "10.1.6" "MEDIUM" "Web services exposed" "$OUT" \
        || result PASS "10.1.6" "MEDIUM" "No web exposure detected" "Clean"
}

# ------------------------------
# 10.1.7 - Database exposure detection (MySQL/Postgres)
# ------------------------------
check_10_1_7(){
    OUT=$(ss -tuln | grep -E ":3306|:5432")

    [[ -z "$OUT" ]] \
        && result PASS "10.1.7" "CRITICAL" "No DB exposure detected" "Secure" \
        || result FAIL "10.1.7" "CRITICAL" "Database exposed to network" "$OUT"
}

# ------------------------------
# 10.1.8 - Cloud metadata exposure (basic check)
# ------------------------------
check_10_1_8(){
    ping -c1 169.254.169.254 &>/dev/null

    [[ $? -ne 0 ]] \
        && result PASS "10.1.8" "HIGH" "Cloud metadata blocked/unreachable" "Safe" \
        || result WARN "10.1.8" "HIGH" "Metadata endpoint reachable" "Risk possible"
}

# ------------------------------
# 10.1.9 - Suspicious listening processes
# ------------------------------
check_10_1_9(){
    OUT=$(ss -tulnp 2>/dev/null | grep -E "nc|netcat|python|perl|bash" | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "10.1.9" "CRITICAL" "No suspicious listeners" "Clean" \
        || result FAIL "10.1.9" "CRITICAL" "Suspicious listeners detected" "$OUT processes"
}

# ------------------------------
# 10.1.10 - External interface detection
# ------------------------------
check_10_1_10(){
    OUT=$(ip route | grep default)

    [[ -n "$OUT" ]] \
        && result PASS "10.1.10" "LOW" "Network route configured" "$OUT" \
        || result WARN "10.1.10" "LOW" "No default route detected" "Check network"
}

# ------------------------------
# RUNNER
# ------------------------------
run_exposure(){
    check_10_1_1
    check_10_1_2
    check_10_1_3
    check_10_1_4
    check_10_1_5
    check_10_1_6
    check_10_1_7
    check_10_1_8
    check_10_1_9
    check_10_1_10
}