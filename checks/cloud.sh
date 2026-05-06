#!/bin/bash

# ============================================================
# CIS CLOUD / VIRTUALIZATION SECURITY MODULE
# Ubuntu 22.04 / 24.04 (SOC / Enterprise Ready)
# ============================================================

source engine/core.sh

# ------------------------------
# 12.1.1 - Cloud metadata endpoint accessibility
# (AWS/GCP/Azure common IP check)
# ------------------------------
check_12_1_1(){
    ping -c1 169.254.169.254 &>/dev/null

    [[ $? -ne 0 ]] \
        && result PASS "12.1.1" "HIGH" "Cloud metadata endpoint blocked/unreachable" "Safe" \
        || result WARN "12.1.1" "HIGH" "Cloud metadata endpoint reachable" "Risk possible"
}

# ------------------------------
# 12.1.2 - AWS IMDSv1 risk check (basic heuristic)
# ------------------------------
check_12_1_2(){
    curl -s --max-time 1 http://169.254.169.254/latest/meta-data/ &>/dev/null

    [[ $? -ne 0 ]] \
        && result PASS "12.1.2" "HIGH" "IMDS not accessible (safe)" "Blocked" \
        || result WARN "12.1.2" "HIGH" "IMDS accessible (risk of SSRF abuse)" "Accessible"
}

# ------------------------------
# 12.1.3 - Cloud credentials file scan
# ------------------------------
check_12_1_3(){
    OUT=$(find / -type f \( -name "*aws*" -o -name "*.pem" -o -name "*.key" \) 2>/dev/null | wc -l)

    [[ "$OUT" -lt 20 ]] \
        && result PASS "12.1.3" "CRITICAL" "Low cloud credential exposure" "$OUT files" \
        || result WARN "12.1.3" "CRITICAL" "Possible credential leakage" "$OUT files"
}

# ------------------------------
# 12.1.4 - SSH private keys exposure check
# ------------------------------
check_12_1_4(){
    OUT=$(find /home /root -name "id_rsa*" 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "12.1.4" "CRITICAL" "No SSH private keys exposed" "Clean" \
        || result FAIL "12.1.4" "CRITICAL" "SSH private keys found" "$OUT files"
}

# ------------------------------
# 12.1.5 - Docker socket exposure (cloud breakout risk)
# ------------------------------
check_12_1_5(){
    [[ -S /var/run/docker.sock ]] \
        && result WARN "12.1.5" "CRITICAL" "Docker socket exposed (privilege escalation risk)" "/var/run/docker.sock exists" \
        || result PASS "12.1.5" "CRITICAL" "Docker socket not exposed" "Safe"
}

# ------------------------------
# 12.1.6 - Kubernetes config exposure
# ------------------------------
check_12_1_6(){
    OUT=$(find / -name "kubeconfig" -o -name "*.kubeconfig" 2>/dev/null | wc -l)

    [[ "$OUT" -eq 0 ]] \
        && result PASS "12.1.6" "CRITICAL" "No kubeconfig exposure detected" "Clean" \
        || result WARN "12.1.6" "CRITICAL" "Kubernetes config files found" "$OUT files"
}

# ------------------------------
# 12.1.7 - Cloud-init misconfiguration check
# ------------------------------
check_12_1_7(){
    [[ -d /etc/cloud ]] \
        && result PASS "12.1.7" "MEDIUM" "Cloud-init present (normal)" "/etc/cloud exists" \
        || result WARN "12.1.7" "MEDIUM" "No cloud-init detected" "Not cloud configured"
}

# ------------------------------
# 12.1.8 - Public interface exposure detection
# ------------------------------
check_12_1_8(){
    OUT=$(ip addr | grep "inet " | grep -v "127.0.0.1" | wc -l)

    [[ "$OUT" -gt 0 ]] \
        && result PASS "12.1.8" "LOW" "Network interfaces active" "$OUT interfaces" \
        || result WARN "12.1.8" "LOW" "No active external interface detected" "Check needed"
}

# ------------------------------
# 12.1.9 - Cloud agent presence (AWS / Azure / GCP)
# ------------------------------
check_12_1_9(){
    if systemctl list-units | grep -q "waagent"; then
        result PASS "12.1.9" "LOW" "Azure agent detected" "waagent active"
    elif systemctl list-units | grep -q "amazon"; then
        result PASS "12.1.9" "LOW" "AWS agent detected" "amazon-agent active"
    else
        result WARN "12.1.9" "LOW" "No cloud agent detected" "Unknown environment"
    fi
}

# ------------------------------
# 12.1.10 - Virtualization detection
# ------------------------------
check_12_1_10(){
    OUT=$(systemd-detect-virt 2>/dev/null)

    [[ "$OUT" != "none" ]] \
        && result PASS "12.1.10" "LOW" "Virtualized environment detected" "$OUT" \
        || result WARN "12.1.10" "LOW" "Physical/unknown environment" "Bare metal or unknown"
}

# ------------------------------
# RUNNER
# ------------------------------
run_cloud(){
    check_12_1_1
    check_12_1_2
    check_12_1_3
    check_12_1_4
    check_12_1_5
    check_12_1_6
    check_12_1_7
    check_12_1_8
    check_12_1_9
    check_12_1_10
}