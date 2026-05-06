#!/bin/bash

echo ""
echo "==============================================="
echo " FINAL CIS COMPLIANCE SUMMARY "
echo "==============================================="

TOTAL=$(grep -E "\[(PASS|FAIL|WARN)\]" "$LOG_FILE" | wc -l)
PASS=$(grep "\[PASS\]" "$LOG_FILE" | wc -l)
FAIL=$(grep "\[FAIL\]" "$LOG_FILE" | wc -l)
WARN=$(grep "\[WARN\]" "$LOG_FILE" | wc -l)

echo "Total Checks : $TOTAL"
echo "PASS         : $PASS"
echo "FAIL         : $FAIL"
echo "WARN         : $WARN"

echo ""
echo "-----------------------------------------------"
echo " HIGH / CRITICAL FAILURES "
echo "-----------------------------------------------"

grep -E "\[FAIL\].*(HIGH|CRITICAL)" "$LOG_FILE"

# ------------------------------
# JSON REPORT
# ------------------------------
JSON_FILE="$JSON_DIR/report_${HOSTNAME}_${TIMESTAMP}.json"

cat <<EOF > "$JSON_FILE"
{
  "total": $TOTAL,
  "pass": $PASS,
  "fail": $FAIL,
  "warn": $WARN
}
EOF

echo "[+] JSON report saved: $JSON_FILE"

# ------------------------------
# HTML REPORT
# ------------------------------
HTML_FILE="$HTML_DIR/report_${HOSTNAME}_${TIMESTAMP}.html"

cat <<EOF > "$HTML_FILE"
<html>
<head>
<title>CIS Report</title>
<style>
body { font-family: Arial; background: #111; color: #eee; }
.pass { color: green; }
.fail { color: red; }
.warn { color: orange; }
</style>
</head>
<body>
<h1>CIS Compliance Report</h1>
<p>Total: $TOTAL</p>
<p class="pass">PASS: $PASS</p>
<p class="fail">FAIL: $FAIL</p>
<p class="warn">WARN: $WARN</p>
</body>
</html>
EOF

echo "[+] HTML report saved: $HTML_FILE"

echo ""
echo "==============================================="
echo " REPORT GENERATED SUCCESSFULLY "
echo "==============================================="