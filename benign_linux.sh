#!/bin/bash
# ============================================================
#  benign_linux.sh  --  B-Profile-style benign traffic generator
#  Run on Linux benign clients: 192.168.10.17, .19, .25
#
#  Reproduces the *behaviour* of CIC's B-Profile (the real B-Profile
#  tool is private): each machine runs several concurrent "users",
#  each user loops through HTTP, FTP, SSH and DNS to the internal
#  services host (.51), with randomised think-time between actions.
#
#  USAGE:   ./benign_linux.sh <RUN_MINUTES>
#  EXAMPLE: ./benign_linux.sh 60
# ============================================================

# -------- CONFIG (edit only if your services move) --------
SERVER="192.168.10.51"     # internal services hub (web/ftp/ssh/dns)
DNS_SERVER="192.168.10.51" # DNS answers here
FTP_USER="benign"
FTP_PASS="benign123"
SSH_USER="benign"
SSH_PASS="benign123"
USERS_PER_HOST=3           # concurrent simulated users on THIS machine
                           # 3 users x (up to) 9 hosts ~= 25 users like CIC
# ----------------------------------------------------------

RUN_MIN="${1:-60}"
END=$(( $(date +%s) + RUN_MIN*60 ))
LOG="/tmp/benign_$(hostname)_$(date +%H%M%S).log"

echo "benign generator on $(hostname) $(hostname -I| awk '{print $1}')" | tee "$LOG"
echo "target services host: $SERVER   run: ${RUN_MIN} min   users: $USERS_PER_HOST" | tee -a "$LOG"

# make sure the tools we use exist (curl + ssh are enough; sshpass for ssh login)
command -v curl >/dev/null || { echo "curl missing: sudo apt install -y curl"; exit 1; }
command -v sshpass >/dev/null || echo "note: sshpass missing -> ssh actions skipped (sudo apt install -y sshpass)"

# a pool of URLs/paths so requests look varied (GET, query strings, POST)
http_actions() {
  local u=$1
  case $(( RANDOM % 6 )) in
    0) curl -s -o /dev/null "http://$SERVER/" ;;                              # homepage GET
    1) curl -s -o /dev/null "http://$SERVER/index.html" ;;                    # page GET
    2) curl -s -o /dev/null "http://$SERVER/?user=u$u&q=$RANDOM" ;;           # GET w/ query
    3) curl -s -o /dev/null -d "user=u$u&pass=x$RANDOM" "http://$SERVER/" ;;  # POST form
    4) curl -s -o /dev/null -b "session=u$u$RANDOM" "http://$SERVER/" ;;      # session cookie
    5) curl -s -o /dev/null "http://$SERVER/nonexistent-$RANDOM" ;;           # 404 (realistic)
  esac
}

ftp_action() {  # download a file over FTP (login + retrieve)
  curl -s -o /dev/null "ftp://$FTP_USER:$FTP_PASS@$SERVER/f.txt" 2>/dev/null
}

ssh_action() {  # short SSH login + command
  command -v sshpass >/dev/null || return
  sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$SSH_USER@$SERVER" "echo ok; uptime" >/dev/null 2>&1
}

dns_action() { # a DNS lookup against the internal resolver
  nslookup "host$RANDOM.local" "$DNS_SERVER" >/dev/null 2>&1
  nslookup "www.example.com"   "$DNS_SERVER" >/dev/null 2>&1
}

# one simulated user = an endless loop of mixed actions with think-time
user_loop() {
  local id=$1
  while [ "$(date +%s)" -lt "$END" ]; do
    case $(( RANDOM % 10 )) in
      0|1|2|3|4|5) http_actions "$id" ;;   # HTTP is the most common (like real users)
      6|7)         dns_action ;;
      8)           ftp_action ;;
      9)           ssh_action ;;
    esac
    # think-time 1-8 s between actions (randomised => realistic timing)
    sleep $(( (RANDOM % 8) + 1 ))
  done
}

echo "starting $USERS_PER_HOST users..." | tee -a "$LOG"
for i in $(seq 1 "$USERS_PER_HOST"); do
  user_loop "$i" &
done
wait
echo "benign generator finished on $(hostname)" | tee -a "$LOG"
