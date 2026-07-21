#!/bin/zsh
cd "$(dirname "$0")/.."
DB=/tmp/ssh-smoke-$$.db
LOG=/tmp/server-$$.log
./target/debug/ssh-sync-server --addr 127.0.0.1:8797 --db $DB --secret devsecret >$LOG 2>&1 &
SRV=$!
sleep 2
echo "=== server alive? pid=$SRV ==="
kill -0 $SRV 2>/dev/null && echo "yes" || echo "no"
echo "=== health ==="
curl -s http://127.0.0.1:8797/api/v1/health || echo "(curl failed)"
echo
echo "=== register ==="
SALT=$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(16)).decode())')
curl -s -X POST http://127.0.0.1:8797/api/v1/register -H 'Content-Type: application/json' \
  -d "{\"username\":\"demo\",\"password\":\"hunter2\",\"vault_salt\":\"$SALT\"}" || echo "(curl failed)"
echo
echo "=== login ==="
TOKEN=$(curl -s -X POST http://127.0.0.1:8797/api/v1/login -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"hunter2"}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))')
echo "token: ${TOKEN:0:20}..."
echo "=== list hosts (empty) ==="
curl -s http://127.0.0.1:8797/api/v1/hosts -H "Authorization: Bearer $TOKEN" || echo "(curl failed)"
echo
echo "=== wrong login (should error) ==="
curl -s -X POST http://127.0.0.1:8797/api/v1/login -H 'Content-Type: application/json' -d '{"username":"demo","password":"nope"}'
echo
kill $SRV 2>/dev/null
echo "=== server log ==="
cat $LOG
