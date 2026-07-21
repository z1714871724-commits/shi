#!/bin/zsh
cd "$(dirname "$0")/.."
LOG=/tmp/client-$$.log
./target/debug/ssh-client >$LOG 2>&1 &
CL=$!
sleep 3
if kill -0 $CL 2>/dev/null; then
  echo "client running (pid $CL) - UI launched OK"
  kill $CL 2>/dev/null
else
  echo "client exited early"
fi
echo "=== client log ==="
cat $LOG
