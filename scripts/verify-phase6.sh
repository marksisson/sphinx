#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

go test ./cmd/sphinx ./internal/cliresult ./internal/tombstate ./internal/worktree ./internal/transaction
go test -race ./cmd/sphinx ./internal/cliresult

bin="$(mktemp -d)/sphinx"
go build -buildvcs=false -o "$bin" ./cmd/sphinx
set +e
stdout="$($bin --json artifact reveal --listen-address 127.0.0.1:8080 production/api 2>"$bin.err")"
status=$?
set -e
[ "$status" -eq 64 ]
[ -z "$stdout" ]
python3 - "$bin.err" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
assert value == {"version":1,"ok":False,"error":{"code":"usage","message":"unknown flag: --listen-address","retryable":False}}
PY

help="$($bin --help)"
for command in tomb artifact guardian decree proclamation; do grep -q "  $command" <<<"$help"; done
if grep -Eiq '\b(listen|online)\b' <<<"$help"; then
  echo 'network command surface remains in root help' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' 'net/http|ListenAndServe|http\.Client|WhoIs\(' cmd/sphinx; then
  echo 'CLI replacement contains a service/client identity path' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' -- '--(listen-address|recovery|stdin|from-json|clipboard|output|file|fd|exec)\b' cmd/sphinx; then
  echo 'forbidden CLI input/output mode remains' >&2
  exit 1
fi

echo 'Phase 6 command, JSON, sysexits, synchronous reveal, and no-listener gates verified'
