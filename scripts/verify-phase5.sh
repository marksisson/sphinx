#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

go test ./internal/decree ./internal/tombstate ./internal/seeker ./internal/reveal ./internal/proclamationrotation ./internal/lockedresource ./internal/transaction

go test -race ./internal/decree ./internal/tombstate ./internal/seeker ./internal/reveal ./internal/proclamationrotation

if grep -R -n -E 'exec\.Command|WhoIs\(' internal/decree internal/tombstate internal/seeker internal/reveal internal/proclamationrotation --include='*.go' --exclude='*_test.go'; then
  echo 'Phase 5 production boundary invokes an external command or remote-peer WhoIs' >&2
  exit 1
fi

if grep -R -n -E -i '\b(relic|essence|facet|medjay|daemon|server)\b' internal/decree internal/tombstate internal/seeker internal/reveal internal/proclamationrotation --include='*.go'; then
  echo 'Phase 5 production boundary contains retired terminology' >&2
  exit 1
fi

echo 'Phase 5 decree, trust-transition, live-seeker, reveal, and rotation gates verified'
