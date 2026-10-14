#!/usr/bin/env bash
set -euo pipefail
root=/home/tenggn/projects/clean_pmeq
work="$root/verification/anchor-replacement"
export GOTOOLCHAIN=local GOPROXY=off GOCACHE="$work/cache/go" GOMODCACHE="$work/cache/mod" GOPATH="$work/cache/gopath" TMPDIR="$work/tmp"
export CGO_ENABLED=1 CGO_LDFLAGS="-L$work/cache/native -lphase6scmp -lcrypto -lpthread"
exec "$root/artifacts/n-domain-regression-pilot-runtime/go/bin/go" "$@"
