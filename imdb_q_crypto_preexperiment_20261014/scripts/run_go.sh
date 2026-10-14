#!/usr/bin/env bash
set -euo pipefail
root=/home/tenggn/projects/clean_pmeq
work="$root/imdb_q_crypto_preexperiment_20261014"
export GOTOOLCHAIN=local GOPROXY=off GOCACHE="$work/cache/go"
export GOMODCACHE="$root/verification/anchor-replacement/cache/mod"
export TMPDIR="$work/tmp" CGO_ENABLED=1
export CGO_LDFLAGS="-L$work/native -lphase6scmp -lcrypto -lpthread"
export GOMAXPROCS=2 GOMEMLIMIT=4GiB
exec "$root/artifacts/n-domain-regression-pilot-runtime/go/bin/go" "$@"
