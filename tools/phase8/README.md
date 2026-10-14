# PHASE8 reproduction

Go1.27.1; use a writable GOCACHE. The final PHASE7B party files must already
exist under artifacts/phase7b and match their committed manifests/hashes.
They are local git-ignored artifacts; tests never rebuild a substitute PSMJ.
Old repository and raw MusicBrainz are read-only. Raw aliases appear only in the
trusted correctness oracle, never in the production PE package.

Build the existing external native bridge into /tmp:

```sh
bash tools/build_phase6_native.sh
CGO_LDFLAGS=/tmp/phase6-native/libphase6scmp.a PMEQ_AGG_FULL=1 \
 go test -tags 'phase6native phase8integration' ./internal/aggregation \
 -run '^TestReal1000Queries$' -count=1 -v -timeout=120m
```

This uses the same seed502 normal queries plus3 workload queries, target texts
from the saved PHASE7B trace, final-width tokens, SAME sealed payload lineage,
actual Anchor/aggregation/compaction/routing and current PE. It does not feed
plaintext oracle D/E into PE. All1003 PE packets are prepared before queries;
production can reserve public capacity bounds and burn unused capacity.

```sh
go test ./... -timeout=60m
go vet ./...
go test -race -timeout=60m ./...
PMEQ_PE_BENCH=small go test ./internal/targetpe -run '^TestPEBenchmarks$' -count=1 -v
PMEQ_PE_BENCH=large go test ./internal/targetpe -run '^TestPEBenchmarks$' -count=1 -v
PMEQ_PE_BENCH=workers go test ./internal/targetpe -run '^TestPEBenchmarks$' -count=1 -v
```

small covers G1/49/1908/5745; large covers50754/180227. Benchmark fixtures run
real routing on sealed payload shares corresponding to saved real queries.
A measures in-memory group-share access, local difference and canonical encoding;
B includes input bit slicing and Boolean masked-gate compute; C message codec/
opening processing; D route/output layout writes. E is the per-trial component
sum, not a sum of independent percentiles and not TCP E2E latency. Disk artifact
loading and offline preprocessing are excluded from online timings.
Each trial uses fresh triples.10 warmup/50 measured, except max G5/20.

The old standalone audit source is built ONLY under /tmp with its existing
rand/rand_chacha/rayon dependencies. export_reference.py adds optional vector
export, with no mathematical change, to a copy of the original source. Run that
copy with PMEQ_AUDIT_EXPORT=/tmp/phase8-old-vectors; loopback sockets are used by
the old reference only. Then:

```sh
PMEQ_PE_REFERENCE=/tmp/phase8-old-vectors go test ./internal/targetpe \
 -run '^TestOldStandaloneDifferential$' -count=1 -v
```

No old Rust source or runtime enters the production tree. Reference timings,
input packing differences and source hash are recorded in results/phase8-results.md.
