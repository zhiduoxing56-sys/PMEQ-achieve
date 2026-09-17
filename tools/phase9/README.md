# PHASE9 reproduction

Use the existing PHASE7B sealed files and manifests under artifacts/phase7b.
The large party files remain locally provisioned, git-ignored artifacts. No test
or production fallback rebuilds a Target index. Old repo and raw DB are read-only.

Build the unchanged external native bridge under /tmp:

```sh
bash tools/build_phase6_native.sh
CGO_LDFLAGS=/tmp/phase6-native/libphase6scmp.a go test -tags phase6native \
 ./internal/targetposition -run 'TestNativePositionBoundsAndComposition' -count=1 -v
CGO_LDFLAGS=/tmp/phase6-native/libphase6scmp.a PMEQ_AGG_FULL=1 \
 PMEQ_POSITION_COUNTS=/tmp/phase9-counts.json go test \
 -tags 'phase6native phase9integration' ./internal/aggregation \
 -run '^TestReal1000Queries$' -count=1 -v -timeout=120m
CGO_LDFLAGS=/tmp/phase6-native/libphase6scmp.a PMEQ_POSITION_BENCH=1 \
 go test -tags phase6native ./internal/targetposition \
 -run '^TestPositionNativeBenchmarks$' -count=1 -v -timeout=120m

go test ./... -timeout=60m
go vet ./...
go test -race -timeout=60m ./...
```

Ordinary unit tests explicitly label their insecure test-only oracle backend.
All performance data and the complete real replay use actual LLAMA. The native
edge tests independently exercise PHASE4 EvalPosition and posting composition.
No trusted oracle constructs the real replay's Match inputs.

The replay provisions fresh Position packets in its trusted offline setup before
initial query token generation, then runs actual Anchor through Target PE and
Position. Capacity comes from the already saved PHASE7B workload; production
reserves public capacity bounds instead. No cloud calls this dealer, and neither
Query User nor DO is contacted after the initial token. A packet is burned at
Begin, including unused capacity. One fresh slot key pair and two Beaver triples
are allocated per occurrence/physical-slot invocation, including repeated buckets.

Benchmark fixtures are real saved candidate payload shares routed through actual
Target PE against the sealed index. The isolated Position component repeats those
secret Match inputs with fresh one-time Position packets/masked bounds each trial.
It does not measure the already executed upstream stages or claim new end-to-end
queries. A covers public slot expansion and local masked-position processing;
B wraps actual backend Eval; C is the rest of unchanged PHASE4 EvalPosition,
including rb correction and output conversion; D/E are the two AND layers; F
writes final HitShares. G sums components within each trial before percentiles.
Static artifact load and offline key generation are excluded from online timing.
Heap samples are relative to the post-preprocessing baseline; RSS includes both
parties, static fixtures and one-time material. These are not TCP E2E latencies.

Short Target strings are explicitly reported as completeness OPEN by the new
initial Position-token API; no fallback is supplied. Normal q=4 semantics and
all sealed artifact parameters remain unchanged.
