# PHASE 7 measured results

Private Routing complete=YES. PHASE5=SEALED; Candidate Compaction=COMPLETE.
Production full Y reconstruction=NO. Target Equality/Position/Aggregation=no.
Query-time party DO/raw DB access=no; Query User offline after initial token.
Paper modified=NO. Old full-Y combine/Target DPF/CW routes were not migrated.

## Target setting and real validation

TargetBucketBits=8 / B=256 for this integration, independent of Anchor bits=16.
Target B final choice=OPEN. This is the last fully materialized/validated PSMJ
setting, not an implicit assignment from Anchor or a new bucket-count freeze.
The interface supports explicit widths 1..16 and rejects mismatched domains.
See phase7-audit.md for source evidence and the PHASE6 mask-width handoff fix.

Materialized MusicBrainz 20260905-002519 PSMJ: all 67896 aliases, 310331 logical
groups, 1317260 padded slots, every reconstructed group point matched to the
independent (joinID,qgram) oracle and bucket: 0 errors.

100000 equal and 100000 unequal routing-point checks: 0 errors. Unequal
categories: same join/different word=33332; different join/same word=26045;
both different=40623. Comparisons are strictly trusted test-oracle operations.
No production equality or full-Y combine exists.

Final native real-query execution runs Anchor DPF, LLAMA Position/Keep,
incidence/aggregation, fresh compaction and private routing for 1000 seed-502
normal queries plus the three PHASE5 workload-quantile queries. User tokens
are generated before Anchor execution. Seed-707 shuffled normal-alias sampling
provides unrelated negatives, with positive and repeated real-alias fixtures.
Queries=1003, positive=248, negative=755, repeated=59,
candidate-occurrence pairs=466105, pairs matching existing logical groups=2554.
Every pair's bucket and reconstructed Y matched its oracle; presence/absence
matched the materialized PSMJ identity map: **0 errors**.

aggregation_test.go:511: PHASE6 K n=1000 min=1 p50=5 p90=151 p95=431 p99=2843 max=4780
aggregation_test.go:517: COMPONENT pct=0.50 query="Kōzushima" intrinsic=32772 stats={XF:240.658µs Perm:1.694352ms Sum:237.217µs B2AZ:6.597µs FComparisons:160 R:2 T:332 P:35968 K:1 Peak:557123568}
aggregation_test.go:517: COMPONENT pct=0.95 query="Negrilla de Palencia" intrinsic=25174016 stats={XF:155.35231ms Perm:4.023177ms Sum:518.642µs B2AZ:68.466µs FComparisons:6560 R:5 T:8700 P:25342848 K:1 Peak:852011128}
aggregation_test.go:517: COMPONENT pct=0.99 query="Saint-Pierre-d'Oléron" intrinsic=68255872 stats={XF:436.110549ms Perm:4.796036ms Sum:753.595µs B2AZ:105.612µs FComparisons:9616 R:5 T:9780 P:68338560 K:1 Peak:869484800}

## Target workload and benchmark grid

Full area_alias.name scan: raw=67896, short (<4 code points)=4047,
normal=63849, names with repeated non-overlapping qchunks=34.

| r min | p50 | p90 | p95 | p99 | max |
|---:|---:|---:|---:|---:|---:|
| 1 | 2 | 4 | 5 | 7 | 16 |

Grid: K={1,5,64,431,512,2843,4780} x r={1,2,5,7,16}.
These combine independent marginals; they are NOT joint-query percentiles.
All 35 distinct points were measured, including 4780*16=76480 pairs after a
state estimate of 6807280 bytes (<12 GiB). Two selected-worker sweep rows are
reused rather than measured twice.

Host: Intel Core i9-14900HX, 32 logical CPUs, Linux amd64, Go 1.27.1.
2 warmups + 10 measured iterations per row, fresh Query User shares each time.
Each table entry is p50 / p95 milliseconds, nearest-rank (p95 is the maximum
of ten samples). User timing includes token generation+encoding; cloud timings
include token decoding and local Prepare. Opening is both Finish calls locally,
not network latency. Benchmarks shared the host with correctness/build tasks;
they are local measurements, not isolated-host throughput guarantees.

## Worker sweep

| K | r | Workers | CS0 ms | CS1 ms | Opening ms |
|---:|---:|---:|---:|---:|---:|
| 431 | 5 | 1 | 21.400 / 30.448 | 20.595 / 26.741 | 0.033 / 0.053 |
| 431 | 5 | 4 | 7.514 / 9.637 | 8.115 / 15.829 | 0.036 / 0.064 |
| 431 | 5 | 8 | 5.913 / 7.947 | 5.886 / 6.942 | 0.032 / 0.057 |
| 431 | 5 | 16 | 5.428 / 5.925 | 5.285 / 6.077 | 0.036 / 0.134 |
| 2843 | 5 | 1 | 126.624 / 143.674 | 125.448 / 138.513 | 0.178 / 0.210 |
| 2843 | 5 | 4 | 41.596 / 43.438 | 42.084 / 57.264 | 0.204 / 0.246 |
| 2843 | 5 | 8 | 31.610 / 38.860 | 32.010 / 37.119 | 0.245 / 0.518 |
| 2843 | 5 | 16 | 28.831 / 30.770 | 28.748 / 32.030 | 0.551 / 1.293 |

Selected/recommended workers=16: lowest CS0+CS1 median sums at both sweep
workloads. This is a host recommendation; the API accepts explicit 1/4/8/16.
Only local point arithmetic and bucket-share generation are parallelized.
Opening and Query User generation are not distributed worker tasks.

## Full grid, 16 workers

| K | r | Query User ms | CS0 ms | CS1 ms | Opening ms |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0.129 / 0.171 | 0.104 / 0.131 | 0.087 / 0.092 | 0.001 / 0.001 |
| 1 | 2 | 0.226 / 0.250 | 0.137 / 0.185 | 0.132 / 0.192 | 0.001 / 0.002 |
| 1 | 5 | 0.517 / 0.627 | 0.150 / 0.214 | 0.182 / 0.252 | 0.002 / 0.004 |
| 1 | 7 | 0.793 / 0.869 | 0.191 / 0.259 | 0.214 / 0.319 | 0.002 / 0.003 |
| 1 | 16 | 1.622 / 1.990 | 0.317 / 0.575 | 0.320 / 0.390 | 0.002 / 0.002 |
| 5 | 1 | 0.119 / 0.162 | 0.221 / 0.276 | 0.212 / 0.437 | 0.002 / 0.002 |
| 5 | 2 | 0.220 / 0.242 | 0.257 / 0.395 | 0.231 / 0.473 | 0.002 / 0.003 |
| 5 | 5 | 0.532 / 0.632 | 0.311 / 0.386 | 0.331 / 0.432 | 0.002 / 0.003 |
| 5 | 7 | 0.677 / 0.861 | 0.331 / 0.461 | 0.365 / 0.489 | 0.002 / 0.006 |
| 5 | 16 | 1.478 / 1.649 | 0.511 / 0.638 | 0.535 / 0.751 | 0.003 / 0.004 |
| 64 | 1 | 0.123 / 0.131 | 1.386 / 1.592 | 1.200 / 1.754 | 0.003 / 0.028 |
| 64 | 2 | 0.220 / 0.368 | 1.382 / 1.783 | 1.218 / 2.093 | 0.004 / 0.007 |
| 64 | 5 | 0.524 / 0.694 | 1.854 / 4.613 | 1.993 / 7.148 | 0.007 / 0.018 |
| 64 | 7 | 0.734 / 0.896 | 1.910 / 2.406 | 1.674 / 2.861 | 0.009 / 0.019 |
| 64 | 16 | 1.502 / 1.780 | 2.582 / 3.391 | 2.613 / 3.468 | 0.023 / 0.035 |
| 431 | 1 | 0.146 / 0.226 | 5.278 / 7.442 | 5.338 / 20.642 | 0.017 / 0.063 |
| 431 | 2 | 0.249 / 0.283 | 5.605 / 6.387 | 5.396 / 6.142 | 0.021 / 0.040 |
| 431 | 5 | 0.513 / 0.749 | 5.428 / 5.925 | 5.285 / 6.077 | 0.036 / 0.134 |
| 431 | 7 | 0.819 / 1.432 | 7.216 / 9.103 | 7.041 / 9.099 | 0.059 / 0.082 |
| 431 | 16 | 1.832 / 2.029 | 9.511 / 11.899 | 10.129 / 13.147 | 0.116 / 0.367 |
| 512 | 1 | 0.115 / 0.146 | 4.692 / 5.586 | 4.626 / 5.844 | 0.010 / 0.021 |
| 512 | 2 | 0.248 / 0.281 | 5.741 / 6.294 | 5.771 / 6.528 | 0.034 / 0.042 |
| 512 | 5 | 0.556 / 0.622 | 7.006 / 8.174 | 6.876 / 7.385 | 0.043 / 0.057 |
| 512 | 7 | 0.734 / 0.940 | 7.860 / 8.190 | 7.785 / 8.527 | 0.062 / 0.081 |
| 512 | 16 | 1.677 / 1.985 | 11.090 / 13.689 | 11.585 / 13.083 | 0.149 / 0.275 |
| 2843 | 1 | 0.125 / 0.208 | 22.621 / 25.416 | 21.707 / 24.188 | 0.050 / 0.085 |
| 2843 | 2 | 0.239 / 0.456 | 23.949 / 32.952 | 23.653 / 25.780 | 0.107 / 0.119 |
| 2843 | 5 | 0.537 / 0.806 | 28.831 / 30.770 | 28.748 / 32.030 | 0.551 / 1.293 |
| 2843 | 7 | 0.742 / 1.082 | 33.182 / 36.566 | 34.041 / 37.208 | 0.339 / 0.495 |
| 2843 | 16 | 1.658 / 2.109 | 51.427 / 58.603 | 50.435 / 60.630 | 0.804 / 1.360 |
| 4780 | 1 | 0.144 / 0.187 | 36.367 / 47.134 | 38.532 / 43.814 | 0.090 / 0.104 |
| 4780 | 2 | 0.262 / 0.394 | 42.525 / 56.519 | 43.568 / 61.695 | 0.190 / 0.501 |
| 4780 | 5 | 0.563 / 0.849 | 48.947 / 51.941 | 49.839 / 54.248 | 0.441 / 0.534 |
| 4780 | 7 | 0.736 / 1.121 | 54.979 / 64.587 | 53.243 / 59.540 | 0.558 / 0.763 |
| 4780 | 16 | 1.647 / 2.571 | 80.306 / 96.820 | 82.084 / 85.272 | 1.419 / 3.595 |

## Bytes and memory

Actual codecs, excluding transport framing:
Query User -> each server = 42+42*r bytes (header plus h/position/point/bucket).
Server -> peer = 82+2*K*r bytes when K*r>0; both directions=164+4*K*r.
K*r=0 generates no opening and zero server-server bytes. Point shares Y NEVER
cross servers and are not included as communication. No PSMJ read is counted.

| r | QueryUser -> CS0 | QueryUser -> CS1 |
|---:|---:|---:|
| 1 | 84 | 84 |
| 2 | 126 | 126 |
| 5 | 252 | 252 |
| 7 | 336 | 336 |
| 16 | 714 | 714 |

Retained routed state, both parties: 304+16*K+16*r+88*K*r bytes on measured
amd64 (152-byte top-level struct, 44-byte Route including padding). This keeps
Anchor RecordID shares once, plus one occurrence/position table per party.
At max grid: user=714 bytes/server; bucket messages=306084 bytes combined;
retained routed state=6807280 bytes. No dummy candidates/accesses for K=0.

Maximum sampled end-of-operation heap increment across measurements=8571968
bytes; this is not a continuous heap high-water measurement. Whole benchmark
process maximum RSS=94371840 bytes, including fixture construction, runtime,
allocation and GC retention. No route state or point cache is stored globally.
Temporary J caches are query-local and scalar multiplication occurs once/candidate.

## Validation and limitations

gofmt, go test ./..., go vet ./..., tagged integration vet,
go test -race -timeout=60m ./..., and git diff --check pass.
The full race gate uses the longer timeout for existing 100k cryptographic suites;
no short mode, sample reduction, or race exclusion is used.
Unit checks include widths 1/8/16, K=0/1/32, short target strings, Unicode,
repeated qchunks, fresh compaction order/ID association, all worker counts,
wrong width/party/index/query binding, malformed messages and replay rejection.

Simulation is relative to public K,r,beta and dimensions. It does not promise
to hide relations or inference already exposed by public bucket patterns; see
phase7-audit.md. Production never reconstructs Y or performs Target equality.
The 100k group log is from the completed group suite before the negative sampler
was made explicitly seeded. Only the final seeded run contributes real-query
counts. Raw logs are preserved with this report; paper modified=NO.
