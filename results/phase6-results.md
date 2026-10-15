# PHASE 6 measured results

Candidate Compaction complete=YES. PHASE5=SEALED. Leakage=K.
Query-time party DO/raw DB access=no. KHPRF/Target filtering started=no.
Paper modified=NO. Old mathematical scheme reusable=YES; see phase6-audit.md.

Environment: Linux amd64, Intel Core i9-14900HX, 32 logical CPUs, Go 1.27.1.
Two local party APIs are measured sequentially in one process. These are
computation/local-message measurements, not TCP latency. Offline dealer work
and oracle reconstruction are outside timed windows. The base K sweep overlapped
the native correctness experiment on the same host; results are not isolated-host
latency claims. Every measured iteration consumes fresh permutations AND masks.

## Real data and correctness

Actual MusicBrainz N=120071. Seed 502 selects 1000 normal queries using the
existing PHASE5 ordering and tau sampling. All run Anchor DPF, native LLAMA
Position, Boolean hits, incidence, deduplication, alignment, native LLAMA Keep,
and exact-K compaction. Each output payload multiset equals the independently
checked plaintext oracle; no missing, extra or duplicate candidates: **0 errors**.
The existing p50/p95/p99 workload queries run in addition, also **0 errors**.
Test-coordinator offline preprocessing/oracle operations are outside party APIs;
no online party method calls a dealer or reads a raw database.

K distribution from these same 1000 cryptographic queries (no rerun for statistics):

| min | p50 | p90 | p95 | p99 | max |
|---:|---:|---:|---:|---:|---:|
| 1 | 5 | 151 | 431 | 2843 | 4780 |

Actual workload-query outputs (workload percentile is distinct from K percentile):

```
aggregation_test.go:498: COMPONENT pct=0.50 query="Kōzushima" intrinsic=32772 stats={XF:243.642µs Perm:2.27306ms Sum:273.334µs B2AZ:4.242µs FComparisons:160 R:2 T:332 P:35968 K:1 Peak:832424536}
aggregation_test.go:498: COMPONENT pct=0.95 query="Negrilla de Palencia" intrinsic=25174016 stats={XF:197.140979ms Perm:4.559309ms Sum:647.4µs B2AZ:92.487µs FComparisons:6560 R:5 T:8700 P:25342848 K:1 Peak:840875320}
aggregation_test.go:498: COMPONENT pct=0.99 query="Saint-Pierre-d'Oléron" intrinsic=68255872 stats={XF:517.786648ms Perm:4.16039ms Sum:648.45µs B2AZ:84.906µs FComparisons:9616 R:5 T:9780 P:68338560 K:1 Peak:488037584}
```

Full-N K=0,1,N,8,N/2,N-1 tests, each run twice, pass. Output K and every field
match the oracle. Same nontrivial support produces different opened positions
under fresh packets. K=0 has empty outputs, K=N has all payloads and refreshed
shares. Small N=0/1/127, wrong layout/shape/query, premature opening, packet-copy
replay, repeated stages/extraction and sealed-pool consumption tests pass.

## Compaction timing

N=120071 for every row. Each distinct K: 10 warmups, 50 measured fresh packets.
Entries are p50 / p95 milliseconds (nearest rank). Duplicate requested K values
are measured once. Opening includes local Keep-message construction and XOR;
extraction includes local count/selection/encoding and temporary-state clearing.

| K | Stage 1 | Stage 2 | Open Keep | Extract | Sampled peak heap increment, bytes |
|---:|---:|---:|---:|---:|---:|
| 0 | 22.369 / 28.998 | 14.903 / 19.464 | 0.900 / 1.173 | 2.430 / 2.847 | 27271184 |
| 1 | 22.671 / 30.284 | 15.138 / 19.094 | 0.949 / 1.187 | 2.446 / 3.248 | 27271264 |
| 5 | 20.217 / 24.571 | 13.666 / 16.371 | 0.827 / 1.138 | 2.152 / 2.613 | 27271616 |
| 8 | 21.392 / 25.917 | 15.298 / 26.494 | 1.032 / 1.326 | 2.520 / 3.213 | 27271840 |
| 64 | 23.079 / 30.194 | 15.111 / 18.158 | 0.948 / 1.325 | 2.443 / 3.026 | 27276544 |
| 431 | 20.702 / 24.224 | 13.601 / 16.161 | 0.842 / 0.993 | 2.177 / 2.770 | 27308544 |
| 512 | 22.127 / 30.230 | 14.756 / 22.321 | 0.962 / 1.232 | 2.492 / 3.297 | 27314176 |
| 2843 | 20.669 / 22.603 | 13.647 / 15.873 | 0.831 / 1.152 | 2.282 / 2.980 | 27529232 |

Heap increment is sampled at stage boundaries against a post-preprocessing,
post-GC baseline, maximum 27,529,232 bytes. It is not a continuous heap high-water
measurement. Whole benchmark process maximum RSS is 118,603,776 bytes, including
inputs, dealer, oracle, runtime and GC retention. Conservative simultaneous
packet+online backing-array bound is 68,560,541 bytes, plus output 84*K and
headers/allocator overhead; see audit for exclusions. Packet backing storage is
41,304,424 bytes. No N-sized shuffled payload is retained after extraction.

## Bytes

Offline correlated mask payload: 30,978,318 bytes/query; fresh permutation
material: 960,568 bytes/query; total 31,938,886 plus public metadata.
Online stage 1: 5,163,053; stage 2: 5,163,053; Keep opening both directions:
240,142; total: 10,566,248 bytes. These are exact logical field widths, not
measured socket traffic or Go padded object sizes. Final output storage is
42*K per party (84*K combined), plus metadata, with no output transmission. On measured amd64, the output
struct header occupies 112 bytes per party, so array backing plus struct is
42*K+112 bytes per party (allocator rounding excluded).

## Validation

gofmt, go test ./..., go vet ./..., tagged native vet, git diff --check, and
focused race tests pass. Raw native-real, edge and benchmark logs are included.
Existing PHASE5 production files are unchanged; its test harness is extended.
The optional native adapter links the old external SCMP implementation only for
the phase6native experiment. No KHPRF or Target filtering experiment was run.
