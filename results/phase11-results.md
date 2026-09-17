# PHASE11 — Candidate Discovery integrated local E2E

AUTHORITATIVE REPO = `/home/tenggn/projects/clean_pmeq`.
Begin HEAD c67336ed04c1ca26438ea2003333863c1b19e895, clean.

## Boundary and supported domain

The production entry point is `discovery.RunLocal(ctx, Query, UserKeys,
UserPacket, [2]*Static, [2]*PartyPacket, SCMPBackend)` returning CandidatePairs,
Metrics and error. Query has Anchor/Target strings and independent TauAnchor/
TauTarget. `discovery.Provision` is a separate TRUSTED OFFLINE operation and
must complete before RunLocal. There is no online refill or dealer callback.
The canonical runner is a Go API; the native replay test is its caller, not its
implementation. It does not call test functions or a reference comparator.

Normal input uses complete nonoverlapping q=4 Unicode chunks, 0<=tau_i<r_i,
lambda_i=r_i-tau_i, Anchor r1..14 and Target r1..16 (existing audited bounds).
Incomplete tails are dropped by the existing token rule; repeated chunks remain
separate occurrences. No tau clamping or query rewriting occurs. Queries with
fewer than four usable characters are rejected; short-string completeness
remains OPEN (Anchor644, Target4047), with no fallback.

Each party receives only its own static objects, packet, encoded user token and
byte-message endpoint. It runs existing real DPF/LLAMA/Beaver/permutation/
compaction/routing/PE/Position/Target aggregation components. PHASE11 adds
orchestration and codecs, not new cryptography or stage optimization. The
original ComposeHits/BatchAND test coordinators are not used online: their
existing party-local Mask/Open/Finish steps consume preprovisioned triples.

## Authorized Query User recovery

CandidatePairs = {QueryID, []Pair{AnchorRecordID,TargetRecordID}}.
Only the user's `candidatequery.Recover(expectedBinding, cs0Bytes, cs1Bytes)`
reconstructs Keep=Keep0 XOR Keep1, AnchorID=ID0+ID1 mod2^64 and TargetID likewise.
Keep1 appends a pair; Keep0 REQUIRES both IDs zero. Duplicates fail closed,
without silently deduplicating. Expected IndexID/manifest, LayoutID,
CompactionID, QueryID, sender role, D26, K and exact lengths are checked.
Authenticated role channels are an assumption; these codecs are not a MAC.

Every cloud output is fixed26K slots, candidate-major then ordinal order.
The result codec is magic8+party1+manifest21+three lineage IDs48+K4+D4 =86
header bytes, followed by17 bytes/slot (Keep1, AnchorID8, TargetID8). Cloud-side
arrays are neither sorted nor compacted again. Only the user learns the final
pair cardinality. Full strings, exact edit-distance verification and application
record fetching are outside Candidate Discovery.

## Real correctness

149/149 historical invalid Target thresholds reject at the runner entrance,
before token generation, provisioning consumption or any cloud message. The
854 valid queries execute the complete real chain, including initial tokens and
final user recovery. Raw strings are used only in separate trusted setup/oracle
code; no oracle-constructed Keep, compaction, routing, Match, Hit or pair input
enters the production runner. The independent oracle computes positional qchunk
matches directly from original area and area_alias strings.

1510 recovered pairs total; FP=0, FN=0, duplicate pairs=0, wrong AnchorID=0,
wrong TargetID=0. Each valid query also preserves its PHASE10 K/G/S workload.
Unlike PHASE10's upstream diagnostic replay, PHASE11 rejects149 before Anchor;
its executed route/slot totals therefore cover854 only. Rejected cases are not
imputed as empty successful answers. Tests additionally cover malformed outputs,
masked nonzero IDs, swapped parties, wrong query bindings, Ring64 wraparound,
K0/K1, duplicate results, packet-copy one-use guards and byte codecs.

## Valid real workload

Mean is primary. Quantiles use nearest rank ceil(n*p)-1. All distributions below
cover854 accepted queries unless explicitly stated otherwise.


| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| K | 97.946136 | 4 | 84 | 349 | 2,739 | 4,780 |
| routes | 467.811475 | 8 | 325 | 1,036 | 11,096 | 38,240 |
| groups | 2,218.509368 | 41 | 1,549 | 4,950 | 52,760 | 180,227 |
| Target physical slots | 9,417.381733 | 176 | 6,592 | 20,944 | 223,604 | 764,768 |
| Recovered real pairs | 1.768150 | 0 | 2 | 6 | 15 | 667 |

Executed totals: routes=399,511, groups=1,894,607, slots=8,042,444.

## Integrated timings, milliseconds

INTEGRATED LOCAL E2E WALL TIME is one outer time.Now/time.Since around initial
user token generation, concurrent cloud processing and final user recovery.
It includes encoded local channel traffic, output encoding and scheduling; it
excludes offline provisioning, index construction and the external oracle.
Token generation includes actual DPF generation and Target token masking/codec.
Recovery includes decoding the user's saved token binding and both output messages.
Cloud phase times include exchanges/waits and use the maximum party duration per
stage. They are supplemental stage measurements, not an E2E definition. The
outer wall is measured independently and is never replaced by their sum.
Heap sampling at10ms and initial/final boundaries instruments the same process.
This is not network/TCP/distributed-deployment latency. Historical component
sums retain their original SUM OF MEASURED COMPONENTS label.


| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| Token | 0.876621 | 0.787500 | 1.433007 | 1.704528 | 2.216274 | 3.345373 |
| Anchor | 236.705800 | 179.970360 | 238.079714 | 506.707103 | 1,382.530224 | 1,584.306153 |
| Compaction | 121.787854 | 118.881196 | 146.589395 | 154.074412 | 171.641541 | 195.426517 |
| Routing | 4.302804 | 2.224982 | 4.874725 | 9.948565 | 67.145470 | 127.134583 |
| TargetPE | 93.541750 | 3.131539 | 75.338647 | 227.448913 | 2,163.423744 | 7,412.717935 |
| TargetPosition | 79.388145 | 1.598361 | 58.572144 | 187.852257 | 1,944.628579 | 6,484.681980 |
| TargetAggregation | 50.572708 | 1.901541 | 39.578481 | 129.582821 | 1,186.428370 | 3,760.360643 |
| OutputEncoding | 0.045554 | 0.003719 | 0.036672 | 0.183059 | 1.112270 | 2.294255 |
| Recovery | 0.148851 | 0.076023 | 0.176824 | 0.424234 | 1.702430 | 4.998146 |
| Cloud | 582.598862 | 320.525684 | 673.486525 | 1,345.243834 | 5,833.737667 | 18,736.487640 |
| INTEGRATED LOCAL E2E WALL TIME | 583.629932 | 321.453126 | 674.543502 | 1,346.666746 | 5,836.373221 | 18,739.992364 |

## Representative repeated real-query E2E

Workload metric is Target physical slots S. Choose nearest actual mean S and nearest-rank p50/p95/p99 among854 valid queries. Each repeat uses fresh full-protocol material prepared before the outer timer. Static state is reused. All runs use the same production RunLocal entry point and compare the final result to the independent oracle. All four cases use10 warmup/30 measured invocations.

mean workload: historical query 292, K=161, S=9440; warmup=10, measured=30.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| INTEGRATED LOCAL E2E WALL TIME ms | 561.579050 | 563.568145 | 602.308093 | 614.468297 |

p50 workload: historical query 82, K=7, S=176; warmup=10, measured=30.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| INTEGRATED LOCAL E2E WALL TIME ms | 334.017942 | 330.919427 | 365.309472 | 367.381862 |

p95 workload: historical query 382, K=259, S=20944; warmup=10, measured=30.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| INTEGRATED LOCAL E2E WALL TIME ms | 859.978625 | 863.765852 | 945.329116 | 1,023.013969 |

p99 workload: historical query 538, K=2774, S=223604; warmup=10, measured=30.

| quantity | mean | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| INTEGRATED LOCAL E2E WALL TIME ms | 6,089.209252 | 6,041.460961 | 6,553.803324 | 6,711.629405 |

## Online communication, encoded application bytes

All values count actual byte slice lengths, not Go object memory. Both initial
user tokens are encoded and decoded; all online cloud messages traverse byte
channels. A37-byte query/packet/sequence/role envelope binds each cloud message,
including one-way permutation/compaction steps (the opposite party sends an
empty envelope). Existing Target framing remains inside this envelope. Local
index reads, internal arrays, random generation and offline material are excluded.
No network transport headers are included. One initial token per cloud has
122+2352*r_anchor+66*r_target bytes with the fixed DPF key encoding.


| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| QueryUser → CS0 | 4,875.861827 | 4,958 | 7,706 | 9,926 | 12,938 | 19,202 |
| QueryUser → CS1 | 4,875.861827 | 4,958 | 7,706 | 9,926 | 12,938 | 19,202 |
| CS0 ↔ CS1 | 22,547,470.864169 | 11,571,542 | 28,265,128 | 55,723,642 | 181,385,468 | 508,221,038 |
| CS0 → QueryUser | 43,378.192037 | 1,854 | 37,214 | 154,344 | 1,210,724 | 2,112,846 |
| CS1 → QueryUser | 43,378.192037 | 1,854 | 37,214 | 154,344 | 1,210,724 | 2,112,846 |
| Total online encoded bytes | 22,643,978.971897 | 11,592,086 | 28,276,984 | 56,906,514 | 181,410,420 | 512,476,254 |

## One-time offline Q_pool material, both parties plus user masks

Preprocessing is provisioned before query execution. All required stage-correlated body fields are counted separately below, using actual opaque SCMP key lengths. These are compact field-volume accounts, not an offline wire codec or resident-memory estimate; packet IDs, public class metadata, registries and allocator overhead are excluded. Raw replay Offline fields count both clouds. The table additionally includes required user secret masks: Anchor Position8*r_anchor bytes, Anchor aggregation r_anchor+1 bytes, Target Position8*r_target bytes and Target aggregation2 bytes. These follow actual uint32 position-mask and byte aggregation-mask representations. The exact per-query expanded accounting is saved in phase11-offline-required.json. Compaction includes both fresh permutation arrays and six43-byte tuple masks per global coordinate. Anchor Position includes both SCMP/rho fields and both F2 triple layers. Anchor Aggregation includes Hit/z B2A, chunked incidence triples, comparisons and global permutation masks. Target stages use their existing field accounts. Reusable static state is excluded. No query-time dealer/refill is called. The replay reserves exact saved public workload capacities offline; the existing Target protocols also support larger public capacity classes. A heterogeneous Q_pool costs the sum of its packet classes, not a percentile multiplied by pool length.

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| AnchorPosition | 1,098,597.489461 | 163,536 | 2,985,448 | 6,082,976 | 11,521,192 | 16,552,936 |
| AnchorAggregation | 83,942,718.566745 | 70,187,851 | 80,160,625 | 141,561,390 | 351,273,276 | 417,297,028 |
| Compaction | 31,938,886 | 31,938,886 | 31,938,886 | 31,938,886 | 31,938,886 | 31,938,886 |
| TargetPE | 431,897.142857 | 12,240 | 306,000 | 954,720 | 10,098,000 | 34,480,080 |
| TargetPosition | 10,999,524.599532 | 205,576 | 7,699,472 | 24,462,624 | 261,169,504 | 893,249,088 |
| TargetAggregation | 14,024,209.044496 | 293,450 | 10,157,210 | 31,885,066 | 341,238,674 | 1,084,295,890 |
| Total one-time field material | 142,435,832.843091 | 103,709,024 | 169,565,970 | 300,385,936 | 797,757,958 | 2,405,364,511 |

## Separate offline/setup timing samples

Existing BSMJ IndexOutsource materialization measured separately: 5,276.988986 ms. Complete trusted fixture setup including raw oracle loading and sealed-file validation: 9,071.925795 ms. Neither enters online E2E. PSMJ construction was not rerun.

One separately measured offline sample per representative query follows; these are setup/provisioning samples, not an854-query offline-latency distribution. Reusable static extensions and one-time material are separated.

| historical query | reusable static extension ms | one-time provisioning ms |
| --- | ---: | ---: |
| 292 | 46.632915 | 965.167096 |
| 82 | 45.889773 | 742.441228 |
| 382 | 99.710747 | 1,148.795967 |
| 538 | 213.488343 | 5,820.846437 |

## Static storage, bytes

PSMJ, global payload and Target aggregation are the original hash-verified sealed files, unchanged. The inherited Anchor implementation has no persistent index/alignment codec: the existing trusted IndexOutsource builder materializes BSMJ once for execution, outside every online timer. Each tested bucket incidence/alignment is provisioned offline before the query; repeated benchmarks reuse it. The full-domain Anchor figures below are exact semantic field counts, not a claim that all25.6GB of sigma factors were loaded or persisted. No index was rebuilt merely to obtain this table, and PSMJ was never rebuilt. Public sealed manifest file sizes are listed separately. Go descriptors, maps, slice headers and in-memory Anchor shape metadata are not mixed with field bytes. User master keys64 bytes are user-only, not cloud static state.

| static item | CS0 | CS1 | combined |
| --- | ---: | ---: | ---: |
| Anchor alignment full-domain factors | 1,708,256 | 25,639,000,772 | 25,640,709,028 |
| Anchor incidence full-domain fields | 760,502,120 | 760,502,120 | 1,521,004,240 |
| BSMJ semantic fields | 94,728,326 | 94,728,326 | 189,456,652 |
| Global sealed payload files | 5,043,028 | 5,043,028 | 10,086,056 |
| PSMJ sealed files | 29,204,994 | 29,204,994 | 58,409,988 |
| Target aggregation sealed files | 100,301,133 | 100,301,133 | 200,602,266 |
| Public sealed manifests | 2,103 | 2,103 | 4,206 |
| Total listed fields/files | 991,489,960 | 26,628,782,476 | 27,620,272,436 |

## Integrated memory

| quantity | mean | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| Integrated peak sampled heap bytes | 1,291,258,170.295082 | 1,286,833,768 | 1,386,120,824 | 1,786,623,768 | 3,585,257,448 | 6,462,384,512 |

Each observation is the peak sampled heap across one complete integrated invocation. No individual-stage peaks are summed. Process RSS below includes trusted offline setup, native code, both clouds and the raw comparison oracle; it is not per-cloud production RSS. Sampling every10ms is a sampled peak, not a proof of continuous peak-live memory.

One-pass process

```text
Elapsed (wall clock) time (h:mm:ss or m:ss): 39:07.71
Maximum resident set size (kbytes): 7150976
Swaps: 0
```

Repeated-benchmark process

```text
Elapsed (wall clock) time (h:mm:ss or m:ss): 17:15.33
Maximum resident set size (kbytes): 3319032
Swaps: 0
```

## NETWORK PAYLOAD LOWER BOUND

Ideal serialization of measured total ONLINE application bytes at the stated aggregate bottleneck bandwidth; no preprocessing, disk reads, TCP/Ethernet overhead, RTT, congestion or protocol round delays. The single aggregate-bottleneck assumption matters: independent full-duplex links may overlap. These are not actual network latency measurements.

| quantity | mean | p95 | p99 |
| --- | --- | --- | --- |
| 1 Gbps, ms | 181.151832 | 455.252112 | 1,451.283360 |
| 10 Gbps, ms | 18.115183 | 45.525211 | 145.128336 |
| 25 Gbps, ms | 7.246073 | 18.210084 | 58.051334 |

## Single-party security and validation

Existing trusted DO, authorized honest Query User, semi-honest noncolluding cloud
assumptions are retained. Neither cloud state contains the user's master keys,
raw query strings, plaintext incidence mappings, peer state, or user masks.
Isolation here is at the party API boundary: this local prototype process hosts
both workers and the user, not separate OS security domains. The coordinator
routes encoded MASKED openings only. Each cloud owns one
packet guard; copying packet handles cannot regenerate or reuse material.
The Query User is offline after initial token emission until final recovery.
The final user result is not sent back to either cloud. No full Y, GroupMatch,
posting Hit, Target Keep, Target ID or final pair count is opened to clouds.
The existing shuffled Anchor Keep opening/allowed K leakage remains unchanged.
No test-only phase10audit build is used by the PHASE11 runner or replay.

Run from `/home/tenggn/projects/clean_pmeq`:

```sh
GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test ./...
GOCACHE=/tmp/phase11-cache /tmp/go/bin/go vet ./...
GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -race -timeout=60m ./...
PMEQ_PHASE11=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestIntegratedReal$' -count=1 -timeout=90m -v
PMEQ_PHASE11_BENCH=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestIntegratedRepeated$' -count=1 -timeout=90m -v
PMEQ_PHASE11_OFFLINE=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/phase11-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestOfflineTiming$' -count=1 -timeout=30m -v
python3 tools/summarize_phase11.py
```

All final checks and exact resource outputs are in companion logs.

CANDIDATE DISCOVERY E2E = COMPLETE for the supported normal query domain.
Historical invalid queries rejected=149/149; valid real queries correct=854/854.
Short-string completeness=OPEN; full-string exact verification implemented=NO.
Query-time DO=NO; paper modified=NO; alternate repository created=NO;
obsolete repository used=NO; backup modified=NO.
