# PHASE 7B — final Target layout and materialization

Begin HEAD: `3afa024328d60d86396c97ebfa3947e3a8daf3ba`, clean.
This report belongs to the single `phase 7: finalize target index layout` commit.
Old repository read only. Paper modified=NO.

## Workload provenance and scope

PHASE7 saved aggregate logs, **not a 1003-query detailed trace**. PHASE7B restored
its deterministic query definitions by replaying the SAME native complete chain:
seed502 normal Anchor selection/tau, seed707 alias catalog, the same positive,
negative and repeated-occurrence selection, and the same three workload queries.
This is a fresh full-chain replay, not a recovered original cryptographic transcript:
CompactionIDs and candidate order are freshly randomized. The saved test-only
`phase7b-workload.jsonl.gz` records actual replay compaction outputs in their order,
Anchor string/tau, Target string, occurrences and candidate join values. It must
NEVER be deployed to either cloud. No independent percentile product is used.
All 1003 queries, 466105 routes, 248 positives, 755 negatives, 59 repeated queries
and 2554 present-group pairs match PHASE7 aggregate evidence exactly.

Six layouts use the same PHASE7 test k_T, same 310331 logical groups and unchanged
clean builder tier logic. Target widths are independent of Anchor bits=16.
The sweep uses buildLogical ONCE, recalculates each bucket through canonical APIs,
and runs the current tier metadata builder for every width. It does not allocate
six sets of fresh party shares; the selected final layout is fully materialized.

## Bucket statistics

Quantiles throughout are nearest rank ceil(p*n), with min/max explicit.
Bucket quantiles include ALL B buckets, including empty buckets. `Joins` is the
number of distinct join values in that bucket, computed inside the trusted audit.

| bits | field | min | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | Groups | 1121 | 1211 | 1257 | 1277 | 1296 | 1310 |
| 8 | Slots | 4720 | 5136 | 5364 | 5412 | 5524 | 5672 |
| 8 | Joins | 1078 | 1155 | 1200 | 1218 | 1226 | 1247 |
| 10 | Groups | 249 | 303 | 326 | 332 | 344 | 363 |
| 10 | Slots | 1032 | 1288 | 1392 | 1420 | 1476 | 1560 |
| 10 | Joins | 244 | 299 | 322 | 328 | 339 | 358 |
| 12 | Groups | 49 | 75 | 87 | 91 | 98 | 110 |
| 12 | Slots | 196 | 320 | 372 | 388 | 420 | 472 |
| 12 | Joins | 49 | 75 | 86 | 90 | 97 | 110 |
| 14 | Groups | 5 | 19 | 25 | 26 | 29 | 40 |
| 14 | Slots | 20 | 80 | 108 | 116 | 132 | 188 |
| 14 | Joins | 5 | 19 | 25 | 26 | 29 | 40 |
| 15 | Groups | 0 | 9 | 13 | 15 | 17 | 24 |
| 15 | Slots | 0 | 40 | 60 | 64 | 80 | 108 |
| 15 | Joins | 0 | 9 | 13 | 15 | 17 | 24 |
| 16 | Groups | 0 | 5 | 8 | 9 | 10 | 18 |
| 16 | Slots | 0 | 20 | 32 | 36 | 48 | 84 |
| 16 | Joins | 0 | 5 | 8 | 9 | 10 | 18 |

## Actual joint query workloads

Every occurrence and every candidate contributes independently, including repeated
bucket accesses. `DistinctBuckets` counts accessed IDs, including an empty bucket.
`Reuse=Routes/DistinctBuckets`. The sum of distinct counts is per-query summed,
not a global deduplicated count; sum of reuse factors is descriptive only.

| bits | field | min | p50 | p90 | p95 | p99 | max | sum |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | Routes | 1 | 10 | 404 | 1215 | 10644 | 38240 | 466105 |
| 8 | GroupComparisons | 1129 | 12217 | 490140 | 1472323 | 12912551 | 46365989 | 565058267 |
| 8 | TouchedSlots | 4720 | 51620 | 2082312 | 6246124 | 54813704 | 196830440 | 2398498400 |
| 8 | DistinctBuckets | 1 | 10 | 204 | 254 | 256 | 256 | 51319 |
| 8 | Reuse | 1 | 1 | 2.0299 | 4.8406 | 41.5781 | 149.3750 | 2686.9827 |
| 10 | Routes | 1 | 10 | 404 | 1215 | 10644 | 38240 | 466105 |
| 10 | GroupComparisons | 249 | 3057 | 122464 | 367188 | 3229678 | 11593270 | 141268286 |
| 10 | TouchedSlots | 1044 | 12988 | 520744 | 1558572 | 13705420 | 49203580 | 599611016 |
| 10 | DistinctBuckets | 1 | 10 | 333 | 706 | 1024 | 1024 | 104000 |
| 10 | Reuse | 1 | 1 | 1.3333 | 1.7564 | 10.3945 | 37.3438 | 1400.5299 |
| 12 | Routes | 1 | 10 | 404 | 1215 | 10644 | 38240 | 466105 |
| 12 | GroupComparisons | 52 | 771 | 30810 | 92122 | 806740 | 2896716 | 35310832 |
| 12 | TouchedSlots | 232 | 3236 | 130800 | 390760 | 3422032 | 12298824 | 149892892 |
| 12 | DistinctBuckets | 1 | 10 | 378 | 1053 | 3814 | 4096 | 186981 |
| 12 | Reuse | 1 | 1 | 1.1722 | 1.3333 | 2.7908 | 9.3451 | 1100.7413 |
| 14 | Routes | 1 | 10 | 404 | 1215 | 10644 | 38240 | 466105 |
| 14 | GroupComparisons | 10 | 194 | 7587 | 23148 | 202023 | 723176 | 8831239 |
| 14 | TouchedSlots | 40 | 820 | 32332 | 97884 | 857220 | 3072020 | 37503460 |
| 14 | DistinctBuckets | 1 | 10 | 400 | 1165 | 7901 | 14668 | 304679 |
| 14 | Reuse | 1 | 1 | 1.0403 | 1.2000 | 1.3926 | 2.8190 | 1035.0412 |
| 15 | Routes | 1 | 10 | 404 | 1215 | 10644 | 38240 | 466105 |
| 15 | GroupComparisons | 4 | 98 | 3802 | 11596 | 101375 | 360977 | 4418057 |
| 15 | TouchedSlots | 16 | 416 | 16244 | 49096 | 430304 | 1531388 | 18752708 |
| 15 | DistinctBuckets | 1 | 10 | 402 | 1184 | 9155 | 22347 | 358355 |
| 15 | Reuse | 1 | 1 | 1.0203 | 1.2000 | 1.3492 | 2.0070 | 1026.3051 |
| 16 | Routes | 1 | 10 | 404 | 1215 | 10644 | 38240 | 466105 |
| 16 | GroupComparisons | 0 | 49 | 1908 | 5745 | 50754 | 180227 | 2209949 |
| 16 | TouchedSlots | 0 | 212 | 8032 | 24444 | 215484 | 764768 | 9380900 |
| 16 | DistinctBuckets | 1 | 10 | 402 | 1192 | 9879 | 28365 | 396523 |
| 16 | Reuse | 1 | 1 | 1.0122 | 1.2000 | 1.3333 | 1.6417 | 1022.3444 |

Bucket data may be cached on repeated access, but a different route has a different
private comparison input. Cache reuse cannot eliminate its equality evaluations.

## Static storage and leakage

| bits | B | nonempty | groups | real | padded | dummy | padding ratio | header bytes/party | CS0 bytes | CS1 bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | 256 | 256 | 310331 | 480945 | 1317260 | 836315 | 2.7389 | 3654 | 28299950 | 28299950 |
| 10 | 1024 | 1024 | 310331 | 480945 | 1317260 | 836315 | 2.7389 | 14406 | 28310702 | 28310702 |
| 12 | 4096 | 4096 | 310331 | 480945 | 1317260 | 836315 | 2.7389 | 57414 | 28353710 | 28353710 |
| 14 | 16384 | 16384 | 310331 | 480945 | 1317260 | 836315 | 2.7389 | 229446 | 28525742 | 28525742 |
| 15 | 32768 | 32765 | 310331 | 480945 | 1317260 | 836315 | 2.7389 | 458780 | 28755076 | 28755076 |
| 16 | 65536 | 64902 | 310331 | 480945 | 1317260 | 836315 | 2.7389 | 908698 | 29204994 | 29204994 |

Index binary v1 has a 70-byte fixed header, 14 bytes per NONEMPTY bucket,
36 bytes per group (local point32 + PadWidth4), and 13 bytes per padded slot
(Ring64 ID8 + Ring32 position4 + F2 validity1). The exact file size is
`70 + 14*nonempty + 36*groups + 13*slots`; public JSON manifests are separate.
A sparse directory is used; empty bucket headers are not serialized.
Global payload BucketShare storage is uint16 at every width, so it adds no
width-dependent storage increase. Public JSON manifests are additional small
files; their exact final lengths are recorded in phase7b-artifact-files.json.
Each party's layout has identical size. All six rows use the same concrete v1
encoding formula; final k=16 lengths are measured and round-tripped on disk.
The six layouts are NOT all claimed to have been serialized/materialized.

k14→k15 adds 229334 bytes/party; k15→k16 adds 449918 bytes/party.
k14→k16 adds **679252 bytes/party, 1358504 bytes for both (1.296 MiB)**.
Padding ratio is padded/real=2.738899; dummy/real=1.738899 (173.8899% overhead).
The public bucket ID reveals respectively 8/10/12/14/15/16 bits of keyed access
pattern. Larger widths distinguish finer buckets. This states the leakage;
it does not assign an abstract privacy value to the additional bits.

## PE projection boundary

**PROJECTED FROM VALIDATED PE BENCHMARK — NOT INTEGRATED MEASUREMENT.**
The old standalone `boolean_equality_audit` was already available under /tmp;
its source hash matches the read-only old source:
`1eefbb407b9e1cfdaa5e9ac6553f3bd3d69957c2f9ec76d52424020a6f33357d`.
Five reruns at 256 bits, 100000 comparisons, one worker/party, all errors=0.
It has 255 AND gates and 8 Boolean rounds. Raw outputs are saved in
`phase7b-pe-reference.jsonl`. No PE source or runtime was migrated.

Median both-party local work normalized by batch size: **121.410710 ns/comparison**.
This is a normalization of a single batch size, not a proven linear latency model.
Therefore **query PE compute latency is deliberately not extrapolated**.
Option4 point subtraction/canonical encoding, routing, input sharing, network
latency, and memory effects are not included in that local primitive number.

For the explicit hypothetical policy of ONE bit-sliced batch per query, with G
comparisons, Boolean openings send `8160*ceil(G/64)` bytes in both directions.
The future private-input share adapter adds `64*G` bytes. The benchmark's 100000
comparison tree sent 12754080 bytes total; the adapter is separate. The projection
table gives both parts and their sum. Different per-bucket batching changes the
rounding overhead. These are projected wire payloads, not current routing traffic.

## Position projection boundary

**PROJECTION FROM EXISTING REAL LLAMA BENCHMARK — NOT INTEGRATED MEASUREMENT.**
Read-only `results/target_position_real_benchmark.csv`: Villesse, workers=1,
30 runs, skip_invalid=0, slots=116991, SCMP evals=233982, errors=0,
`pos_scmp_ms=70.615`. Source merge uses max(CS0,CS1) local duration; normalization
is 0.603593 us/slot (two comparisons), not the sum of the two servers.
This projects only local interval SCMP work, not a completed Target Position
Filter or its Boolean conjunctions. Historical smaller cases have different
normalized rates, so the estimate is a workload sizing model, not a latency promise.

Current verified Bin7/Bout1 key material is 284 bytes/comparison/party
(also preserved from PHASE5 native component evidence). Two bounds give
568 bytes/slot/party, 1136 bytes/slot for both. For independent masked lower/upper
positions and one threshold pair per route, compact 7-bit-as-byte openings are
`4*(S+R)` bytes both directions (S=touched slots, R=routes), excluding framing.
The threshold-sharing/batching policy is an explicit projection assumption;
no Target opening codec or Position runtime is implemented this phase.

| bits | projected quantity | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| 8 | PE_AND_tree_online_bytes | 1558560 | 187728960 | 1646353440 |
| 8 | PE_Option4_input_share_bytes | 781888 | 94228672 | 826403264 |
| 8 | PE_total_online_bytes | 2340448 | 281957632 | 2472756704 |
| 8 | Position_SCMP_local_ms | 31.1575 | 3770.1195 | 33085.1921 |
| 8 | Position_SCMP_keys_bytes_both | 58640320 | 7095596864 | 62268367744 |
| 8 | Position_masked_open_bytes_both | 206520 | 24989356 | 219297392 |
| 10 | PE_AND_tree_online_bytes | 391680 | 46822080 | 411786240 |
| 10 | PE_Option4_input_share_bytes | 195648 | 23500032 | 206699392 |
| 10 | PE_total_online_bytes | 587328 | 70322112 | 618485632 |
| 10 | Position_SCMP_local_ms | 7.8395 | 940.7438 | 8272.5016 |
| 10 | Position_SCMP_keys_bytes_both | 14754368 | 1770537792 | 15569357120 |
| 10 | Position_masked_open_bytes_both | 51992 | 6239148 | 54864256 |
| 12 | PE_AND_tree_online_bytes | 106080 | 11750400 | 102864960 |
| 12 | PE_Option4_input_share_bytes | 49344 | 5895808 | 51631360 |
| 12 | PE_total_online_bytes | 155424 | 17646208 | 154496320 |
| 12 | Position_SCMP_local_ms | 1.9532 | 235.8602 | 2065.5161 |
| 12 | Position_SCMP_keys_bytes_both | 3676096 | 443903360 | 3887428352 |
| 12 | Position_masked_open_bytes_both | 12980 | 1567900 | 13730704 |
| 14 | PE_AND_tree_online_bytes | 32640 | 2953920 | 25761120 |
| 14 | PE_Option4_input_share_bytes | 12416 | 1481472 | 12929472 |
| 14 | PE_total_online_bytes | 45056 | 4435392 | 38690592 |
| 14 | Position_SCMP_local_ms | 0.4949 | 59.0821 | 517.4124 |
| 14 | Position_SCMP_keys_bytes_both | 931520 | 111196224 | 973801920 |
| 14 | Position_masked_open_bytes_both | 3320 | 396352 | 3471456 |
| 15 | PE_AND_tree_online_bytes | 16320 | 1485120 | 12925440 |
| 15 | PE_Option4_input_share_bytes | 6272 | 742144 | 6488000 |
| 15 | PE_total_online_bytes | 22592 | 2227264 | 19413440 |
| 15 | Position_SCMP_local_ms | 0.2511 | 29.6340 | 259.7287 |
| 15 | Position_SCMP_keys_bytes_both | 472576 | 55773056 | 488825344 |
| 15 | Position_masked_open_bytes_both | 1700 | 201200 | 1763792 |
| 16 | PE_AND_tree_online_bytes | 8160 | 734400 | 6479040 |
| 16 | PE_Option4_input_share_bytes | 3136 | 367680 | 3248256 |
| 16 | PE_total_online_bytes | 11296 | 1102080 | 9727296 |
| 16 | Position_SCMP_local_ms | 0.1280 | 14.7542 | 130.0647 |
| 16 | Position_SCMP_keys_bytes_both | 240832 | 27768384 | 244789824 |
| 16 | Position_masked_open_bytes_both | 892 | 102552 | 904512 |

## Recommendation

**RECOMMENDED TargetBucketBits=16, B=65536.**

| bits | G p50 | G p95 | G p99 | S p50 | S p95 | S p99 |
| --- | --- | --- | --- | --- | --- | --- |
| 8 | 12217 | 1472323 | 12912551 | 51620 | 6246124 | 54813704 |
| 10 | 3057 | 367188 | 3229678 | 12988 | 1558572 | 13705420 |
| 12 | 771 | 92122 | 806740 | 3236 | 390760 | 3422032 |
| 14 | 194 | 23148 | 202023 | 820 | 97884 | 857220 |
| 15 | 98 | 11596 | 101375 | 416 | 49096 | 430304 |
| 16 | 49 | 5745 | 50754 | 212 | 24444 | 215484 |

k15→k16 reduces query p95/p99 GroupComparisons by 50.46%/49.93%, and TouchedSlots by 50.21%/49.92%.
The primitive work/communication and Position sizing projections fall accordingly,
while total extra index data is only 899836 bytes for both parties. It reveals
one additional bucket-ID bit relative to k15. This meets the requested selection
rule. No width above16 was examined.

## Final materialization, integrity and reconstruction

Logical build+crypto: **11.172237s**; sharing/padding: **15.420653s**; in-memory Build: **26.592892s**.

Build sampled heap peak (10ms): **306432264 bytes**.
Build-end VmHWM: **323956 kB**.
Build-end VmRSS: **323956 kB**.
Build-end VmSwap: **0 kB**.

Build plus file encoding, full byte-for-byte codec roundtrip and manifest write: **31.617009s**; this explicitly includes codec validation work.
The /usr/bin/time log additionally reports the whole test process RSS, including
later trusted oracle validation, separately from the build-end high-water above.
No process swaps were reported. These measurements ran alongside the necessary
native workload replay, not on an isolated idle host.

All 310331 group points and all 480945 real + 836315 dummy slots reconstructed
correctly. Additionally sampled WITHOUT replacement 10000 real slots, 10000 dummy
slots and 10000 groups; all passed. Every group's stored bucket was independently
checked through canonical KBucketJoin XOR KBucketWord; maximum real group=16.
The tier ladder remains 4/16/64/256/1024/4096/8192/16384; only4 and16 are used.
The exact party schema allow-list and full binary roundtrip passed. Party files
contain only local shares, PadWidth and public bucket metadata, never plaintext
join IDs, qgrams, full T, or peer shares.

Final artifact directory: `artifacts/phase7b/`. Public manifest contains IndexID,
version1, Q4, independent Anchor/Target widths, all8 tiers, dimensions, file
lengths and SHA256 digests. Large .bin files are present locally and git-ignored;
manifests, hashes, experiment code and audit evidence are committed.
Each cloud receives ONLY its respective cs0/cs1 file, never the whole directory.

`BuildFinalTarget` has no width argument. `targetrouting.LoadIndex` loads and
validates the final manifest into an opaque BoundIndex; its Prepare method uses
that bound width, rejecting old8-bit token/payload bindings. Generic Build and
routing primitives remain available for historical controlled experiments.
No caller-selectable width is accepted by the final artifact entry points.

120071 global payload tuples were freshly provisioned through the existing
PHASE5 GeneratePayload API at the final width. Every reconstructed KJoin and
BucketJoin was audited; KJoin's definition is unchanged. Their v1 codec uses
46 header bytes +42N=5043028 bytes/party; LayoutID and IndexID are bound in the
header, with separate payload-manifest hashes. This is a NEW offline LayoutID;
it must be provisioned with its matching PHASE5 alignment using the existing
DealerLayout mechanism, and must never be attached to old Keep/gamma state.
No previously persisted PHASE5 alignment was available or relabelled, and no
PHASE5 online protocol was modified. The audit regenerates and validates this
payload material, not a full persistent Anchor alignment artifact.

The 1003-query final regression selects these shares in the saved replay's
candidate order, retains its CompactionID association, generates final-width user
tokens, and executes the unchanged party-local routing and bucket opening.
All **466105 routes** pass bucket/Y/share association oracles; the **2554** pairs
whose group exists point to the actual materialized bucket. Absent groups are
checked as negative routes, not incorrectly claimed to exist in the index.
K=0 and wrong-width rejection also pass. Full Y/T reconstruction occurs ONLY
inside the trusted test oracle; neither production party reconstructs either.

## Gates and frozen status

`gofmt`, `go test ./...`, `go vet ./...`, `git diff --check`: PASS.
Additional race tests for indexbuild/targetartifact/targetrouting: PASS.
No production concurrency was added; the memory sampler is test-only.
The four engineering documents are updated. Paper modified=NO.

TargetBucketBits=16; Target B final choice=FROZEN; PSMJ=SEALED.
PHASE5=SEALED; Candidate Compaction=COMPLETE; Private Routing=COMPLETE.
Target Private Equality/Position/Aggregation started=no.
