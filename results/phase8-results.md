# PHASE8 — Target 256-bit Private Equality

Begin HEAD `e22a54ecbceb048c774d9130f26ce3bd9c7e8e2b`, clean. Single commit:
`phase 8: add target private equality`. Old repository read-only; paper unchanged.

## Manifest, structure, lineage

The actual PHASE7B sealed files are loaded, never replaced/rebuilt. Their
IndexID/version1/Target bits16/Q4/8 tiers and own file SHA256/lengths are checked.
Both own global payload hashes/headers are checked as well. All65536 buckets are
scanned for GroupCount and ordered PadWidth; public structure digests agree.
No secret T share is compared in that public audit. Sealed owner file hashes
pin the actual group ordinals; the trusted oracle separately confirms their
logical identities. Every online frame binds the public structure digest.

PHASE7B had generated a new payload LayoutID but did NOT persist matching Anchor
alignment. This phase restores DealerLayout from the SAME sealed payload inside
trusted offline setup, before any PHASE5 Alignment call. It verifies all120071
record memberships, then the existing alignment protocol uses that layout.
Production Load requires trusted alignment lineage to match the payload manifest;
Begin asserts the routed LayoutID matches it. Wrong lineage/index/width fails.
`artifacts/phase8/alignment-lineage.json` records public provenance, not a claim
that all Anchor alignment/permutation files are now persisted.

## Input proof and legacy audit

D0=Y0-T0, D1=T1-Y1; D0=D1 iff Y0+Y1=T0+T1. Canonical Ristretto encoding is
injective, including identity. E0/E1 are exactly32 bytes; no hash/truncation or
scalar reinterpretation. The party0 initial share is1 XOR E0_i and party1's is
E1_i; XOR is1 XOR E0_i XOR E1_i. AND of256 such bits is equality.
**Old input adapter required=NO. Input communication=0.** Initial input shares
need not be freshly randomized: each is determined only by its owner's already
private input. Fresh independent gate triples hide every online d/e opening.
See phase8-design.md, written before implementation, for the formal algebra.

The existing clean f2beaver package is extended to packed independent F2 lanes.
Its scalar and packed paths call ONE common Finish formula:
`c_u XOR(d&b_u) XOR(e&a_u) XOR([u=0] d&e)`.
No second Beaver protocol or old production runtime was introduced.102400 packed
lanes pass differential against the existing scalar API and independent product
truth, in addition to the existing100000 scalar tests.

## Batching, lifecycle, output

Flatten public route order, then bucket group ordinal. W=ceil(G/64). Arrays are
bit-major: bit*W+word, with comparison i in word i/64, lane i%64.8 balanced layers
have128/64/32/16/8/4/2/1 gates; exactly255W triple words are consumed. Unused lanes
are zero at input and masked at final output; they never enter MatchShares.

Each party sends d/e uint64 words:16 bytes per gate-word,32 both directions.
Actual codec payload sums to8160W, with no +64G adapter. Each frame has62 bytes
(magic8, public binding digest32, packetID16, party1, round1, count4),16 frames
per nonempty query=992 bytes. G=0 has zero triple words/messages/framing.

Triples are ONE-TIME Q_pool data:6120W bytes/party,12240W combined. Fixed packet
metadata/Go allocator overhead is separate, not an offline wire-format claim.
Packet capacity can upper-bound actual G: use the255W prefix and burn the whole
packet, including unused capacity. No query-time DO fallback. The1003-query test
prepares all packets before any query using published workload capacities;
production can use public upper bounds without anticipating a private query.
A copied packet shares the same consumption guard. Reuse, cross-binding, wrong
party/round and malformed frame shapes are rejected.

TargetGroupMatches carries Manifest, LayoutID, CompactionID, QueryID, K,
Occurrences (including Position), AnchorRecordIDShare[K], route descriptors
(CandidateIndex, OccurrenceID, BucketID, MatchOffset, GroupCount), and F2
MatchShares[G]. IDs are retained once at top level. No D/E/peer value, Y/T, or
plaintext group identity/hit is output. No group result is opened in production.

## Correctness

100000 equal and100000 unequal Option4+PE cases: false negative=0, false positive=0.
Tests also cover same join/different word, different join/same word, both different,
repeated word occurrences, zero scalar, identity point, canonical roundtrip,
malformed encoding, zero routes/empty buckets, lane boundaries63/64/65/129,
all worker counts, one-use packets, capacity prefixes and lineage/hash corruption.
Old standalone vs current:100000 identical shared inputs/results, errors=0.

The native full chain executes actual Anchor DPF/LLAMA Position/incidence/
aggregation/Keep, fresh compaction, routing, sealed PSMJ lookup, Option4 and PE.
It uses the same seed502 workload and saved PHASE7B Target query texts. Query
User tokens are created at query start; correctness oracle inputs never become
PE inputs. Raw aliases are read ONLY by the trusted oracle; the Target index
is read exclusively from sealed files. Protocol parties do not contact DO/DB.

Queries=1003; routes=466105; total comparisons=2209949.
Positive group matches=2554; zero-match routes=463551; one-match routes=2554;
>1-match routes=0; errors=0. All hit counts are trusted-test-only reconstruction.
G: min0, p50=49, p90=1908, p95=5745, p99=50754, max180227, derived from this replay
and identical to PHASE7B. K/r/route metadata and candidate ID association are
preserved in the output. Whole native log is phase8-real.txt.

## Actual component timings

Intel Core i9-14900HX,32 logical CPUs, Go1.27.1, linux/amd64. Shared host with
native correctness/race jobs; these are NOT isolated-host or TCP E2E latencies.
Both parties' local times are summed. Index files are verified/loaded once;
query A includes in-memory bucket group-share access and point processing,
not disk loading. A=local D construction+canonical encoding (including validation);
B=input bit slicing+Boolean local compute; C=8 rounds encode/decode/opening
processing; D=output/route layout writes; E=per-trial A+B+C+D. Independent
percentiles are not added. Every trial uses fresh triples; preprocessing excluded.
10 warmup/50 measured; max G180227 uses5 warmup/20 measured due actual cost.
All fixtures correspond to real saved query G values and current sealed shares.

| G | W | A ms p50/p95 | B ms p50/p95 | C ms p50/p95 | D ms p50/p95 | E ms p50/p95 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | 0.051/0.131 | 0.021/0.039 | 0.016/0.045 | 0.012/0.024 | 0.102/0.215 |
| 49 | 1 | 2.233/2.438 | 0.058/0.073 | 0.016/0.024 | 0.017/0.042 | 2.329/2.521 |
| 1908 | 30 | 81.643/90.347 | 1.636/1.743 | 0.122/0.177 | 0.181/0.212 | 83.608/92.276 |
| 5745 | 90 | 247.458/263.030 | 4.885/5.311 | 0.323/0.490 | 0.456/0.643 | 253.131/268.914 |
| 50754 | 794 | 2077.592/2841.175 | 41.148/57.320 | 2.578/3.897 | 3.404/4.422 | 2128.903/2908.011 |
| 180227 | 2817 | 7546.574/8117.393 | 158.249/178.969 | 19.527/23.932 | 13.305/15.286 | 7738.223/8329.451 |

## Worker sweep

8 sequential Boolean rounds are retained at every worker count. Only independent
packed work is partitioned, with simple bounded goroutines. D/encoding is serial.

| G | workers | B ms p50/p95 | E ms p50/p95 |
| --- | --- | --- | --- |
| 50754 | 1 | 41.307/51.736 | 2136.159/2306.030 |
| 50754 | 4 | 14.388/17.997 | 2068.824/2158.128 |
| 50754 | 8 | 13.738/16.116 | 2172.860/2859.327 |
| 50754 | 16 | 11.947/13.823 | 2145.758/2404.567 |
| 180227 | 1 | 142.105/157.126 | 7082.242/7224.169 |
| 180227 | 4 | 48.752/53.460 | 7002.873/7392.618 |
| 180227 | 8 | 43.459/48.086 | 6272.771/7301.370 |
| 180227 | 16 | 39.800/43.963 | 6256.211/6311.882 |

**Chosen default workers=1.** Packed computation improves with parallelism, but it
accounts for only about2% of the total component cost at p99/max; its elimination
would improve the whole component by only about2%. The default follows the
allowed conservative choice when total gains are small. The sweep transparently
reports faster packed-loop configurations; it does not claim one worker is the
fastest packed loop. Between-run A variation on the shared host is not attributed
to Boolean parallelism. All1/4/8/16 implementations pass correctness tests.

## Bytes and memory

All quantities below combine both parties except `offline/party`.
Offline rows are exact-size capacities; a larger reserved packet costs more
material even though only the actual255W prefix is used. Online excludes992
bytes framing. The temporary E arrays use32G bytes/party; D points are transient
per-comparison objects, not a retained G-point array. Other buffers and allocation
effects are captured by sampled online heap deltas. MatchShares are1 byte/share
in the current Go representation, G bytes/party, excluding route metadata/IDs.
Heap delta is sampled after protocol phases, max across trials including warmup,
relative to the post-preprocessing baseline; it is not continuous heap high-water.
RSS is the end-of-case process RSS (both parties plus static fixtures/runtime),
and HWM is the process cumulative RSS high-water, not a per-server claim.

| G | W | offline/party | offline both | online payload | E buffers both | Match both | heap delta | RSS KiB | HWM KiB | adapter savings |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 49 | 1 | 6120 | 12240 | 8160 | 3136 | 98 | 44816 | 140628 | 176896 | 3136 |
| 5745 | 90 | 550800 | 1101600 | 734400 | 367680 | 11490 | 3743408 | 143956 | 176896 | 367680 |
| 50754 | 794 | 4859280 | 9718560 | 6479040 | 3248256 | 101508 | 33489088 | 194916 | 197340 | 3248256 |
| 180227 | 2817 | 17240040 | 34480080 | 22986720 | 11534528 | 360454 | 118527680 | 277192 | 292708 | 11534528 |

The PHASE7B projection was8160W+64G; actual PE payload is8160W. Savings are
exactly64G bytes, independently verified by the current codec. Framing is
reported separately rather than subtracted from the historical payload model.

## Old standalone reference

Original source SHA256:1eefbb407b9e1cfdaa5e9ac6553f3bd3d69957c2f9ec76d52424020a6f33357d.
It was rebuilt ONLY under /tmp, with optional input/result vector export. Five
100000-comparison/256-bit/one-worker runs all have0 errors,255 AND and8 rounds.
No old full-Y or Target DPF path was called. Source is not copied into production.

Old median both-party Boolean compute: 13.671644 ms per100000 comparisons; sent payload=12754080 bytes.
Old timing starts with already bit-sliced inputs; its loopback wall time is not
compared with current local component sums. Current differential on the identical
100000 cases separately logs input packing, Boolean compute and message handling
in phase8-differential.txt. That is a single audit run, not a percentile benchmark.
Current B above includes input packing, explaining a materially different scope.
The PHASE7B normalized primitive estimate excluded D/encoding and packing; it
must not be presented as an integrated query latency estimate.

## Single-party security and gates

CSu holds only its Y_u/T_u/D_u/E_u, local triple shares, masked openings and its
output MatchShare_u, plus existing public bucket/dimensions. D/E are deterministic
functions of already held local shares. Fresh independent triples simulate the
masked openings under the existing trusted-dealer, semi-honest/noncolluding model;
composition leaves the final hit XOR-shared. No full Y/T, peer D/E, join value,
qgram or plaintext match is given to either cloud. G/offsets are determined by
already public beta/group dimensions. This is not a malicious-security proof
and does not hide the existing bucket access pattern.

Final gofmt, go test ./..., go vet ./..., go test -race -timeout=60m ./...,
native-tag vet and git diff --check PASS. No short/reduced100k race test mode.
The four required engineering documents are updated. No sealed PHASE7B artifact,
KHPRF, q/tier/bucket parameter or PHASE5/6/7 protocol semantics were changed.

TargetBucketBits=16; Target B=FROZEN; PSMJ=SEALED; PHASE5=SEALED;
Candidate Compaction=COMPLETE; Private Routing=COMPLETE;
Target Private Equality complete=YES. Production full Y reconstructed=NO;
group Match opened=NO. Target Position/Target Aggregation/Candidate ID Generation
started=no; query-time DO=no; paper modified=no.
