# PHASE9 — Target Position Filtering

Begin HEAD `bd84b29eec8911e2dc64c1118623dbb4529b3d15`, clean.
One authorized commit: `phase 9: add target position filtering`.
Old repository read-only. PHASE7B sealed files and all mathematical/index
parameters unchanged. No paper file changed.

## PHASE4 reuse audit

Anchor Position reusable=YES. QueryToken extension=YES.
The traced chain is anchorquery.MakeOccurrence -> UserPreprocessing.ConsumeBounds
-> PartyQuery masked bounds; trusted anchorfilter.Preprocess -> per-party rho,
Lower/Upper opaque SCMP keys and rb; ReducePosition -> masked p+rho opening ->
anchorfilter.EvalPosition -> local rb removal -> interval XOR -> F2 Beaver.
The Anchor ComposeHits coordinator calls Match AND Validity then AND Position;
Target uses the specified equivalent association Match AND Position then AND
Validity. Both use the existing f2beaver Mask/Finish and its sole party0 d&e term.
The helper BatchAND itself is a trusted harness that creates triples, so production
Target uses preallocated PartyBatch slices and party-local calls instead.

Target calls the SAME PHASE4 EvalPosition, not a reimplemented comparator or rb
formula. The timed backend only delegates Eval to existing scmpnative.Backend.
The C++ bridge and LLAMA source are unchanged. The active bridge calls
phase6_keygen/keyGenSCMP, with sysRandomSeed initialization; rho/eta and Beaver
material use Go crypto/rand. Historical seeded test wrappers are not this path.
Ordinary unit tests label their
insecure oracle comparator explicitly; it is never used in native performance
or the complete real replay.

## Initial token and offline lifecycle

QueryToken retains Manifest/QueryID/Party/Words. It adds Position[r], with each
PositionToken = PID[16], Ltilde(uint32), RplusTilde(uint32). OccurrenceID/Position
remain the already public PHASE7 occurrence fields. No tau, unmasked bound,
qgram, query string, kT or peer share is added. Query User holds per-occurrence
UserPreprocessing(PID,eta_L,eta_R), masks bounds before Anchor starts, then offline.

Each party's one-time Q_pool occurrence has PID, Bin7, rho_L/rho_R arrays, Lower/
Upper SCMPKeyShare arrays (opaque keys plus cached local rb), and two F2 triple
batches. Preprocess belongs to the trusted offline boundary, never called by
cloud Begin/Next/Accept. Capacity may upper-bound the actual public slot workload.
Unused capacity burns; copied packets share the single-use guard. Repeated bucket
accesses and repeated occurrences use distinct key/triple entries. The trusted
replay provisions from saved public workload capacities BEFORE initial tokens;
production can reserve public upper bounds without learning secret Match.

## Full-data bounds and correctness algebra

Full area_alias scan: records67896, indexed63849, short4047; maximum real posting
position62, maximum indexed rune length66, maximum normal qchunk position60.
Every sealed reconstructed slot position (including dummy zero) also satisfies
0<=p<=62. q=4 complete nonoverlapping code-point chunks preserve repeats.
Short strings remain OPEN; the new Position-token API returns explicit
ErrShortTarget rather than silently entering the normal qgram path. No fallback.

PHASE4 Upos=62, Bin7/Bout1: L=max(0,pQ-tau), R=min(62,pQ+tau), with PHASE4's
uint32 overflow saturation. For accepted pQ<=62, L/R in[0,62], R+1 in[1,63],
so both semantic differences lie in[-63,62], inside signed7 bits. Masked ring
values can span[0,127]; they are not plaintext signed positions. Full supported
uint32 tau clamping is retained. Actual saved tau family spans0..5; native tests
cover0/1/2/62/maxUint32 and all database positions0..62 at boundary query positions.
No automatic Bin expansion or new position semantics.

PosOK = correctedSCMP(p>=L) XOR correctedSCMP(p>=R+1).
A = GroupMatchSlot AND PosOK; Hit = A AND Validity.
All physical slots, real/dummy and matched/unmatched, execute2 SCMP comparisons
and2 fresh Beaver ANDs. No secret-dependent pruning occurs. Group share replication
is local. The native boundary/composition tests and complete trusted oracle cover
matched/failed positions, unmatched groups, dummy zero positions, repeats,
duplicate postings, boundaries and tau extremes. Errors=0.

## Sealed input and output coherence

The existing PHASE8 loader checks IndexID/version/Q4/TargetBucketBits16/tiers,
own PSMJ and payload hashes, and trusted final alignment lineage. The full65536
bucket public structure digest is retained. Target Begin also rejects mismatched
manifest/LayoutID/QueryID/CompactionID, wrong occurrence/route/group offsets,
missing Position tokens, wrong PID/party/capacity or reused packets. Online frames
bind the manifest/lineage/query/compaction/structure/route order and token PIDs.

TargetPostingHits = Manifest, LayoutID, CompactionID, QueryID, K,
Occurrences[r], AnchorRecordIDShare[K], Routes[] and HitShares[S].
Each route contains CandidateIndex, OccurrenceID, BucketID, SlotOffset, SlotCount,
Groups[] of GroupOrdinal, PadWidth, SlotRelativeOffset. HitShares follow exactly
route -> sealed group ordinal -> physical slot order. No sort/compaction/dummy
removal, target record ID, group identity or posting-record incidence is output.
This preserves the next-stage association without implementing aggregation.

## Full native MusicBrainz replay

Same1003 saved real queries, same Anchor seed/family and final PHASE8 lineage.
Actual Anchor -> Anchor Position -> Aggregation -> Keep -> fresh Compaction ->
Private Routing -> sealed PSMJ lookup -> Target PE -> Target Position -> Validity.
No oracle-created Match inputs and no query-time Target index rebuild.

Queries=1003; routes=466105; group comparisons=2209949;
physical slots=9380900; real Target hits=4144;
zero-hit queries=751; errors=0.
Whole-chain process peak RSS=4470688 KiB, swaps=0 (includes upstream phases).
All hit statistics are trusted-test-only reconstruction. Production never opens
Match, PosOK, Validity or Hit. The saved trace has59 repeated-qchunk queries.
Each of1003 S values was recomputed in this replay and compared element-by-element
against PHASE7B TouchedSlots, not merely against the reported percentiles.

| quantity | min | p50 | p90 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| S | 0 | 212 | 8032 | 24444 | 215484 | 764768 |
| SCMP comparisons | 0 | 424 | 16064 | 48888 | 430968 | 1529536 |
| F2 ANDs | 0 | 424 | 16064 | 48888 | 430968 | 1529536 |

## Real LLAMA component measurements

Intel Core i9-14900HX,32 logical CPUs, Go1.27.1, linux/amd64. Concurrent replay/
race workloads share the host; no isolated-host or TCP E2E latency claim.
Both parties' local times are summed. Representatives are actual saved queries
chosen by S (not independent K/r percentiles); their actual routing and Target PE
produce the benchmark Match inputs. Repeated isolated Position trials use fresh
keys/triples and fresh masked bounds. No test comparator generates timing data.
10 warmup/50 measured for p50/p95/p99; max5 warmup/20 measured.

A=public slot/output-structure expansion and masked-position body processing.
B=real LLAMA Eval calls. C=remaining PHASE4 EvalPosition, including rb correction,
conversion/allocation and timing-wrapper overhead. D=Match AND Position body
processing. E=Validity AND body processing. F=final HitShare writes.
G=per-trial A+B+C+D+E+F before taking percentiles. Offline generation, initial
token generation, static artifact load and frame-header/session housekeeping
are outside this component sum. This is explicitly a component sum, not full
transport/runtime wall time; communication accounting includes actual headers.

| S | A ms p50/p95 | B ms p50/p95 | C ms p50/p95 | D ms p50/p95 | E ms p50/p95 | F ms p50/p95 | G ms p50/p95 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 212 | 0.080/0.122 | 1.004/1.372 | 0.081/0.107 | 0.018/0.024 | 0.016/0.020 | 0.001/0.001 | 1.229/1.591 |
| 24444 | 5.107/6.354 | 94.908/116.807 | 6.196/8.119 | 1.555/2.011 | 1.380/1.788 | 0.096/0.142 | 109.250/134.050 |
| 215484 | 38.450/42.585 | 686.033/776.806 | 43.961/50.469 | 10.844/12.994 | 9.818/11.505 | 1.219/1.478 | 790.336/896.767 |
| 764768 | 109.552/125.281 | 2236.390/2462.448 | 145.315/160.632 | 36.572/43.821 | 33.480/39.186 | 3.332/4.420 | 2559.440/2828.257 |

## Offline and online bytes

Each serialized LLAMA key is284 bytes. Current party material also stores a
cached local rb byte per comparison and uint32 rho per comparison. Thus SCMP
key/mask body=2*(284+1+4)*S=578S bytes/party. Two scalar F2 triple shares cost6S
bytes/party. One-time body total=584S/party,1168S combined. Capacity overreservation
costs its reserved S, not only used slots. The table reports exact-size bodies.
Additional public field data: PID16+Bin1 per occurrence and lineage(40)+party1
per party packet; thus body plus these fields is584S+17r+41 per party. The Go
packet has no offline wire codec; slice/allocator/mutex overhead is not claimed
as serialized bytes and is reflected in RSS. Query User preprocessing has24r
bytes of PID/eta fields; initial Position token adds24r bytes per cloud before
framing. These are separate from the server-server online bytes.

Each party emits two uint32 masked-position shares per slot:8S,16S combined.
Each AND layer emits two1-byte F2 opening shares per party:4S combined;
two layers=8S. Online payload=24S both. Each nonempty route chunk has3 sequential
exchanges,6 messages,57-byte header each:342 bytes/chunk, where chunk count is
sum_routes ceil(route.SlotCount/1024). Empty routes emit no messages. Headers
are counted from actual codec output. Bucket reads and retained HitShares are
NOT server-server communication.

| S | r | SCMP/party | Beaver/party | body both | SCMP online both | AND online both | framing both | total online |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 212 | 1 | 122536 | 1272 | 247616 | 3392 | 1696 | 3762 | 8850 |
| 24444 | 3 | 14128632 | 146664 | 28550592 | 391104 | 195552 | 404928 | 991584 |
| 215484 | 4 | 124549752 | 1292904 | 251685312 | 3447744 | 1723872 | 3611178 | 8782794 |
| 764768 | 8 | 442035904 | 4588608 | 893249024 | 12236288 | 6118144 | 12944700 | 31299132 |

## Memory

Only final HitShares[S] and public route/group output layout persist at query
scale. Position, Match replication, A and validity buffers are bounded by a
1024-slot route chunk; there are no four full-S intermediate predicate arrays.
Consumed/unused one-time material is released after output. Static PSMJ remains
unchanged at29204994 bytes/party. The memory below is a dual-party test process.
Heap delta is sampled after protocol phases and every1024 messages, maximum
across trials including warmup relative to post-preprocessing allocation; it is
not a continuous heap high-water. The existing native adapter copies serialized
key bytes during each Eval, so cumulative allocations pending GC can exceed
the live chunk buffers; a small live chunk is not a small heap-delta guarantee.
RSS includes static fixtures and Q_pool material;
HWM is cumulative process high-water, not a per-server incremental bound.

| S | HitShares both bytes | sampled heap delta bytes | RSS KiB | HWM KiB |
| --- | --- | --- | --- | --- |
| 212 | 424 | 280288 | 147444 | 306944 |
| 24444 | 48888 | 32049408 | 296756 | 306944 |
| 215484 | 430968 | 284159760 | 729960 | 795588 |
| 764768 | 1529536 | 1009391376 | 2181700 | 2232744 |

## Single-party security and completion

CSu sees existing public beta/layout dimensions, its Match/Position/Validity shares,
its SCMP/Beaver material, masked openings and its Hit shares. Same PHASE4
trusted-dealer, semi-honest noncolluding assumptions apply. Fresh independent
rho/eta hide opened positions/bounds; SCMP output masking/correction follows
that existing primitive; fresh triples hide both AND openings. Public replication
and chunk scheduling add no secret branch. No plaintext match/predicate/validity/
hit, join value, qgram, target record identity or posting-record relation is
exposed. The leakage remains prior public access pattern/dimensions, including S.
This is not a claim of malicious security or hidden accessed buckets.

Gofmt, go test ./..., go vet ./..., go test -race -timeout=60m ./...,
native correctness, native-tag vet and git diff --check PASS.

Target B=65536; PSMJ=SEALED; Private Routing=COMPLETE;
Target Private Equality=COMPLETE; Target Position complete=YES.
Production group Match opened=NO; posting Hit opened=NO.
Target Aggregation started=no; Candidate ID Generation started=no;
final recovery started=no; query-time DO=no;
query-time Query User after initial token=no; paper modified=no.
