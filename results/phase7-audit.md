# PHASE 7 — private Target routing audit

Begin HEAD: 24f863d8ef057fb37f8f0fa427f85f36e2a59420, clean.
Target repo: /home/tenggn/projects/pmeq-clean. Old repo: read-only.
PHASE5 remains SEALED; Candidate Compaction remains COMPLETE.

## Target bucket configuration

There is no single frozen production TargetBucketBits and no persistent clean
PSMJ artifact/manifest file. `indexbuild.Build` explicitly accepts separate
anchorBits and targetBits and returns `PublicMetadata.TargetBucketBits`.
The full, materialized and correctness-validated setting recorded in PHASE3C3
and `internal/indexbuild/full_validation_test.go:TestFullMusicBrainzValidation`
is Target bits=8 / B=256. The later bits=16 Target figures are layout analysis
(`AnalyzeTierLayout`), not another complete materialization. PHASE5 froze only
Anchor bits=16, not Target bits.

This phase keeps the production interface parameterized (1..16), independently
of Anchor width. Real integration materializes all PSMJ aliases at bits=8, with
BSMJ Anchor bits=16. Target B final choice = OPEN. No implicit assignment from
AnchorBucketBits, automatic bucket-count change or bit truncation is performed.

`targetrouting.FromMetadata(IndexID, PublicMetadata)` creates the trusted
manifest binding. IndexID is supplied by the trusted artifact/config owner;
this is not an implemented signed/persistent manifest format. Tokens, local
candidate metadata and peer bucket messages must agree with the local manifest.

A necessary handoff fix: PHASE6's old convenience constructor still defaults
to 16 bits, but `PreprocessCompactionWithBucketBits` now generates masks in the
explicit selected XOR domain, validates input shares and labels its output
`TargetBucketBits`. This prevents 8-bit inputs from acquiring unconstrained
upper mask bits through the old 16-bit compaction default. The permutation and
product-group equations are unchanged. Integration supplies independently
DO-generated 8-bit global payload shares using the existing GeneratePayload
parameter. Existing 16-bit payloads cannot simply be relabeled for an 8-bit
index; routing rejects width mismatches. No PHASE5 production logic was changed.

`targetcrypto.BucketDomain` is a uint8 value type, preserving the package's
no-struct security gate. Its constructor/Validate/XOR/Open methods enforce the
width at each operation. Routing never implements its own raw XOR/truncation.
uint16 conversion in codecs is serialization only, after/before domain checks.

## Current call graph and schemas

Query User only:
`targetquery.GenerateTokens -> KWord -> FullEval -> SplitPoint`, and
`WordBucketComponent -> SplitBucketComponent`.
Q_target is split by rune positions 4*h into complete four-code-point chunks.
Trailing short fragments are dropped; repeated occurrences retain separate h,
position and fresh shares. Tokens are created before Anchor query execution;
there is no subsequent Query User call in routing.

One-party QueryToken:
`Manifest{IndexID[16],TargetBucketBits,Q=4}, QueryID[16], Party,
Words[]{OccurrenceID uint32, Position uint32, WordPointShare[32],
BucketWordShare uint16}`. It contains no text, qgram, master key, plaintext
scalar/bucket, or peer share. EncodeToken/DecodeToken are explicit codecs.

One-party Candidates is the PHASE6 handoff:
`LayoutID, CompactionID, TargetBucketBits, K, RecordIDShare[K],
KappaJoinShare[K], BucketJoinShare[K]`. The integration copies only typed
array references into this adapter. No global gamma or plaintext ID enters it.

One-party cloud path:
`targetrouting.Prepare(local manifest, party, local Candidates, local token,
workers) -> Pending + encoded bucket message -> Pending.Finish(peer bucket
message) -> RoutedCandidates`.

Output retains Manifest, LayoutID, CompactionID, QueryID, K,
AnchorRecordIDShare[K], Occurrences[r], Routes[K*r] in c*r+h order.
Each Route contains CandidateIndex, OccurrenceID, public BucketID and one Y
point share. Position is carried once in the occurrence table. RecordID shares
are copied once at top level, not per occurrence. c is meaningful only within
CompactionID. Output owns its arrays; consumed Pending releases its route and
bucket backing arrays. No point-share peer message exists.

## Algebra

P = FromUniformBytes(SHA512("PMEQ-TARGET-KHPRF-POINT-V1")), the existing
fixed targetcrypto base point (not the canonical generator).

User: kw=KWord(k_T,w); W=kw*P; W=W0+W1 by fresh point splitting.
User: bw=WordBucketComponent(k_T,w,k); bw=bw0 XOR bw1 by fresh XOR splitting.

For u in {0,1}:
J_u[c]=KappaJoinShare_u[c]*P, computed once per candidate.
Y_u[c,h]=J_u[c]+WordPointShare_u[h].
Thus Y0+Y1=(KJoin(k_T,j)+KWord(k_T,w))*P, equal to the existing
DeriveTargetGroupPoint and stored T0+T1 for a real logical group (j,w).

b_u[c,h]=BucketDomain.XOR(BucketJoinShare_u[c],BucketWordShare_u[h]).
The only server-server opening is BucketDomain.Open(b0,b1), giving
beta=beta_J XOR beta_w. Neither component is opened separately.

Production never reconstructs Y, kappa_J, kappa_w, beta_J, beta_w, j or gamma.
Only trusted `_test.go` oracles reconstruct output Y and stored T for checks.
No D0/D1 construction, point-difference equality encoding, 256-bit Private
Equality invocation, Target Position or Target Aggregation is implemented.

## Message and storage accounting

Actual query-token codec per party: 42-byte header + 42*r bytes.
Header = IndexID16 + bits1 + Q4 + QueryID16 + party1 + r4.
Occurrence = h4 + position4 + point-share32 + bucket-share2.
No qgram/string is encoded.

Actual server bucket codec per party for K*r>0:
82-byte header + 2*K*r bytes. Header is magic4 + party1 + bits1 + Q4 +
IndexID16 + LayoutID16 + CompactionID16 + QueryID16 + K4 + r4.
Payload is one LE16 local combined bucket share per pair, including when
Target bits=8; this implementation does not pack it into a byte.
Both directions total = 164 + 4*K*r bytes. For K*r=0 no message is generated,
no dummy candidate/J/Y/bucket access is performed, and server bytes=0.

Y shares NEVER count as server-server communication. PSMJ local bucket reads
are not network traffic; routing itself performs no bucket read or equality.
Token codecs and bucket codecs are exercised in correctness and timing tests;
reported sizes are actual serialized protocol message lengths, not TCP framing.

On measured amd64: Route size=44 bytes (including padding); routed header=152.
Both-party internal routed state = 304 + 16*K + 16*r + 88*K*r bytes.
This includes RecordID shares only once and the positions/occurrence table.
At K=4780,r=16: 76480 pairs, state=6,807,280 bytes, well below 12 GiB, so the
max-by-max case was actually measured. Temporary joins/word-point caches,
messages, GC retention and allocator overhead are separate from retained state.
Measured memory and timing are in phase7-results.md.

## Single-party view and leakage

CSu has only KappaJoinShare_u, BucketJoinShare_u, WordPointShare_u,
BucketWordShare_u, public beta, its own Yu and its own Anchor RecordID shares.
The trusted non-colluding/semi-honest model and independently domain-separated
keyed derivations are unchanged. Missing scalar/point/XOR shares remain hidden;
Y_u is a function solely of already-local shares. No peer point reaches the
server, so it cannot combine full Y. The word-point masks are fresh for every
occurrence/query, even when text repeats. Candidate shares/order are freshly
rerandomized by compaction and c has no stable cross-query identity.

Conditioned on the explicitly disclosed K,r,beta and public index/layout
dimensions, a simulator supplies independent local scalar/point/ID/component
shares and sets each peer bucket-message share to beta XOR the simulated local
combined bucket share. The local Y output follows from local arithmetic. Under
the keyed-derivation assumptions this introduces no additional plaintext j/w,
scalar or full-Y disclosure. This is a leakage-relative argument, not a claim
that disclosed buckets contain no information: bucket patterns reveal XOR
relations, collisions and potentially linkable public access patterns. Small
bucket components do not acquire 128-bit secrecy, and deductions from public
leakage/auxiliary knowledge are not claimed to be hidden.

Only public bucket-message headers and combined shares cross servers. Binding
checks reject wrong party, index/width, LayoutID, CompactionID, QueryID, K/r,
length and out-of-domain bucket shares before committing the opening. Tokens
reject noncanonical points, inconsistent occurrence/position and wrong manifest.
Bounded workers touch disjoint output ranges and read immutable input points;
opening, token generation and index access are not parallel routing jobs.
The host recommendation (16 workers) is measured, not a universal default.

## Old routing audit

- `dmpf_agg_proto/src/bin/khprf_psmj_route.rs` sends 32*N*r partial-point bytes
  from the left party; the right decodes them, calls combine(peer,own) and
  stores full tags in PMEQKO01. That is an OLD protocol, not migrated.
- `psmj/crypto.go` exposes KHPRFCombine, RoutingTag and HGroup; RoutingTag emits
  a complete point encoding. `cmd/target-e2e-bench/main.go` then calls RoutingTag
  and retired match.Gen. None of these functions is used by current routing.
- Repository-wide searches recovered no distinct H_route implementation to
  migrate. Old CWMatch/BFV/constant-weight paths are historical prose (also
  classified as zero implementation hits by CURRENT_PROTOCOL.md). No H_route,
  Target DPF or CW token is generated here.

Current output is exclusively public bucket placement plus party-local Y for
Option4 + future 256-bit Private Equality. The latter stage remains unstarted.

## Reproduction

Use Go 1.27.1. The existing external LLAMA test adapter is reused unchanged;
old sources/data are read-only and native artifacts stay in /tmp.

```
bash tools/build_phase6_native.sh
CGO_LDFLAGS=/tmp/phase6-native/libphase6scmp.a PMEQ_AGG_FULL=1 \
  go test -tags 'phase6native phase7integration' ./internal/aggregation \
  -run '^TestReal1000Queries$' -count=1 -v -timeout=120m
PMEQ_ROUTING_BENCH=sweep go test ./internal/targetrouting \
  -run '^TestRoutingBenchmarks$' -count=1 -v
PMEQ_ROUTING_BENCH=grid PMEQ_ROUTING_WORKERS=16 go test ./internal/targetrouting \
  -run '^TestRoutingBenchmarks$' -count=1 -v
go test ./...
go vet ./...
go test -race -timeout=60m ./...
git diff --check
```

PMEQ_ROUTING_SKIP_GROUPS=1 only skips the separate 100k group suite when it has
already passed; it does not skip PSMJ materialization, all-group validation or
any real query. Anchor query seed=502. Negative alias selection uses a seed-707
shuffled normal-alias catalog, with rejection of candidate-related areas.
Positive/repeated fixtures are selected before Anchor execution using only the
trusted test oracle. The initial prefix run completed the 100k suite; the final
1000-query run uses the explicitly seeded negative sampler. It is the final run
that supplies real-query totals; incomplete prefix queries are not counted.

Paper modified=NO. Query-time party DO/raw DB access=no. Query User is offline
after initial token. Full Y never reconstructed in production.
