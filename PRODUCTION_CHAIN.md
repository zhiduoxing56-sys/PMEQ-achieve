# PMEQ Production Chain

## Sole Candidate Discovery production chain

IndexOutsource
→ Anchor Match
→ Anchor Position Filtering
→ Anchor Record Aggregation
→ Anchor Keep
→ Secure Candidate Compaction
→ KHPRF Private Routing
→ Target Private Equality
→ Target Position Filtering
→ Target Record Aggregation
→ Candidate ID Generation

## Current stage status

- **IndexOutsource:** PHASE 3C3 base builder implemented in memory for raw
  MusicBrainz `area`/`area_alias`: q=4 code-point postings, Anchor q-gram
  groups, Target `(joinID,qgram)` groups, party-local fresh shares, and frozen
  per-group tiers `{4,16,64,256,1024,4096,8192,16384}`. The uniform per-bucket
  maximum is experiment baseline only. Persistent format is not implemented.
- **Anchor Match:** 128-bit DPF is wired to tiered Anchor groups and replicated
  locally to their variable-width slots.
- **Anchor Position Filtering:** PHASE 4A foundation implemented. Query
  signatures are non-overlapping q=4 rune chunks; masked Ring32-to-Bin position
  inputs use the external validated LLAMA SCMP (`Bin=7`, `Bout=1`) boundary.
  Two batched F2 Beaver layers produce secret posting-hit shares. Native LLAMA
  remains external, and B2A belongs to PHASE 5.
- **Anchor Record Aggregation:** PHASE 5B2 implements the hidden-incidence,
  external SCMP, Z128 B2A, two-stage permutation and local count composition.
  PHASE 5B3 stores only a CS0-local rhoSeed and CS1 uint32 sigma per bucket;
  rho expands lazily for an accessed invocation. Q_pool is a finite offline
  one-use query-material budget, separate from reusable static state.
- **Anchor Keep:** masked external SCMP produces F2 Keep aligned with a
  DO-generated per-record global payload under the same LayoutID.
- **Candidate Compaction:** PHASE 6 migrates the audited two-stage hidden shuffle, opens shuffled Keep and retains exactly K local secret payloads.
- **KHPRF Routing:** PHASE 7 implements K*r routing with public Target buckets and party-local Y shares.
- **Target Private Equality:** OPTION 4 approved. The Target stored group key is
  the additive Ristretto255 point share pair `T = T0 + T1`; the future equality
  compares `Enc(Y0 - T0)` against `Enc(T1 - Y1)` under full-256-bit Private
  Equality. PHASE 3B delivered the routing foundation
  (`internal/targetcrypto`). The equality protocol itself is PHASE 8 and does
  not exist. Target DPF retired.
- **Target Position Filtering:** awaiting implementation.
- **Target Record Aggregation:** awaiting implementation and an independent security audit.
- **Candidate ID Generation:** awaiting implementation.
- **Canonical Candidate Discovery runner:** does not exist; may be created only in PHASE 11.
- **Production E2E:** does not exist; production E2E may be claimed only in PHASE 12.

## RETIRED / FORBIDDEN

- old e2e drivers;
- old target-e2e;
- old anchor-e2e;
- old `IndexEncode(uint64)`;
- `Trunc64(SHA256(w_B))`;
- Target DPF;
- old KHPRF full-point combine (the path that reconstructed `Enc(Y)` in one
  party and wrote it to disk);
- XOR sharing of the Target stored key (`Z0 XOR Z1` over encoded points);
- public, unkeyed `H_K` for the Target join and q-gram derivations;
- PMEQKI01 plaintext target key;
- plaintext Posting struct as production storage;
- plaintext Position temporary split;
- `aliasByArea[ids[c]]`;
- plaintext `candidates()`;
- query-time raw DB access;
- production oracle access;
- old Anchor aggregation rows/wrapper that leak `phi_h`;
- old generated index reader;
- BFV / MBFV / CWMatch production chain.

None of the paths above may re-enter the production graph through a compatibility interface.

## PHASE 4A boundary and open dependencies

IndexOutsource is sealed. Anchor filtering now ends at `x_{h,s}` F2 hit shares.
B2A and hidden incidence aggregation through local-record F are now implemented
by PHASE 5B1. PHASE 5B2 adds F->z, global alignment, C, Keep and payload.
Private Equality, Target filtering, Candidate
ID Generation, and a full Candidate Discovery runner remain unimplemented.

PHASE 5B1: F2 posting shares -> batched Z128 B2A -> chunked scalar-vector Beaver
with secret-shared incidence -> F shares. T is physical bucket slots; D is an
independent power-of-two record-coordinate capacity. DO-only mapping never
enters party state. Static A, one-time triples, and masked-opening traffic are
accounted separately. Benchmarks execute real Beaver algebra in a single
trusted coordinator with in-memory openings; no network latency is claimed.
Per-record payload is a DO-generated Global LayoutID array aligned with
Keep, never an aggregation of the posting routing fields.

Future Position Filtering is variable-width compatible: it must iterate each
group and then that group's slots; no `groupIndex * bucket.LPad` interface or
implementation exists. Future hidden Aggregation consumes posting slots and
their hidden record relation independently of group width, so variable
`PadWidth` is not an interface blocker. PHASE 3C3 does not implement either
stage.

SHORT-STRING COMPLETENESS remains OPEN. Anchor B=65536 and the new posting
ladder are frozen in PHASE 5B2. Payload/Keep alignment is implemented; payload
rerandomization during future compaction/selection remains that phase's duty.
SCMP remains an external validated primitive. Timing reports are SUM OF
MEASURED COMPONENTS, not monolithic E2E. The paper is unchanged.

PHASE 5B3 retains the PHASE 5B2 mathematics and freezes preprocessing semantics:
PoolStorage=Q_pool*S_offline for equal-capacity query packets, or the sum of
packet capacities for heterogeneous queries. Q_pool has no frozen numeric value.
Static payload/LayoutID/DO gamma/incidence shares/index/rhoSeed/sigma are reusable;
SCMP masks/keys, B2A/incidence triples, permutation masks and Keep threshold
material are one-time. Query DPF tokens remain query-generated. Keep has no
additional Beaver triples in the current implementation.

The factor footprint is 25640709028 bytes for all 53383 nonempty buckets,
not including metadata/allocator overhead. This is quantified static storage,
not a full-table resident-memory claim. Only accessed sigma and transient rho
are loaded for experiments. No persistent format, query-time DO service, or
raw DB lookup was added. PHASE 6 subsequently implements Candidate Compaction; PHASE 7 subsequently implements private Target routing.

**PHASE5 = SEALED.** Correctness, hidden posting correspondence, aligned payload,
static storage accounting and finite offline-preprocessing lifecycle gates pass.
PHASE 6 completes Candidate Compaction after this sealed PHASE5 boundary. Short-string
completeness remains OPEN; SCMP remains an external validated component.


PHASE 6 party-local chain:

CandidateInput(LayoutID, Keep, RecordID, KappaJoin, BucketJoin shares)
-> CS1.Begin -> masked message -> CS0.Stage1(tau0)
-> CS0.BeginStage2 -> masked message -> CS1.Stage2(tau1)
-> each party OpenKeep -> exchange only final Keep shares
-> each party Extract -> CompactedCandidates(LayoutID, fresh CompactionID, K,
three K-length payload-share arrays).

Only the offline dealer has both factors/materials; online method signatures
never take both inputs. Factors AND masks are fresh per query, unlike static
PHASE5 alignment factors. K is public; gamma, payload and cross-query positions
remain hidden. K=0 retains no dummies. Tests reconstruct only in the coordinator.
The native real-query experiment runs Anchor DPF, LLAMA Position, Boolean hits,
incidence, deduplication, global alignment, LLAMA Keep and this compaction.
See results/phase6-audit.md and results/phase6-results.md. No later phase begins.


PHASE 7 current chain:
Query User initial target token (fresh point/XOR shares, h and position)
+ PHASE6 compacted candidate shares
-> local J_u and Y_u for K*r pairs
-> exchange ONLY combined bucket-share messages
-> public Target BucketID plus local Y_u, with Anchor RecordID shares retained
once at top level and c scoped to CompactionID.

The Target manifest binds its own bit width, independent of Anchor width.
Real PSMJ uses the last full validated setting, bits=8; Target B remains OPEN.
No full Y combine, H_route, Target DPF/CW token, equality or target filtering.
Query User is offline after initial token; query-time DO/raw DB=no. See
results/phase7-audit.md and results/phase7-results.md. Paper modified=NO.
