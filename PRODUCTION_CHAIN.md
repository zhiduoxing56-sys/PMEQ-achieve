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
→ Query User final candidate-pair recovery

## Current stage status

- **IndexOutsource:** PHASE 3C3 base builder implemented in memory for raw
  MusicBrainz `area`/`area_alias`: q=4 code-point postings, Anchor q-gram
  groups, Target `(joinID,qgram)` groups, party-local fresh shares, and frozen
  per-group tiers `{4,16,64,256,1024,4096,8192,16384}`. The uniform per-bucket
  maximum is experiment baseline only. PHASE7B adds the sealed Target v1
  artifact; a persistent Anchor index/alignment format remains deferred.
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
- **Target Private Equality:** PHASE8 implements Option4 local canonical
  differences, direct natural XOR-share input and packed Boolean Beaver equality.
  It ends at secret group Match shares; no input adapter and no hit opening.
- **Target Position Filtering:** PHASE9 implements PHASE4 SCMP plus two F2 AND layers; posting Hit stays secret.
- **Target Record Aggregation:** PHASE10B fixed D26 hidden incidence, F/z/C/Keep; evidence in results/phase10b-results.md.
- **Candidate ID Generation:** PHASE10B fixed26K secret pair shares; no final count opening to clouds.
- **Canonical Candidate Discovery runner:** PHASE11 `discovery.RunLocal` connects the real components and authorized user recovery.
- **Integrated local E2E:** PHASE11 uses an independent outer wall timer. Completion is gated by854 valid queries and149 early rejections; evidence is in results/phase11-results.md. No socket/distributed latency claim.

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
PHASE7 used then-last-validated bits=8. PHASE7B now freezes and fully materializes
Target bits=16, independently of Anchor bits=16.
No full Y combine, H_route, Target DPF/CW token, equality or target filtering.
Query User is offline after initial token; query-time DO/raw DB=no. See
results/phase7-audit.md and results/phase7-results.md. Paper modified=NO.


PHASE7B final Target outsourcing boundary:
BuildFinalTarget (trusted DO, fixed final width)
-> cs0.psmj.bin / cs1.psmj.bin + public TargetManifest v1
-> targetrouting.LoadIndex -> BoundIndex.Prepare -> unchanged private routing.

TargetBucketBits=16; Target B final choice=FROZEN; PSMJ=SEALED.
Artifacts: artifacts/phase7b (one share file per party, never both to a cloud).
The Target manifest records Q4, all8 frozen tiers, IndexID/version, dimensions
and file SHA256/lengths. Width validation rejects mismatched tokens/payloads.
Corresponding 120071-record global payload files are width/index/layout-bound;
new offline LayoutID material must use its matching PHASE5 alignment, not old
Keep coordinates. No persistent Anchor alignment or Candidate Discovery runner
is added. All plaintext replay traces and reconstruction remain test-only.
See results/phase7b-results.md. PE/Position costs there are projections only;
none of Target PE, Target Position or Target Aggregation is implemented.
PHASE5=SEALED; Candidate Compaction=COMPLETE; Private Routing=COMPLETE.
Paper modified=NO.


PHASE8 current party-local boundary:
Verified final PSMJ + verified global-payload/alignment lineage + RoutedCandidates
-> own D0=Y0-T0 / D1=T1-Y1 -> own canonical256-bit input
-> direct XOR share (party0 complements bits) ->8 Beaver opening rounds
-> TargetGroupMatches(MatchOffset,GroupCount,secret MatchShares), with candidate
ID shares and occurrence positions carried through unchanged.

A cloud loads only its own hash-bound artifact. Public structural digests cover
all65536 buckets and each ordered PadWidth; they are bound in every message.
File hashes and the sealed DO construction bind the paired group ordinals;
public structure comparison does not compare secret T values.
All PE triples are prepared offline in finite Q_pool packets, consumed once.
No full Y/T, canonical peer E, or Match is opened in production.
Target B remains65536/FROZEN, PSMJ=SEALED, PHASE5=SEALED, Compaction/Routing=COMPLETE.
Target Private Equality=COMPLETE. Target Position, Target Record Aggregation,
Candidate ID Generation and production Candidate Discovery runner remain absent.
The full native run is a trusted composition correctness harness; reported PE
components are not TCP E2E latency. Paper modified=NO.

PHASE9 current boundary adds Target Position after secret Target PE:
`TargetGroupMatches -> PHASE4 LLAMA interval -> two F2 AND layers -> TargetPostingHits`.
The sealed PHASE7B artifact is read locally through the hash/manifest/lineage-
validated PHASE8 PartyIndex. The Position projection exports only own Position
and Validity shares, with public PadWidths; no record ID or T share enters output.

The authorized initial `targetquery.GeneratePositionTokens` extends the initial
word token with one masked-bound PositionToken per occurrence. Q_pool SCMP and
Beaver material is allocated before that initial token; each party receives only
its own material. A capacity upper bound is permitted and unused material burns.
Routing never triggers Query User/DO interaction. The replay's trusted setup
uses saved public workload capacities before any Anchor execution.

All real and dummy physical slots are processed in route/group/slot order.
The two AND layers are GroupMatch AND Position, then AND Validity. Output keeps
secret posting hits and the same AnchorRecordIDShare association. There is no
Target record aggregation or target candidate generation. Short strings remain
an explicitly reported completeness issue. See results/phase9-results.md for
full native replay, per-component measurements and exact communication scope.


PHASE10B current party-local boundary (supersedes earlier phase-local status):
Original PHASE8 secret GroupMatch retained after PHASE9
+ PHASE9 physical posting Hit shares + authenticated own offline sidecar
-> existing Z128 Hit B2A -> chunked26-row incidence -> F
-> real LLAMA z -> Z128 z B2A -> local cross-occurrence C
-> real LLAMA KeepTarget
-> Ring64 GroupMatch selection from group/ordinal ID payloads
-> F2 first-positive representative for r1..16
-> Ring64 representative selection -> Ring64 Keep masking
-> CandidatePairShares in fixed candidate/ordinal order, length26K.

The same join-local ordinal aligns occurrences without a global permutation.
D26 hides actual per-candidate alias count. Lambda is explicitly r-tau with
0<=tau<r. Both sidecar hashes and full original manifest/order are bound.
Only masked comparison/Beaver messages cross clouds. PairKeep/IDs remain secret;
no second compaction or final pair-count opening occurs. The output contains
neither actual nalias nor plaintext IDs. Query User recovery remains absent.

The trusted native validation keeps all1003 historical upstream queries, rejects
149 invalid aggregation thresholds, and verifies854 pair outputs. No historical
query Tau is silently modified. The complete replay is a correctness harness,
not the PHASE11 canonical production runner or PHASE12 production E2E.
AUTHORITATIVE REPO = `/home/tenggn/projects/clean_pmeq`; paper modified=NO.

## PHASE11 integrated Candidate Discovery boundary

The canonical Go entry point `discovery.RunLocal` now composes actual initial
user tokens, Anchor filtering/aggregation, compaction, routing, PE, Target
Position/aggregation and authorized final recovery. `discovery.Provision` is
strictly before execution. Each cloud worker has own state and byte endpoints;
the coordinator is the local transport/user role, not a shared cloud state.

`candidatequery.Recover` checks fixed26K result envelopes, reconstructs Keep and
Ring64 IDs only at the user, requires zero masked IDs for Keep0, and rejects
duplicates. Candidate Discovery ends at plaintext ID pairs, without record
fetching or full-string exact verification. Query User is offline between token
emission and final recovery; no final pair-count feedback goes to clouds.

Normal input: q4, Anchor r1..14/Target r1..16,0<=tau_i<r_i.149 historical invalid
Target queries reject before cloud execution;854 run the actual full chain.
No clamping, fallback or semantic replacement. Short-string completeness remains
OPEN (644 Anchor/4047 Target). Mean INTEGRATED LOCAL E2E WALL TIME is the primary
latency; it comes from one outer online timer, excludes all offline setup and
is not a component sum or network measurement. Evidence: results/phase11-results.md.
The current PHASE11 request supersedes the previous PHASE12-only E2E gate.
AUTHORITATIVE REPO = `/home/tenggn/projects/clean_pmeq`; paper modified=NO.

Final PHASE11 status: CANDIDATE DISCOVERY E2E = COMPLETE for the supported
normal q=4 domain, 0<=tau_i<r_i (Anchor r1..14, Target r1..16).
Final real replay:149/149 invalid queries rejected,854/854 valid queries correct,
1510 recovered pairs; FP/FN/duplicates/wrong AnchorID/wrong TargetID all0.
See results/phase11-results.md for final timing, communication, offline material,
static accounting, memory and security evidence. Short-string completeness OPEN;
full-string exact verification NO; query-time DO NO; paper modified NO.
