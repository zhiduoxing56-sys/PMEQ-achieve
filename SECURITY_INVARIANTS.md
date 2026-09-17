# PMEQ Security Invariants

## Single-party security boundary

Neither cloud acting alone may obtain:

- plaintext searchable value;
- plaintext record ID;
- plaintext Position;
- JoinID;
- complete kappa;
- complete Target stored group key;
- posting-to-record correspondence;
- gamma;
- complete local-to-global permutation pi (a random rho or sigma factor alone is permitted);
- the other party's share;
- final candidate identity.

The following are prohibited:

- query-time raw DB access;
- query-time production oracle access;
- plaintext candidate shortcuts;
- plaintext Posting production storage.

## Frozen permitted leakage

Only the following leakage is currently permitted:

- public system parameters;
- each group's public padding tier / `PadWidth`, revealing its coarse real-size
  class;
- public bucket group count and total padded slot count;
- K from exact-K compaction.

No other leakage may be treated as permitted unless it is explicitly frozen by a reviewed specification decision.

## PHASE 4 Anchor filtering boundary

The authorized Query User alone derives the plaintext Anchor HMAC point and
generates the two DPF keys. A cloud receives only its own opaque DPF key, the
public accessed bucket ID, a one-time `pid`, and the two masked bounds. It must
not receive `Q`, the q-chunk, `k_B`, alpha, or its peer's key.

Each position preprocessing `pid` is one-use for one query occurrence against
one bucket. Query-user state contains only `pid, eta_L, eta_R`; each cloud's
state contains only its own additive rho shares and opaque SCMP key shares.
Preprocessing is independent of the query and bucket contents. Clouds batch
open only `p+rho`, never `p` or rho. LLAMA `evalSCMP` output includes the local
`key.rb`; failing to subtract it before Boolean composition is forbidden.

The test-only plaintext SCMP backend is an oracle for composition correctness
only. It is not a production backend and none of its timings may be reported as
secure Position Filter performance. Real performance evidence comes from the
external unmodified EzPC/LLAMA primitive sources copied into `/tmp` for build;
no C++ SCMP source enters this repository.

The two Boolean multiplication layers use independent one-time Beaver triples
and one batched opening per layer. Party 0 alone adds the public `d AND e` term.
The result remains an F2 share; reconstructing hits or silently converting to
an integer inside PHASE 4 is prohibited.

## Required stage audits

**Correctness PASS does not imply security PASS.**

Every production stage must separately pass:

1. correctness test;
2. single-party API/state/view audit.

At minimum, the single-party audit must examine:

- function parameters;
- return values;
- local persistent state;
- local temporary state;
- logs;
- debug output;
- serialized files;
- caches;
- index schema;
- message transcript;
- length information;
- explicit identifiers;
- derivable correspondence.

If any item permits CS0 or CS1 acting alone to recover prohibited information, the stage is a **security FAIL**.

## Authorized reconstruction boundary

The foundational `internal/reconstruct` package is an explicit authorized
reconstruction boundary. A share type must not provide its own reconstruction
method. Once a CS-facing package exists, it must not import
`internal/reconstruct`; this import boundary is part of every subsequent
single-party API/state/view audit.

## DPF role and package boundaries

The 128-bit Anchor DPF evaluation boundary accepts one cloud's opaque `Key` and
one public `Point` and returns only that cloud's `share.BitShare`. A cloud object
must not hold the query alpha, the peer key, or the peer root seed.

`internal/dpf128/internal/core` is a compiler-enforced nested Go `internal`
boundary: packages outside the `internal/dpf128` subtree cannot import its key
constructors or protocol fields. `internal/dpf128/gen` is different: it is a
policy-separated trusted generator package, not a compiler-enforced cloud
boundary. Every future CS-facing package is forbidden from importing
`pmeq/internal/dpf128/gen`; this rule must be enforced by import-graph regression
tests when such a package is introduced.

The DPF key has no wire encoding in PHASE 2D. Production code must not log or
format its root seed, correction words, or final correction bit. Passing the
structural party-view audit is not a proof of the underlying DPF security,
which additionally relies on the stated AES-based PRG assumption and on CS0
and CS1 remaining non-colluding.

## Target routing boundary (PHASE 3B)

**Target stored representation.** The Target stored group key is the additive
Ristretto255 point share pair `T = T0 + T1`. Each party's production state holds
only its own canonical 32-byte encoding. `Enc(T0) XOR Enc(T1)` has no protocol
meaning.

The following are prohibited in production:

- reconstructing, opening, revealing, combining, or reserializing a full target
  point or a full target scalar;
- any exported `Recover*`, `Open*`, `Reveal*`, `Peer*`, or `Secret*` entry point
  on a share type;
- exposing `Enc(Y0 - T0)` or `Enc(T1 - Y1)` outside the party that computed it
  before the PHASE 8 equality protocol consumes it;
- public, unkeyed derivation of a Target join or q-gram value.

**Master key boundary.** `k_T` is a 256-bit secret held only by the DO and an
authorized Query User. The `targetcrypto.MasterKey` type deliberately offers no
serialization, no formatting method, and no logging surface. The all-zero value
is rejected so that an unset key cannot silently reach production. `k_T` is used
only as an HMAC key; it is never a plain hash message field.

**Trusted build boundary.** `DeriveTargetGroupPoint` returns a complete group
point and is therefore a trusted data-owner build-time helper. A future
cloud-facing package must not import it, must not import `MasterKey`, and must
not import `FullEval`. This must be enforced by an import-graph regression test
when the first cloud-facing package is introduced.

**Fresh sharing per posting occurrence.** A record's `kappa_J` and its `beta_J`
secret are the same plaintext secret in every posting occurrence of that record.
Nevertheless, every posting occurrence must obtain a **fresh, independently
sampled** party-local share of each of them. Reusing a party-local share across
occurrences is a **SECURITY FAIL**: a single cloud would recover the
posting-to-record correspondence from share equality alone. This rule binds
PHASE 3C IndexOutsource and is not satisfied by sampling once per record.

**Query-time rerandomization.** Selected `kappa_J` and `beta_J` shares must be
rerandomized per query before they are consumed:

```text
kappa'_J0 = kappa_J0 + rho ,  kappa'_J1 = kappa_J1 - rho        (Z_l)
beta'_J0  = beta_J0 XOR rho_b , beta'_J1 = beta_J1 XOR rho_b    (F_2^k)
```

with fresh `rho` / `rho_b` per query and per candidate. Without this, a cloud
can link the same candidate across queries by local-share equality. A secure
shuffle does **not** provide this automatically; PHASE 6 compaction and PHASE 7
selection must each state explicitly that they rerandomize.

**Structural policy.** Production share types are plain value types, not
structs, so that no share type can grow a second party's state. The package
`internal/targetcrypto` declares no production struct type and holds no
third-party dependency beyond the Ristretto255 implementation.

**PHASE 5B1 hidden incidence.** `PartyMatrix` contains D, T and one cloud's
coefficient shares only. Posting IDs and random local coordinates exist only
in DO `Posting`/`DealerLayout`; online Aggregator/PartyTriples/B2A cannot reach
them. Every real, dummy, and unused coefficient receives independent uniform
mod-128 masking, so either party's matrix distribution is independent of the
mapping, conditioned on public D/T. D reveals the approved record-capacity
size class, separately from the posting PadWidth leakage.

Scalar-vector Beaver shares one fresh scalar mask across the coordinates of
ONE posting, with independent vector masks; it does not reuse masks across
postings or queries. Only d=x-a and e=A-b are opened. Party 0 adds d*e.
Preprocessing objects are consumed once. The static A shares may be reused
with fresh triples. Structural/distribution regressions exercise the old
row-equality/nonzero-column attack but are not a cryptographic proof.

No sparse plaintext index, record ordinal, phi/rho, peer coefficient shares,
or full dealer state may enter a cloud object. F reconstruction is test-only.
Global payload is shared independently per record and bound to the
same Global LayoutID as Keep; posting payload must not be folded.

## PHASE 5B2 alignment and comparison

Anchor B=65536 is frozen. Posting tiers are
4/16/64/256/1024/4096/8192/16384. Public W=8192 reveals 4097..8192;
W=16384 now reveals 8193..16384. Uniform padding is baseline only.
The existing public D capacity class remains distinct from posting PadWidth.

DealerLayout alone holds gamma/record IDs. Stage0 holds LayoutID, BucketID and
rhoSeed; Stage1 holds LayoutID, BucketID and uint32 sigma, never pi or the
other factor. Only invocation-local CS0 scratch holds expanded uint32 rho. PartyPayload
contains only LayoutID and local ID/scalar/bucket shares. CandidateInput binds
local Keep and payload by the identical LayoutID and length. Static payload
does not authorize releasing local candidate payloads without the future
compaction/selection rerandomization already required above.

Permutation preprocessing is one-time: CS0 has c1,a2,b2 and CS1 a1,b1,c2.
Only x1-a1 and r0-a2 cross the online boundary; neither cloud receives both
the mask and masked value. Each factor is uniformly distributed independent
of pi; fresh vector masks hide dynamic values across repeated invocations.
No combined StaticPerm/controller state is copied from the old repository.

F->z and C->Keep open only value+fresh R, not value or R. Bound masks belong
only to the authorized user. LLAMA keys are party-local and rb is removed.
The full-data F<=2 and normal-query C<=14 bounds justify signed Bin=7.
Comparison and permutation packets reject repeated consumption. Reference
SCMP is test-only composition code and never performance evidence.

## PHASE 5B3 representation and one-time lifecycle

rhoSeed is generated by crypto/rand independently for each bucket's static
alignment setup. It belongs ONLY to CS0. AES-256-CTR with fixed domain IV
"PMEQ-RHO-PRG-V1!", LE32 words and rejection-sampled Fisher-Yates deterministically
expands rho. Changing rho from an array to this seed does not give CS0 pi/gamma:
the seed is independent of that mapping. CS1 gets sigma, never the seed or rho.
Security of replacing full random rho by seeded rho is computational under the
PRG assumption, not a claim of exact uniform sampling of all N! possibilities.
Tests establish deterministic algebra/schema correctness, not a cryptographic proof.

Static factor objects contain no random-mask packet or peer pointer. Coordinates
are uint32; no int/uint64 permutation coordinate arrays are stored. ExpandedStage0
is temporary invocation scratch, not an all-bucket cache. DO gamma is also uint32
coordinate-valued; uint64 record IDs are not permutation coordinates.

Q_pool controls an offline epoch's finite one-use query packets. SCMP keys/masks,
B2A/incidence triples, permutation masks and Keep threshold material are never
reused, even when static index/factors/payload are reused. The party-local registry
is sealed before online consumption and cannot be refilled online. Actual correlated
materials stay in the existing typed party-local objects, never in the peer registry.
Any material-pool exhaustion is an offline reprovisioning condition, not permission
for a query-time DO callback or raw database lookup. Current Keep has no separate
Beaver triples; this does not make its SCMP threshold packet reusable.


## PHASE 6 exact-K compaction

PHASE5 remains SEALED. Its global gamma is static and must never be exposed by
opening Keep[gamma]. Every compaction consumes independently sampled fresh
permutations tau0/tau1 and independent domain-specific one-time masks. The same
permutation pair acts on all four fields. CS0 knows only tau0 and CS1 only tau1.
No party object or method holds both payload inputs, original IDs or dealer gamma.
Input scalar encodings are checked before use. Keep is boolean F2, preventing
the old fixture's full-byte stable-tag defect. Public seeded benchmark randomness
is not used in production preprocessing.

In the semi-honest, non-colluding model, CS0's final ordering is randomized by
unknown tau1, and CS1's by unknown tau0. Independent pads hide online masked
messages. Conditioned on K, final opened Keep is a fresh random K-subset in
each party view. Additional leakage is exactly K with fixed public N; K is not
hidden. Extreme K=0/N supports cannot change, but secret outputs are refreshed.
A compacted slot has no cross-query stable candidate identity.

Only shuffled Keep is exchanged in opening. Extraction reads local payloads;
no payload is opened or transmitted as an output. RecordID uses Ring64 addition,
kappa uses scalar-field addition, bucket uses XOR. Never treat their plaintext
serialization as a common XOR group. Output includes no original-coordinate map.

Fresh CompactionID, LayoutID, shape and stage binding reject wrong packets and
replays. Packet handle copies share consumed state; the sealed offline pool
supports one-use CompactionID tickets and no query-time refill. Successful local
extraction releases all N-sized packet/shuffled state and returns exactly K
shares. Cryptographic randomness and offline material must never be reused.
See results/phase6-audit.md for equations and the simulation argument. No new
malicious-security guarantee, persistent transport or storage format is claimed.
Query-time DO/raw DB=no; KHPRF/Target filtering started=no; paper modified=no.


## PHASE 7 private Target routing

PHASE5=SEALED and Candidate Compaction=COMPLETE. Width is explicit metadata:
Target Manifest/IndexID, PHASE6 handoff and QueryToken must agree, independently
of AnchorBucketBits. PHASE7 originally used then-last-validated bits=8; PHASE7B
freezes Target bits=16 with a full materialized artifact. BucketDomain is a checked scalar width type,
not a composite share; existing no-struct/single-share gates remain intact.
Compaction masks must respect the chosen width; no post-hoc truncation of an
existing differently derived bucket component is allowed.

Only Query User code takes k_T/Q_target and calls KWord/FullEval/SplitPoint.
Cloud entry points take one candidate share set and one word-token share set.
They cannot receive a peer point: the sole server message has only combined
bucket shares. Y_u=(kappa_J)_u*P+W_u stays local. Full Y, IDs, gamma, component
scalars and individual bucket components are never opened in production.
Only trusted test oracles reconstruct Y/T for correctness; no Target Equality
code or point-difference equality input is produced.

Leakage is K, r_target, beta[c,h], and public dimensions. Simulation is relative
to these public values and the existing semi-honest non-collusion assumptions;
it does not deny XOR relations or linkage implied by disclosed bucket patterns.
Fresh word point/XOR shares hide repeated text at the share level. Candidate
index c has meaning only within fresh CompactionID. Top-level ID shares retain
association without per-occurrence duplication or plaintext recovery.

Message codecs validate manifest/index, layout, CompactionID, QueryID, party,
K/r, occurrence positions, lengths, point encodings and bucket-width bounds.
Pending.Finish is one-use and rejects malformed peer openings before committing
public buckets. K*r=0 sends no opening and creates no dummy route. Parallelism
is bounded to 1/4/8/16 local arithmetic workers with disjoint output ranges;
Y never becomes a server-server message. Query User is offline after initial
token, DO remains offline, and no raw DB access exists in cloud methods.
Target Private Equality/Position/Aggregation remain unstarted. Paper modified=NO.


## PHASE7B final artifact invariants

- TargetBucketBits=16 is independent of AnchorBucketBits=16. Final manifest
  loading checks width, Q4, IndexID/version, tier ladder and dimensions; final
  production constructors expose no alternative width parameter.
- Manifest provenance is trusted-owner provisioning. SHA256 file binding is
  integrity checking, not a signature or malicious-party proof.
- A cloud receives only its own artifact. PSMJ v1 serializes local point/ID/
  position/validity shares and public bucket/PadWidth metadata. No plaintext
  joinID/qgram/full T/peer share is present. Codec and schema allow-list pass.
- Payload files carry IndexID, LayoutID, width and party. A fresh offline
  LayoutID is not compatible with old Keep/alignment state: provision the
  matching existing DealerLayout/alignment. No post-hoc truncation/relabeling.
- k-bit bucket access reveals k bits of keyed bucket identity; the sweep's
  k8/10/12/14/15/16 values give progressively finer public access patterns.
  Final routing still leaks K, target occurrence count, accessed beta and
  public dimensions; no secrecy of these access relations is claimed.
- Repeated bucket reads may be cached. Distinct candidate/occurrence inputs
  still require distinct equality comparisons, even when beta is identical.
- Saved real-workload traces contain plaintext oracle identities and queries;
  they are test-only evidence, NEVER party artifacts. The restored trace is a
  fresh native PHASE7 replay, not the unavailable original randomized transcript.
- All-point/all-slot reconstruction and 466105 final route checks run only in
  the trusted test coordinator. Neither production party combines T or Y.
- PHASE5=SEALED; Compaction=COMPLETE; Private Routing=COMPLETE. PSMJ=SEALED and
  Target B final choice=FROZEN after full materialization/route/schema gates.
  PE, Target Position, Target Aggregation remain unimplemented. Paper unchanged.


## PHASE8 private group equality

- Load validates version1, IndexID, Q4, independent Target bits16, all8 tiers,
  own artifact SHA256/lengths and the final payload/alignment LayoutID lineage.
  Begin rejects routing metadata/lineage mismatches. No query-time raw DB lookup
  or PSMJ rebuild exists. Group ordinals are fixed by the hash-bound sealed files.
- Only one party's Y/T shares enter its local difference helper. Canonical
  encoding is injective: D0=D1 iff Y0+Y1=T0+T1. Identity is supported; malformed
  local encodings fail. No hash, truncation or scalar reinterpretation is used.
- CS0's input bit is1 XOR E0_i and CS1's is E1_i. XOR reconstructs bitwise
  equality. The old random input-share adapter has no additional necessary
  security role for these naturally private inputs; zero input bytes are sent.
- At every gate fresh independent triples mask d=x XOR a and e=y XOR b.
  Reuse of triples is forbidden. 64 lanes are independent F2 gates. Scalar and
  packed operations use the same existing Beaver Finish convention, party0 d&e.
- A query packet is consumed atomically once, including unused upper-bound
  capacity; copies share this guard. Sessions enforce round order and bind
  IndexID/LayoutID/CompactionID/QueryID/packetID/public structure/route layout.
  These checks are coherence/replay checks, not malicious-security authentication.
- Given its existing Y_u/T_u, a party can compute D_u/E_u itself; these local
  computations leak no additional information. Fresh masked openings are
  simulatable under the existing trusted-preprocessing, semi-honest noncolluding
  model. The final equality bit remains XOR-shared, never publicly opened.
- Public dimensions and beta determine G. G/offsets/group counts add no plaintext
  hit leakage. No claim is made to hide existing public bucket access patterns.
  Peer E/D, full Y/T, join value, qgram and plaintext Match never enter one
  production party's state. Test-only reconstruction is confined to the oracle.
- Output contains only public route descriptors, local Anchor ID shares and
  local F2 Match shares. No D/E/Y/T field or peer value is returned. Unused packed
  lanes are masked and cannot become output entries. No Target Position,
  Target Aggregation or Candidate ID Generation is implemented. Paper unchanged.
