# CURRENT PMEQ Production Engineering Specification

This document is the current production engineering specification for PMEQ.

## 1. Sources of truth

- Old repository: `/home/tenggn/projects/new-pmeq` — read-only reference only.
- New repository: `/home/tenggn/projects/pmeq-clean` — the only production source of truth.
- Source snapshot: `/home/tenggn/projects/PMEQ_SNAPSHOT_PRE_ANCHOR_AGG_20260915T190526+0800/source.tar`
- Snapshot SHA256: `a456dec8a84236b333c043b7ce68033b6418f6c6ac8e2ca494858b62f66792a0`

The current engineering specification takes precedence over the paper text. The paper is only a provisional implementation target and may be changed when implementation, security, interface, or logic defects are found. Old code must not enter the production repository through a compatibility layer.

## 2. System model

- **DO:** trusted; responsible for IndexOutsource and preprocessing; offline during queries.
- **CS0 / CS1:** semi-honest and non-colluding.
- **Query User:** authorized and honest.

## 3. Dataset and query object

- Sole raw database: MusicBrainz fullexport `20260905-002519`.
- Primary tables: `area(id,name)` and `area_alias(id,name,area)`.
- Join condition: `area.id = area_alias.area`.
- `q = 4`.
- Anchor: `area.name`.
- Target: `area_alias.name`.

## 4. Current Candidate Discovery boundary

The only intended chain is:

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

Candidate Discovery stops at Candidate ID Generation. Full-string Candidate Retrieval is a separate future problem. The current project must not claim that full-string Candidate Retrieval has been implemented.

## 5. Frozen primitives and designs

### Sharing

Additive Secret Sharing.

### Anchor logical key and production representation

The Anchor logical key is:

```text
w_B = BSMJ || Table || SearchAttr || JoinAttr || qgram
```

The Anchor production representation is:

```text
z_B = Trunc128(
  HMAC-SHA256_kB(
    "PMEQ-BSMJ-INDEX-V1" || w_B
  )
)
```

The engineering meaning of concatenation inside `w_B` is the following
canonical, length-delimited byte encoding:

```text
U32BE(len(UTF8("BSMJ"))) || UTF8("BSMJ")
|| U32BE(len(UTF8("area"))) || UTF8("area")
|| U32BE(len(UTF8("name"))) || UTF8("name")
|| U32BE(len(UTF8("id"))) || UTF8("id")
|| U32BE(len(UTF8(qgram))) || UTF8(qgram)
```

Every length is the UTF-8 byte length. A qgram must be valid UTF-8 and contain
exactly four Unicode code points. Encoding preserves the exact input bytes and
case: it performs no NFC, NFKC, case folding, whitespace trimming, or other
normalization.

`k_B` is exactly 256 bits and is held only by the DO and authorized Query User.
CS0 and CS1 do not know it. The DO and authorized Query User must call the one
shared canonical encoder; role-specific duplicate encoders are forbidden.
`Trunc128` means copying bytes 0 through 15 of the complete HMAC-SHA256 digest
directly into an opaque 16-byte value, with no integer reinterpretation.

Bucket mapping is not defined by PHASE 2B. In particular, this specification
does not yet choose whether a future bucket function consumes a logical key or
`z_B`; that decision belongs to PHASE 3.

Anchor Match uses a 128-bit DPF with security parameter 128 and GGM depth 128.
Its input `Point` is the Anchor `Value`'s 16 bytes copied verbatim. Tree levels
consume byte 0 through byte 15 and consume each byte from its most-significant
bit to its least-significant bit. This traversal convention does not reinterpret
the Anchor value as an integer.

The DPF output group is `F_2`, `beta = 1`, and each local evaluation returns one
`share.BitShare`. Per-slot `Validity` and `PositionPredicate` values are also
`share.BitShare`. PHASE 4A computes

```text
Match AND Validity AND PositionPredicate
```

with two batched Beaver multiplications in `F_2`. Its final output is the
party-local posting hit share `x_{h,s}` in `F_2`; B2A is implemented at the
PHASE 5 aggregation boundary, not inside filtering.

The DPF PRG uses each 128-bit seed `s` as an AES-128 key with four exact,
distinct 16-byte domain blocks:

```text
C_L = 00000000000000000000000000000000
C_R = 00000000000000000000000000000001
C_T = 00000000000000000000000000000002
C_V = 00000000000000000000000000000003

G(s) = AES_s(C_L) || AES_s(C_R)
       || MSB(AES_s(C_T)[0]) || second-MSB(AES_s(C_T)[0])
Convert(s) = MSB(AES_s(C_V)[0])
```

Its security argument relies on AES-128 PRF/PRP security for a random
seed-as-key evaluated on fixed, distinct input blocks, providing the
pseudorandom expansion required by the GGM/DPF construction. Tests provide
correctness evidence only; they do not prove PRG security.

DPF key serialization is deferred until a reviewed query-token schema exists.
The old 64-bit DPF and Target DPF are permanently retired from the production
path.

### Padding and validity

Production padding is the frozen per-group tier ladder
`{4,16,64,256,1024,4096,8192,16384}`. Each group's public `PadWidth` is the
smallest tier greater than or equal to its real posting count. `PadWidth`
reveals the corresponding coarse real-size class and is allowed structural
leakage. Validity remains secret-shared per slot: `real = 1`, `dummy = 0`.

### KHPRF routing

Retain the current Ristretto255 KHPRF design.

### Candidate compaction

Use exact-K secure compaction.

- Input: secret Keep / payload.
- Process: two-stage secure shuffle.
- Permitted opening: shuffled Keep.
- Output: exactly K payload shares.
- Permitted leakage: K.

### Target match

Target DPF is permanently retired.

**OPTION 4 is approved.** The Target stored group key is the KHPRF group point

```text
T = (kappa_J + kappa_w) * P          (Ristretto255)
```

shared additively in the group:

```text
T = T0 + T1
```

Each party's production state holds only its own `canonical 32-byte encoding of
T_u`. `Enc(T0) XOR Enc(T1)` has no protocol meaning. No cloud may reconstruct
`T`, and no production type or function may reconstruct, open, or reveal a full
target point or scalar.

Target Match remains **full-256-bit Private Equality**, evaluated over the two
parties' locally computed private inputs:

```text
CS0: A = Enc(Y0 - T0)
CS1: B = Enc(T1 - Y1)
```

with `Y_u = PartEval(kappa_u)` and `Y0 + Y1 = T` on a match. Each party encodes
its own difference locally; the canonical encoding never enters a multi-party
computation. The equality identity is

```text
Y = T  <=>  Enc(Y0 - T0) = Enc(T1 - Y1)
```

which holds because Ristretto255 canonical encoding is injective on the group.

### Target routing primitives (PHASE 3B)

- Master key: `k_T`, 256 bits, held only by the DO and an authorized Query User.
- Canonical encoding: the single length-delimited `Frame` encoder. No bare
  string concatenation.
- Scalar mapping: `HMAC-SHA512(k_T, Frame(domain, ...))` -> 64 bytes ->
  `Scalar.SetUniformBytes`. `Element.SetUniformBytes` must not substitute for
  the scalar mapping, and `k_T` is never a plain hash message field.
- Base point: `P = Element.SetUniformBytes(SHA512("PMEQ-TARGET-KHPRF-POINT-V1"))`.
  The canonical generator is deliberately not used.
- Bucket component: `HMAC-SHA256(k_T, Frame(domain, ...))`, first `k` bits
  MSB-first, combined by XOR in `F_2^k`. `B = 2^k`; no modulo reduction.
  The current production width is not fixed by PHASE 3B (`B RE-EVALUATION
  OPEN`); the primitive only requires a power of two.

### Base outsourced index schema (PHASE 3C1; padding frozen in PHASE 3C3)

PHASE 3C1 implements the trusted-DO, in-memory base index builder for the raw
MusicBrainz `area` and `area_alias` COPY text tables. It does not define a
persistent index format and does not generate the full-dataset index.

Q-grams are exactly four Unicode code points. For `r := []rune(name)`, the
builder emits every `string(r[i:i+4])` at zero-based code-point position `i`,
including repeated occurrences. There is no byte slicing, normalization,
trimming, or case folding. Names shorter than four code points are counted and
excluded from this main index; the completeness policy remains open.

The Anchor logical group identity is the q-gram. Its public group value is
`z_B = anchorindex.Encode(k_B, qgram)`. Its bucket is the first `k` bits of
`z_B`, MSB-first, for `1 <= k <= 16`. Each Anchor party slot contains exactly
one local share of the record ID, position, validity, `kappa_J`, and `beta_J`.

The Target logical group identity is the tuple `(area_alias.area, qgram)`, not
the q-gram alone. The DO derives the full group point only during trusted
construction and stores one additive Ristretto point share per party. The
Target bucket is

```text
JoinBucketComponent(k_T, area_alias.area, k)
XOR WordBucketComponent(k_T, qgram, k).
```

Each Target party slot contains exactly one local share of alias ID, position,
and validity. It contains no join value or routing payload.

Padding is per group. For a nonempty group with `n` real postings:

```text
PadWidth(n) = min { L in {4,16,64,256,1024,4096,8192,16384} : L >= n }.
```

An input group larger than 16,384 is an error; there is no dynamic tier, exact
width, or bucket-maximum fallback. Anchor and Target use the same ladder. A
bucket's total slots are `sum_g PadWidth(g)`, never
`GroupCount * bucket.LPad`. Real validity is shared from one. Dummy record ID, position, validity,
Anchor scalar, and Anchor bucket component are all shared afresh from semantic
zero; no local all-zero convention or plaintext dummy flag exists. Group count
and every group's `PadWidth` are public structural metadata. This coarse
size-class leakage is accepted in exchange for substantially lower padding.
The PHASE 3C2 per-bucket-maximum layout remains available only as an experiment
baseline. No cap/overflow, dummy-group, or ORAM policy is implemented.

The public metadata contains only `q`, both bucket widths, and for each
nonempty Anchor/Target bucket its bucket ID, total slots, and group count. Each
party group contains the same public `PadWidth`, and its local slots slice has
exactly that length. Buckets do not carry a production `LPad`. Party
state contains no plaintext name, q-gram, join ID, raw record, peer share, both
shares, full Target point, or derivation key.

### Open items carried forward

- **SHORT-STRING COMPLETENESS = OPEN.** Strings shorter than `q` cannot be
  indexed by the `q`-gram chain. The live counts are 644 `area` records and
  4,047 `area_alias` records. No policy is frozen here: an out-of-domain
  restriction is **not** adopted, and no short-string index is implemented.
- **Anchor B = 65536 FROZEN in PHASE 5B2.** AnchorBucketBits=16. The Target
  bucket-width primitive remains independently parameterized.
- **PHASE 5 PAYLOAD ALIGNMENT = CLOSED in PHASE 5B2.** Keep and fresh DO-generated
  per-record payload use the same hidden global LayoutID. Compaction remains future work.
- The paper is **not modified** by PHASE 3C3; it will be synchronised once the
  protocol is stable.

### Anchor filtering foundation (PHASE 4A)

Query signatures are non-overlapping complete four-code-point chunks. For
`r := []rune(Q)`, occurrence `h` is `string(r[4h:4h+4])` at zero-based rune
position `4h`; an incomplete tail is dropped and repeated chunks remain
distinct occurrences. Database names continue to use overlapping q-grams.

The MusicBrainz snapshot has maximum real Anchor/Target positions `54/62` and
maximum indexed rune lengths `58/66`. Thus public `U_pos=62` and the minimal
signed LLAMA width is `Bin=7`, satisfying `U_pos+1 < 2^(Bin-1)`. Each cloud
reduces its stored Ring32 share modulo `2^Bin` locally; positions are never
reconstructed and reshared.

For `L=max(0,pQ-tau)` and `R=min(U_pos,pQ+tau)`, external validated LLAMA SCMP
with `Bout=1` supplies shares of `[p>=L]` and `[p>=R+1]`; their XOR is the
inclusive position predicate. The clean Go repository implements the masked
input algebra and an opaque SCMP adapter, not LLAMA itself. Each one-use `pid`
has query-user `(pid,eta_L,eta_R)` and party-local `(pid,Bin,rho_L[],rho_R[],
lower keys[],upper keys[])`; preprocessing depends only on `Bin`, capacity,
and fresh randomness. Evaluation subtracts each key's local `rb` output mask.

The authorized-user `anchorquery` package derives Anchor HMAC/DPF material.
Each cloud token contains only its DPF key, public bucket ID, `pid`, and masked
bounds. Filtering iterates variable-width group slot slices and returns
`x = Match AND Validity AND PositionPredicate` as `F_2` shares. It performs no
record aggregation, compaction, Target filtering, or B2A. IndexOutsource is
sealed. PHASE 5B2 freezes Anchor B and implements payload alignment;
short-string completeness remains open. The paper is unchanged.

### Secure permutation

Retain the two-party secure permutation primitive.

## 6. Frozen status of Anchor Aggregation

The mathematical target is:

```text
F_{h,j} = sum_{s:phi_h(s)=j} x_{h,s}

z_{h,j} = 1[F_{h,j}>0]
```

Then use hidden global coordinate `gamma` and two-party secure permutation to align records across groups:

```text
z_h
→ hidden permutation
→ y_h

C = sum_h y_h

Keep_j = 1[C_j >= lambda]
```

**PARTIAL REUSE approved; PHASE 5B1 implements the hidden posting-to-F boundary.**

Old Z128 aggregation rows/wrapper must not be migrated because party-local rows expose `phi_h(s)` and `t_h`. The new boundary reuses the existing B2A and scalar-vector Beaver mathematics with independent coefficient shares.

### PHASE 5B0/5B1 incidence interface

For an accessed bucket, T is the sum of group PadWidths; M is its number of
distinct real records (DO-only); D is zero for M=0, otherwise the smallest
power of two >= M. D is a public record-capacity class, not a group PadWidth.
The DO randomly injects records into [0,D). A has D rows and T columns.
Real columns are unit incidence vectors; dummy columns and unused rows are
zero. Each coefficient, including zero, is freshly shared in Z/128Z.
Each cloud holds only its own column-major coefficient shares and public D/T.

`internal/incidence` accepts PHASE4 `share.BitShare` inputs. One batched B2A
layer computes x=x0+x1-2*x0*x1 using Z128 Beaver. A scalar-vector Beaver triple
per posting then computes F[j]=sum_s A[j,s]*x_s modulo 128. Accumulation is
chunked, with no intermediate product matrix. The public chunk limit is
configurable; default 64 is an experimental local-compute choice.
Exact integer-count semantics require F<128; current full-data k=14 buckets
have at most 3 occurrences of one record. Future SCMP also needs its signed
range checks. This stage returns F, not [F>0].

Static incidence shares are reusable. B2A/vector triples are one-time offline
material. Online messages are only masked d/e differences. BigState posting
conversion/evaluation is unnecessary for this direct A*x boundary and is not
migrated. The PHASE 5B1 package still ends at F; PHASE 5B2 completes the
following stages in `internal/aggregation`, without compaction or routing.

The implemented next-stage interface is F -> z -> global alignment -> Keep[gamma]. The
DO independently creates fresh per-record ID/KJoin/JoinBucket shares at the
same hidden gamma/Global LayoutID. Payload must not be folded from posting
shares. Posting KappaJoinShare/BucketJoinShare are DEPRECATED / REDUNDANT for
the new aggregation path, retained until a later schema cleanup. Short-string
completeness remains OPEN; the paper is unchanged.

### PHASE 5B2 complete Anchor record aggregation

AnchorBucketBits=16, B=65536. All base indexes use the posting tiers
4/16/64/256/1024/4096/8192/16384; uniform bucket-max is experiment baseline only.
The full raw-data maximum same-record/same-qgram occurrence count is 2.
Thus correctly filtered F<=2<64. F->z and C->Keep use external LLAMA signed
SCMP Bin=7, Bout=1; local raw evaluation output has key.rb removed. Fresh
input masks and masked query-user bounds are one-time offline material.

z is converted once from F2 to Z128 before alignment, reusing existing B2A.
DO fixes N_global=120071 and a random gamma and LayoutID. It independently
shares (record ID, KJoin, JoinBucket) once per record at gamma; posting payloads
are never folded. D local coordinates are embedded into N_global, unused
coordinates and appended zeros complete pi to a permutation.

DO samples rho and sets sigma[rho[i]]=pi[i]. In PHASE 5B3 rho is generated
from a fresh crypto/rand 32-byte seed using the frozen PRG below. CS0 holds
only this seed representation of rho; CS1 only uint32 sigma. Two-stage masked scatter is the existing old permutation
mathematics, not a new aggregation protocol. Fresh a1,c1,a2,c2 yield
b1=scatter(rho,a1)-c1, b2=scatter(sigma,a2)-c2. CS0 material is c1,a2,b2;
CS1 material is a1,b1,c2. Online CS1 sends d1=x1-a1; CS0 computes
r0=scatter(rho,x0+d1)+c1 and sends d2=r0-a2. Outputs are
y0=b2 and y1=scatter(sigma,b1+d2)+c2. All arithmetic is modulo 128.

Each cloud locally sums aligned vectors. Normal queries require 1<=r<=14
and 0<=tau<r; lambda=r-tau, C<=14. Final CandidateInput has LayoutID,
KeepShare[] and Payload[] with equal global lengths. This is the sole future
compaction input; no compaction or routing is implemented here.

The offline interface can provision chosen bucket invocations before queries;
no online method accepts raw records or dealer mapping. Experiments simulate
this pool in a trusted coordinator. Full static factors are quantified below,
not confused with one-time query material or all materialized in RAM.
Composition tests use explicitly test-only SCMP reference keys; real SCMP
performance comes only from the external LLAMA component. No monolithic
native Go/LLAMA E2E or persistent index format is claimed. Paper modified=NO.

### PHASE 5B3 static representation and preprocessing freeze

N_global=120071, Anchor B=65536 and posting tiers
4/16/64/256/1024/4096/8192/16384 remain frozen; aggregation mathematics is unchanged.
Per bucket, DO uses crypto/rand to generate rhoSeed[32]. ExpandRho v1 is:
AES-256-CTR(key=rhoSeed, IV=ASCII "PMEQ-RHO-PRG-V1!"), interpreting successive
four stream bytes as little-endian uint32; descending Fisher-Yates from N-1
to 1. For bound=i+1, reject words v below 2^32 mod bound, then j=v mod bound.
The CTR counter follows Go's standard big-endian increment. This rejection
removes modulo bias; the resulting permutation is computationally pseudorandom,
not information-theoretically uniform over S_N from only 256 seed bits.

CS0 static state is exactly LayoutID, BucketID, rhoSeed. CS1 static state is
exactly LayoutID, BucketID, sigma []uint32. DO computes sigma[rho[i]]=pi[i].
Neither party receives pi/gamma or the peer factor. rhoSeed is CS0-local
representation, NOT a shared secret. CS0 expands only the accessed invocation's
rho []uint32 and releases it afterwards; CS1 loads only the accessed sigma.
No startup all-bucket rho expansion exists. pi/gamma permutation coordinates
also use uint32; loop indices and lengths may use int, but coordinate arrays do not.

For 53383 nonempty buckets, factor data alone: CS0=1708256 bytes,
CS1=25639000772, combined=25640709028, versus 102556003088 previously.
Per bucket: 32 + 4*N = 480316 bytes (old 16*N=1921136). This is 3.999733509x
smaller, NOT a claim that all CS1 state now fits the experiment RAM limit.
Layout/bucket metadata, slice headers, map and allocator overhead are separate.
The experiment holds selected party-state objects; no new persistence or
compression format is defined.

`PreprocessingPoolSize = Q_pool` is a public system parameter, without a
frozen/default numeric value. One packet means one complete query invocation:
r independently masked qchunk subpackets plus final Keep threshold material.
It is prepared in an offline epoch and consumed once. A sealed party-local
packet registry rejects duplicate/unknown consumption, exhaustion and online
refill. The registry is lifecycle/accounting, not a serializer or a store of
peer materials; typed party-local correlated packets retain their one-use guards.
Tests generate only their required packets in the trusted offline coordinator.

PoolStorage = Q_pool * per-query offline material

This equality uses an equal-capacity packet class. For heterogeneous workloads,
PoolStorage=sum_i S_offline(i), or Q_pool times a declared capacity upper bound;
do not multiply a percentile by Q_pool and claim a complete pool size.
The PHASE5 aggregation-only byte count (both parties) remains:
S_agg=4P+8T+6Dsum+6Nr+(2*K_SCMP+2)*(Dsum+N)+(r+1).
K_SCMP=284 for the measured external codec. Static state is excluded. If the
pool covers Anchor filtering too, add its independently accounted PHASE4
position/Boolean preprocessing; S_agg is not that larger pool's total.
These are correlated-material payload bytes; PacketID registry/container
metadata and allocator overhead are separate, not hidden in S_agg.

STATIC REUSABLE: global payload shares, LayoutID, DO-only gamma, bucket A
shares, rhoSeed/sigma, and outsourced index/DPF evaluation points and parameters.
Query DPF tokens are still query-generated, not reclassified as static keys.
ONE-TIME: SCMP input/bound/output masks and keys, B2A triples, incidence Beaver
triples, permutation masks, final Keep threshold material. Keep currently uses
SCMP and has no separate Keep Beaver triples; any future such triples would
also be one-time, never static. No unlimited-query/no-preprocessing claim is made.

An online cloud consumes only previously provisioned local state. Exhaustion
requires a new offline provisioning epoch, never query-time DO or raw DB access.
Future Candidate Compaction remains a separate, not-started phase. Paper modified=NO.

PHASE5 = SEALED (PHASE 5B3): Anchor aggregation correctness passes, posting
mapping remains hidden in party-local incidence shares, Keep/payload share one
LayoutID, static factor storage is quantified, finite one-time preprocessing
is explicit, and online party APIs require neither DO nor raw DB access.
This seals the normal-query aggregation component, not short-string completeness,
an all-bucket resident store, a persistent material pool, or a monolithic E2E runner.

## 7. Phase gates

- **PHASE 0:** new repository + Git + specification documents.
- **PHASE 1:** foundational domains / sharing types.
- **PHASE 2:** AnchorIndexEncode HMAC-128 + 128-bit DPF.
- **PHASE 3:** entirely new IndexOutsource production schema.
- **PHASE 3B:** Target routing foundation primitives (approved OPTION 4
  representation; keyed scalar mapping; fixed KHPRF base point; additive point
  and scalar sharing; domain-separated bucket components). Primitive layer only:
  no IndexOutsource, no private equality, no Beaver, no B2A, no runner.
- **PHASE 4:** Anchor filtering foundation implemented through F2 posting-hit
  shares; native LLAMA remains an external validated component.
- **PHASE 5:** hidden incidence core implemented through Z128 local-record F;
  subsequent deduplication, global alignment and Keep remain unimplemented.
- **PHASE 6:** Candidate Compaction.
- **PHASE 7:** KHPRF Routing.
- **PHASE 8:** Target Private Equality.
- **PHASE 9:** Target Position + Target Aggregation.
- **PHASE 10:** Candidate ID Generation.
- **PHASE 11:** the sole Candidate Discovery runner.
- **PHASE 12:** real workload and production E2E.

No later Candidate Discovery phase may begin until PHASE 5 passes both correctness and single-party security audits.
