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
`share.BitShare`. Future per-slot `Validity` and `PositionPredicate` values must
also be `share.BitShare`. Computing

```text
Match AND Validity AND PositionPredicate
```

requires two future secure `F_2` multiplications. After the complete Boolean
filter, every processed or retained slot must undergo an explicit B2A conversion
before entering the current integer Record Aggregation interface. If a later
review formally changes the PHASE 5 aggregation design, the exact B2A placement
may be reviewed again, but the cross-domain conversion must not be silently
omitted. Boolean secure multiplication and B2A are not implemented in PHASE 2D;
both must pass independent correctness and single-party view audits before
PHASE 4 posting filtering is complete.

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
`{4,16,64,256,1024,4096,16384}`. Each group's public `PadWidth` is the
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
PadWidth(n) = min { L in {4,16,64,256,1024,4096,16384} : L >= n }.
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
- **B RE-EVALUATION = OPEN.** The bucket width is not re-frozen in PHASE 3B.
- **PHASE 5 PAYLOAD ALIGNMENT = OPEN.** The base posting payload is frozen for
  PHASE 3C1, but its eventual secure aggregation/compaction alignment remains a
  PHASE 5 dependency.
- The paper is **not modified** by PHASE 3C3; it will be synchronised once the
  protocol is stable.

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

**SPEC FROZEN. IMPLEMENTATION NOT PRODUCTION-SECURE.**

Old Z128 aggregation rows/wrapper must not be migrated into production because party-local rows expose `phi_h(s)` and `t_h`. PHASE 5 must solve the posting-to-record correspondence hiding problem again.

## 7. Phase gates

- **PHASE 0:** new repository + Git + specification documents.
- **PHASE 1:** foundational domains / sharing types.
- **PHASE 2:** AnchorIndexEncode HMAC-128 + 128-bit DPF.
- **PHASE 3:** entirely new IndexOutsource production schema.
- **PHASE 3B:** Target routing foundation primitives (approved OPTION 4
  representation; keyed scalar mapping; fixed KHPRF base point; additive point
  and scalar sharing; domain-separated bucket components). Primitive layer only:
  no IndexOutsource, no private equality, no Beaver, no B2A, no runner.
- **PHASE 4:** Position + secret Validity.
- **PHASE 5:** solve hiding of `phi_h` in Anchor Aggregation again.
- **PHASE 6:** Candidate Compaction.
- **PHASE 7:** KHPRF Routing.
- **PHASE 8:** Target Private Equality.
- **PHASE 9:** Target Position + Target Aggregation.
- **PHASE 10:** Candidate ID Generation.
- **PHASE 11:** the sole Candidate Discovery runner.
- **PHASE 12:** real workload and production E2E.

No later Candidate Discovery phase may begin until PHASE 5 passes both correctness and single-party security audits.
