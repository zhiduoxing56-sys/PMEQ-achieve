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

Padding exists. `L_pad` may be public. Validity is secret-shared between the two parties per slot: `real = 1`, `dummy = 0`. No single cloud may determine real/dummy directly from its local state.

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

Target DPF is permanently retired. The Target stored group key is `Z = Z0 XOR Z1`, where `Z0` and `Z1` are each 256 bits. Target Match is full-256-bit Private Equality.

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
