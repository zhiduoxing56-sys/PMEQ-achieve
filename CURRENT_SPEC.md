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

`k_B` is held only by the DO and authorized Query User. CS0 and CS1 do not know it.

Anchor Match uses a 128-bit DPF with security parameter 128 and GGM depth 128. The old 64-bit DPF is permanently retired from the production path.

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
