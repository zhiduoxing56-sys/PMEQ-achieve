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

- **IndexOutsource:** awaiting an entirely new implementation.
- **Anchor Match:** design frozen; primitive awaiting migration verification.
- **Anchor Position Filtering:** comparison primitive awaiting migration/re-verification.
- **Anchor Record Aggregation:** mathematical specification frozen; no current production implementation; PHASE 5 blocker.
- **Anchor Keep:** depends on secure aggregation and comparison.
- **Candidate Compaction:** candidate primitive exists; awaits a later independent migration audit.
- **KHPRF Routing:** design frozen; awaits a later independent migration audit.
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
