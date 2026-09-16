These are read-only copies of existing validated component results, used only
for cost projection. CSV line endings are normalized to LF; values are unchanged.
No old runtime source was migrated.

- target_position_real_benchmark.csv: old repository results with this name;
  Villesse, one worker, skip_invalid=0, 116991 slots, 30 runs, zero errors.
  pos_scmp_ms=70.615 is the max of party-local durations, averaged over runs.
- phase5b2-scmp-f95.txt: existing native clean-phase component log, n=6560,
  Bin7/Bout1, 284 key bytes per comparison per cloud, corrected_errors=0.
- ../phase7b-pe-reference.jsonl: five fresh reruns of the EXISTING standalone
  /tmp/phase5a-target/release/boolean_equality_audit (256 bits, one worker).
  The /tmp source hash equals the read-only old Rust source, SHA256:
  1eefbb407b9e1cfdaa5e9ac6553f3bd3d69957c2f9ec76d52424020a6f33357d.
  This remains an isolated benchmark, not an implemented Target PE stage.

No network latency or complete Target filtering time is inferred from these
component results. See the report for exact batching and opening assumptions.
