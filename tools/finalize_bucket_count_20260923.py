#!/usr/bin/env python3
"""Combine audited B=14/15/17 checkpoints with the existing formal B=16 run."""
import csv
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/bucket-count-candidate-final-20260923"
OLD = ROOT / "results/bucket-count-candidate-20260923"
STAGES = {14: OUT / "b14", 15: OUT / "formal-b15-v2", 17: OUT / "formal-b17"}
FIELDS = ("B", "b", "query_count", "mean_candidate_discovery_ms", "mean_online_mib", "mean_target_slots", "bsmj_padded_postings", "psmj_padded_postings", "static_storage_gib")
RAW_FIELDS = ("B", "b", "query_id", "tau_anchor", "tau_target", "trial", "candidate_discovery_ms", "online_bytes", "K", "route_count", "target_slots", "groups", "final_pairs", "oracle_pairs", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id", "matches_default", "pair_sha256", "packet_id_sha256")

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def read_csv(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))

def write_csv(path, rows, fields):
    with path.open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def write_text(path, value):
    with path.open("x") as f:
        f.write(value)

def normalized_old_raw():
    result = []
    for x in read_csv(OLD / "candidate-raw.csv"):
        result.append(dict(B=65536, b=16, query_id=x["query_id"], tau_anchor=x["tau_anchor"], tau_target=x["tau_target"], trial=x["trial"],
                           candidate_discovery_ms=float(x["local_e2e_ns"]) / 1e6,
                           online_bytes=x["total_online_bytes"], K=x["K"], route_count=x["routes"], target_slots=x["target_slots"],
                           groups=x["groups"], final_pairs=x["final_pairs"], oracle_pairs=x["oracle_pairs"],
                           FP=x["FP"], FN=x["FN"], duplicates=x["duplicates"], wrong_anchor_id=x["wrong_anchor_id"],
                           wrong_target_id=x["wrong_target_id"], matches_default=x["matches_default_bucket_result"],
                           pair_sha256=x["pair_sha256"], packet_id_sha256=x["packet_id_sha256"]))
    return result

def validate_raw(bits, rows, baseline):
    assert len(rows) == 854 * 3, (bits, len(rows))
    assert len({x["packet_id_sha256"] for x in rows}) == 2562
    by_query = defaultdict(list)
    for x in rows:
        q = int(x["query_id"])
        assert int(x["B"]) == 1 << bits and int(x["b"]) == bits
        assert x["matches_default"] == "true"
        assert all(x[f] == "0" for f in ("FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id"))
        if baseline is not None:
            assert x["pair_sha256"] == baseline[q]
        by_query[q].append(x)
    assert len(by_query) == 854
    for q, triples in by_query.items():
        assert sorted(int(x["trial"]) for x in triples) == [1, 2, 3]
        assert len({x["pair_sha256"] for x in triples}) == 1
    return by_query

def old_summary(raw):
    by_query = validate_raw(16, raw, None)
    med = []
    for q, x in sorted(by_query.items()):
        med.append(dict(B=65536, b=16, query_id=q,
                        candidate_discovery_ms=statistics.median(float(y["candidate_discovery_ms"]) for y in x),
                        online_bytes=statistics.median(int(y["online_bytes"]) for y in x),
                        K=int(x[0]["K"]), route_count=int(x[0]["route_count"]), target_slots=int(x[0]["target_slots"])))
    build = json.loads((OLD / "build-and-storage.json").read_text())
    static = sum(sum(v) for key, v in build["Static"].items() if key != "Public manifests")
    s = dict(B=65536, b=16, query_count=854,
             mean_candidate_discovery_ms=statistics.mean(x["candidate_discovery_ms"] for x in med),
             mean_online_mib=statistics.mean(x["online_bytes"] for x in med) / 2**20,
             mean_target_slots=statistics.mean(x["target_slots"] for x in med),
             bsmj_padded_postings=build["AnchorIndex"]["PaddedSlots"],
             psmj_padded_postings=build["TargetIndex"]["PaddedSlots"],
             static_storage_gib=static / 2**30)
    old = read_csv(OLD / "summary.csv")[0]
    for field in ("mean_candidate_discovery_ms", "mean_online_mib", "mean_target_slots"):
        assert abs(float(old[field]) - s[field]) < 1e-6, field
    assert abs(float(old["total_static_gib"]) - s["static_storage_gib"]) < 1e-9
    checks = []
    for q, triples in sorted(by_query.items()):
        checks.append(dict(B=65536, b=16, query_id=q, trials=3,
                           candidate_pairs=triples[0]["final_pairs"], oracle_pairs=triples[0]["oracle_pairs"],
                           pair_sha256=triples[0]["pair_sha256"], trials_identical="true",
                           matches_plaintext="true", matches_default="true", FP=0, FN=0,
                           duplicates=0, wrong_anchor_id=0, wrong_target_id=0))
    storage = dict(B=65536, b=16, cs0_static_bytes=sum(v[0] for key, v in build["Static"].items() if key != "Public manifests"),
                   cs1_static_bytes=sum(v[1] for key, v in build["Static"].items() if key != "Public manifests"), total_static_bytes=static,
                   static_storage_gib=static / 2**30, accounting=build["StaticAccounting"], components=build["Static"])
    return s, med, checks, storage, {q: triples[0]["pair_sha256"] for q, triples in by_query.items()}

def main():
    original = normalized_old_raw()
    prior_summary, prior_medians, prior_checks, prior_storage, baseline = old_summary(original)
    baseline_order = [int(x["query_id"]) for x in original if int(x["trial"]) == 1]
    baseline_tau = {int(x["query_id"]): (x["tau_anchor"], x["tau_target"]) for x in original}
    assert len(baseline_order) == 854 and len(set(baseline_order)) == 854
    raw = []
    medians = []
    checks = []
    summaries = []
    storage = {}
    capability = []
    hashes = {}
    for bits in (14, 15, 16, 17):
        if bits == 16:
            records, summary, median, correct, stat = original, prior_summary, prior_medians, prior_checks, prior_storage
            source = OLD
            status = "completed_existing_default"
        else:
            source = STAGES[bits]
            suffix = "-accounting-v2" if bits == 14 else ""
            required = ("candidate-raw.csv", f"summary{suffix}.csv", f"correctness{suffix}.csv", f"query-medians{suffix}.csv", f"build-storage-summary{suffix}.json")
            if not all((source / x).is_file() for x in required):
                log = source / "run.log"
                reason = "formal checkpoint missing"
                if log.is_file():
                    lines = log.read_text(errors="replace").splitlines()
                    reason = "; ".join(lines[-3:])[:400]
                capability.append(dict(B=1 << bits, b=bits, status="incomplete", reason=reason))
                continue
            records = read_csv(source / "candidate-raw.csv")
            summary = read_csv(source / f"summary{suffix}.csv")[0]
            median = read_csv(source / f"query-medians{suffix}.csv")
            correct = read_csv(source / f"correctness{suffix}.csv")
            stat = json.loads((source / f"build-storage-summary{suffix}.json").read_text())
            status = "completed"
        validate_raw(bits, records, baseline)
        for trial in (1, 2, 3):
            assert [int(x["query_id"]) for x in records if int(x["trial"]) == trial] == baseline_order, (bits, trial, "query order")
        assert all((x["tau_anchor"], x["tau_target"]) == baseline_tau[int(x["query_id"])] for x in records), (bits, "tau")
        assert len(median) == len(correct) == 854
        assert all(x["matches_plaintext"] == "true" and x["matches_default"] == "true" for x in correct)
        raw.extend(records)
        medians.extend(median)
        checks.extend(correct)
        summaries.append({key: summary[key] for key in FIELDS})
        storage[str(1 << bits)] = stat
        capability.append(dict(B=1 << bits, b=bits, status=status, reason="854 queries x 3; correct and default candidate sets identical"))
        for name in ("candidate-raw.csv", "build-and-storage.json", f"summary{'-accounting-v2' if bits == 14 else ''}.csv", f"correctness{'-accounting-v2' if bits == 14 else ''}.csv"):
            path = source / name
            hashes[str(path.relative_to(ROOT))] = digest(path)
    assert len(summaries) >= 3, "fewer than three complete B configurations"
    write_csv(OUT / "candidate-raw.csv", raw, RAW_FIELDS)
    write_csv(OUT / "query-medians.csv", medians, prior_medians[0].keys())
    write_csv(OUT / "correctness.csv", checks, prior_checks[0].keys())
    write_csv(OUT / "summary.csv", summaries, FIELDS)
    write_csv(OUT / "capability-final.csv", capability, ("B", "b", "status", "reason"))
    write_text(OUT / "build-and-storage.json", json.dumps(storage, indent=2, ensure_ascii=False) + "\n")
    notes = ["# Bucket-count results", "", "Full MusicBrainz database; the same 854 legal queries, three trials each. Each query's time and bytes use the trial median, followed by the mean across queries. MiB and GiB use powers of two. Static storage is full-domain accounting, not process RSS.", "", "| B | Candidate discovery (ms) | Online (MiB) | Target slots | Static (GiB) |", "|---:|---:|---:|---:|---:|"]
    for x in summaries:
        notes.append(f"| {x['B']} | {float(x['mean_candidate_discovery_ms']):.6f} | {float(x['mean_online_mib']):.6f} | {float(x['mean_target_slots']):.3f} | {float(x['static_storage_gib']):.6f} |")
    notes.append("")
    for a, b in zip(summaries, summaries[1:]):
        def d(field):
            delta = float(b[field]) - float(a[field])
            return "increased" if delta > 0 else "decreased" if delta < 0 else "was unchanged"
        notes.append(f"From B={a['B']} to B={b['B']}, time {d('mean_candidate_discovery_ms')}, online communication {d('mean_online_mib')}, target slots {d('mean_target_slots')}, and static storage {d('static_storage_gib')}.")
        slot_delta = float(b["mean_target_slots"]) - float(a["mean_target_slots"])
        for field, label in (("mean_candidate_discovery_ms", "Time"), ("mean_online_mib", "Online communication")):
            delta = float(b[field]) - float(a[field])
            relation = "the same direction" if delta * slot_delta > 0 else "opposite directions" if delta * slot_delta < 0 else "no direction in at least one value"
            notes.append(f"{label} and target slots moved in {relation} over that interval.")
    for x in capability:
        if x["status"] == "incomplete":
            notes.append(f"B={x['B']} incomplete: {x['reason']}.")
    write_text(OUT / "notes.md", "\n".join(notes) + "\n")
    sourcepaths = sorted((ROOT / "internal").rglob("*.go"))
    sourcehash = hashlib.sha256("".join(f"{p.relative_to(ROOT)} {digest(p)}\n" for p in sourcepaths).encode()).hexdigest()
    provenance = dict(source_set_sha256=sourcehash, source_file_count=len(sourcepaths),
                      source_provenance_note="B=65536 reuses the previously completed default run; B=16384 completed before the final 17-bit source-width patch; later widths use the resumed native binary.",
                      raw_and_summary_sha256=hashes,
                      formulas=dict(query="median of three trials", bucket="mean of 854 query medians", online_mib="bytes / 2^20", static_gib="both clouds' accounting bytes / 2^30"))
    write_text(OUT / "provenance.json", json.dumps(provenance, indent=2, ensure_ascii=False) + "\n")
    write_text(OUT / "run-command.txt", "B=16384: existing completed run in b14/run.log\nB=32768: cd internal/discovery && PMEQ_BUCKET_FINAL_OUTPUT=/home/tenggn/projects/clean_pmeq/results/bucket-count-candidate-final-20260923/formal-b15-v2 PMEQ_BUCKET_FINAL_BITS=15 /tmp/pmeq-bucket-final.test -test.run '^TestBucketCountFinal$' -test.v\nB=65536: reused results/bucket-count-candidate-20260923\nB=131072: see formal-b17/run.log\n")
    print(json.dumps(summaries, indent=2))

if __name__ == "__main__":
    main()
