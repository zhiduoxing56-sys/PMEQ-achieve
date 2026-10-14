#!/usr/bin/env python3
"""Audit one finished bucket run and write its immutable checkpoint files."""
import csv
import hashlib
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bits = int(sys.argv[1])
name = sys.argv[2]
suffix = sys.argv[3] if len(sys.argv) > 3 else ""
run = root / "results/bucket-count-candidate-final-20260923" / name
old = root / "results/bucket-count-candidate-20260923/candidate-raw.csv"
assert 14 <= bits <= 17 and run.is_dir()

def rows(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def write_csv(path, records):
    with path.open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)

baseline = defaultdict(list)
for row in rows(old):
    baseline[int(row["query_id"])].append(row)
assert len(baseline) == 854 and all(len(v) == 3 for v in baseline.values())
expected = {}
for q, triples in baseline.items():
    assert len({r["pair_sha256"] for r in triples}) == 1
    expected[q] = (triples[0]["pair_sha256"], triples[0]["tau_anchor"], triples[0]["tau_target"])

rawpath = run / "candidate-raw.csv"
raw = rows(rawpath)
assert len(raw) == 854 * 3, len(raw)
assert "\nPASS\n" in (run / "run.log").read_text()
assert len({r["packet_id_sha256"] for r in raw}) == len(raw)
by_query = defaultdict(list)
for row in raw:
    q = int(row["query_id"])
    assert int(row["b"]) == bits and int(row["B"]) == 1 << bits
    assert (row["pair_sha256"], row["tau_anchor"], row["tau_target"]) == expected[q]
    assert row["matches_default"] == "true"
    assert all(row[x] == "0" for x in ("FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id"))
    by_query[q].append(row)
assert len(by_query) == 854 and set(by_query) == set(expected)

medians = []
checks = []
for q, triples in by_query.items():
    assert sorted(int(x["trial"]) for x in triples) == [1, 2, 3]
    assert len({x["pair_sha256"] for x in triples}) == 1
    for field in ("K", "route_count", "target_slots", "groups", "final_pairs", "oracle_pairs"):
        assert len({x[field] for x in triples}) == 1, (q, field)
    medians.append(dict(B=1 << bits, b=bits, query_id=q,
                        candidate_discovery_ms=statistics.median(float(x["candidate_discovery_ms"]) for x in triples),
                        online_bytes=statistics.median(int(x["online_bytes"]) for x in triples),
                        K=int(triples[0]["K"]), route_count=int(triples[0]["route_count"]),
                        target_slots=int(triples[0]["target_slots"])))
    checks.append(dict(B=1 << bits, b=bits, query_id=q, trials=3,
                       candidate_pairs=triples[0]["final_pairs"], oracle_pairs=triples[0]["oracle_pairs"],
                       pair_sha256=triples[0]["pair_sha256"], trials_identical="true",
                       matches_plaintext="true", matches_default="true",
                       FP=0, FN=0, duplicates=0, wrong_anchor_id=0, wrong_target_id=0))
medians.sort(key=lambda x: x["query_id"])
checks.sort(key=lambda x: x["query_id"])

buildpath = run / "build-and-storage.json"
build = json.loads(buildpath.read_text())
assert build["N"] == 120071 and build["TargetInput"]["RawRows"] == 67896
cloud = [sum(v[p] for key, v in build["Static"].items() if key != "Public manifests") for p in (0, 1)]
total = sum(cloud)
summary = dict(B=1 << bits, b=bits, query_count=854,
               mean_candidate_discovery_ms=statistics.mean(x["candidate_discovery_ms"] for x in medians),
               mean_online_mib=statistics.mean(x["online_bytes"] for x in medians) / 2**20,
               mean_target_slots=statistics.mean(x["target_slots"] for x in medians),
               bsmj_padded_postings=build["AnchorIndex"]["PaddedSlots"],
               psmj_padded_postings=build["TargetIndex"]["PaddedSlots"],
               static_storage_gib=total / 2**30)
storage = dict(B=1 << bits, b=bits, cs0_static_bytes=cloud[0], cs1_static_bytes=cloud[1],
               total_static_bytes=total, static_storage_gib=total / 2**30,
               accounting=build["StaticAccounting"], components=build["Static"])
write_csv(run / f"summary{suffix}.csv", [summary])
write_csv(run / f"correctness{suffix}.csv", checks)
write_csv(run / f"query-medians{suffix}.csv", medians)
with (run / f"build-storage-summary{suffix}.json").open("x") as f:
    json.dump(storage, f, indent=2)
    f.write("\n")
with (run / f"checkpoint-provenance{suffix}.json").open("x") as f:
    json.dump(dict(raw_sha256=digest(rawpath), build_sha256=digest(buildpath), baseline_sha256=digest(old)), f, indent=2)
    f.write("\n")
print(json.dumps(summary))
