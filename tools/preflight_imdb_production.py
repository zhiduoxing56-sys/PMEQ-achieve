#!/usr/bin/env python3
"""Public, read-only preflight for the single 100k x 10k IMDb production run."""
import argparse
import hashlib
import json
import os
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "imdb_production_20261015"
PROPOSAL = ROOT / "reports/production-handoff-20261015/evidence/final-scale-proposals.json"


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--launch-gate", action="store_true", help="exit nonzero until every production start condition is met")
    args.add_argument("--output", type=Path)
    opt = args.parse_args()
    manifest = json.loads((SAMPLE / "manifest.json").read_text())
    proposal = json.loads(PROPOSAL.read_text())
    assert manifest["version"] == "IMDB-100K-10K-20261015-v1"
    assert manifest["anchor_count"] == 100000 and manifest["target_count"] == 10000
    assert manifest["anchor_object_id_sequence_sha256"] == proposal["anchor"]["id_digest"]
    assert manifest["target_tconst_sequence_sha256"] == proposal["configurations"][0]["target_id_digest"]
    for name, stamp in manifest["files"].items():
        p = SAMPLE / name
        assert p.stat().st_size == stamp["bytes"] and sha(p) == stamp["sha256"], name
    assert sha(ROOT / "imdb_final_dataset/data/imdb_final.duckdb") == manifest["mother_database_sha256"]
    assert sha(ROOT / "imdb_final_dataset/provenance/source_manifest.json") == manifest["source_manifest_sha256"]
    c = duckdb.connect()
    anchor = str(SAMPLE / "MOVIECAST.parquet")
    target = str(SAMPLE / "MOVIE.parquet")
    source = str(SAMPLE / "MOVIECAST_SOURCE.parquet")
    count = c.execute(f"""SELECT (SELECT count(*) FROM read_parquet('{anchor}')),
       (SELECT count(*) FROM read_parquet('{target}')),
       (SELECT count(*) FROM read_parquet('{source}')),
       (SELECT count(DISTINCT tconst) FROM read_parquet('{anchor}'))""").fetchone()
    assert count == (100000, 10000, 100000, 8895)
    max_repeat = c.execute(f"""WITH grams AS (
       SELECT tconst, substr(primaryTitle, i, 4) gram
       FROM read_parquet('{target}'), generate_series(1, greatest(0,length(primaryTitle)-3)) x(i))
       SELECT max(n) FROM (SELECT tconst,gram,count(*) n FROM grams GROUP BY tconst,gram)""").fetchone()[0]
    assert max_repeat == 4
    budget = next(row for row in proposal["configurations"][0]["offline_classes"] if row["public_C"] == 10000)
    mem = next(int(line.split()[1])*1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    disk = os.statvfs(SAMPLE).f_bavail * os.statvfs(SAMPLE).f_frsize
    static = budget["static_semantic_bytes_including_sigma"]
    offline = budget["static_plus_one_offline_batch_semantic_bytes"] - static
    # Two durable party copies plus one full staging copy. This is a planning
    # floor, not a measured peak or a claim that Go's heap follows wire bytes.
    disk_floor = 3 * static + 2 * offline
    result = {
        "version": manifest["version"], "sample_file_hashes_verified": True,
        "mother_database_unchanged": True, "anchor_objects": count[0], "target_objects": count[1],
        "source_objects": count[2], "covered_movies": count[3], "max_target_q4_repeat": max_repeat,
        "public_C": 10000, "q": 4, "signatures_each": 4, "bucket_count": 65536,
        "D_target": 26, "position_bin": 10, "position_max": 270,
        "math_domains": {"object_and_join": "uint64 / Ring64 shares", "positions": "Ring32 shares; SCMP Bin10/Bout1", "anchor_labels": "GF(2^16)", "counts_and_matrix": "Z/128Z", "hits": "F2"},
        "layout": {"anchor_real_postings": proposal["anchor"]["real_postings"], "anchor_padded_slots": proposal["anchor"]["padded_slots"], "anchor_nonempty_buckets": proposal["anchor"]["nonempty_buckets"], "target_real_postings": proposal["configurations"][0]["target_real_postings"], "target_padded_slots": proposal["configurations"][0]["target_padded_slots"], "target_max_bucket_slots": 44, "target_max_bucket_groups": 11},
        "bytes": {"anchor_cs1_sigma_one_party": proposal["anchor"]["sigma_bytes_CS1_at_N100000"],
                  "anchor_index_both": proposal["anchor"]["anchor_index_semantic_bytes_both"],
                  "target_matrix_both": proposal["configurations"][0]["target_matrix_sidecar_bytes_both_D26"],
                  "target_position_offline_both": budget["target_position_correlated_field_bytes_both"],
                  "target_matrix_offline_both": budget["target_matrix_offline_field_bytes_both"],
                  "target_PE_offline_both": budget["target_PE_field_bytes_both"],
                  "anchor_global_offline_both": budget["anchor_global_offline_field_bytes_both"],
                  "anchor_local_max_shape_offline_both": budget["anchor_local_maximum_shape_offline_field_bytes_both"],
                  "static_semantic_total": static, "one_offline_batch": offline,
                  "static_plus_offline": static+offline,
                  "memory_planning_1p5_plus_2GiB": budget["planning_budget_1p5_times_plus_2GiB"],
                  "disk_two_copies_plus_stage_floor": disk_floor,
                  "mem_available_now": mem, "disk_available_now": disk},
        "peak_temporary_copy": "Current DO builds permutation, rho, sigma and party artifacts in memory; no measured heap upper bound. One sigma bucket is 400000 bytes; all 53116 are 21246400000 bytes.",
        "query_execution": {"candidate_slots": 10000, "target_routes": 40000, "S_bound": budget["S_bound"], "G_bound": budget["G_bound"], "one_time_material_burn": True},
        "startup_conditions": {
            "memory_budget_now": mem >= budget["planning_budget_1p5_times_plus_2GiB"],
            "disk_planning_floor_now": disk >= disk_floor,
            "actual_keyed_bucket_layout_verified": False,
            "bucket_local_sigma_persistence_and_lazy_loading_implemented": False,
            "measured_DO_and_cloud_peak_heap": False,
            "movie_DO_build_and_recovery_entrypoints_complete": False,
        },
    }
    result["ready_to_launch"] = all(result["startup_conditions"].values())
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if opt.output:
        if opt.output.exists():
            raise SystemExit(f"refusing to overwrite existing preflight result: {opt.output}")
        opt.output.write_text(rendered)
    else:
        print(rendered)
    if opt.launch_gate and not result["ready_to_launch"]:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
