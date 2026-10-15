#!/usr/bin/env python3
"""Read-only extraction of v3 public workload/resource metrics."""

import json
import os
from pathlib import Path


ROOT = Path.cwd()
PRIVATE = ROOT / ".private"
DEST = Path(__file__).with_name("summary.json")
CASES = {
    "matrix_first": "d6fc203b8ea19238312a43a7ebd7c448",
    "zero_first": "5fbf27364c1703fcd148e32f974ace21",
    "zero_tail": "c537df9f00a0a4d8be5b361e05e1a2a0",
    "matrix_tail": "f1e0fa4da0a7b0a1759219ae2e7509f9",
}


def tree_bytes(root):
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())


def free_bytes(path):
    s = os.statvfs(path)
    return s.f_bavail * s.f_frsize


def main():
    stock = PRIVATE / "imdb-v3-scmp-stock"
    ledger = json.loads((stock / "ledger.json").read_text())
    manifest = json.loads((stock / "manifest.json").read_text())
    cases = {}
    for name, ticket in CASES.items():
        run = PRIVATE / "imdb-v3-query-results" / ticket
        ticket_dir = PRIVATE / "imdb-v3-tickets" / ticket
        metrics = json.loads((run / "metrics.json").read_text())
        complete = json.loads((run / "complete.json").read_text())
        m = metrics["metrics"]
        claim = ledger["Admissions"][ticket]
        cases[name] = {
            "ticket": ticket,
            "ticket_bytes": tree_bytes(ticket_dir),
            "user_material_bytes": (ticket_dir / "user/material.bin").stat().st_size,
            "cs0_material_bytes": (ticket_dir / "cs0/material.bin").stat().st_size,
            "cs1_material_bytes": (ticket_dir / "cs1/material.bin").stat().st_size,
            "guaranteed_slots": claim["Guarantee"],
            "claimed_slots": claim["Count"],
            "start_slot": claim["Start"],
            "both_roles_claimed": claim["RoleClaim"],
            "both_roles_finished": claim["RoleFinish"],
            "closed": claim["Closed"],
            "burned_failure": claim["Burned"],
            "candidate_pairs": complete["pair_count"],
            "pairs_sha256": complete["pairs_sha256"],
            "K": m["K"],
            "routes": m["Routes"],
            "groups": m["Groups"],
            "slots": m["Slots"],
            "cloud_ns": m["Cloud"],
            "target_position_ns": m["TargetPosition"],
            "target_aggregation_ns": m["TargetAggregation"],
            "stock_claim_ns_by_role": m.get("StockClaim"),
            "stock_read_ns_by_role": m.get("StockRead"),
            "correction_local_ns_by_role": m.get("StockCorrectionLocal"),
            "correction_wait_ns_by_role": m.get("StockCorrectionWait"),
            "correction_new_intercloud_bytes": 2 * (37 + 77 + 8 * m["Slots"]),
            "correction_new_rounds": 1,
            "server_bytes": m["ServerBytes"],
            "peak_go_heap_bytes": m["PeakHeap"],
            "process_until_result_ns": metrics["process_until_result_ns"],
            "index_verify_ns": metrics["index_verify_ns"],
            "ticket_load_ns": metrics["ticket_load_ns"],
        }
    next_free = ledger["NextFree"]
    capacity = manifest["Capacity"]
    summary = {
        "stock": {
            "bank_id": bytes(manifest["BankID"]).hex(),
            "initial_slots": capacity,
            "record_bytes_per_role": manifest["RecordBytes"],
            "total_stock_bytes": tree_bytes(stock),
            "claimed_or_burned_slots": next_free,
            "unbound_slots": capacity - next_free,
            "worst_case_replenishment_slots": max(0, 1920000 - (capacity - next_free)),
            "admissions": len(ledger["Admissions"]),
        },
        "cases": cases,
        "v3_zero_label_bytes": tree_bytes(PRIVATE / "imdb-v3-target-zero-labels"),
        "windows_c_free_bytes_at_collection": free_bytes("/mnt/c"),
        "wsl_output_free_bytes_at_collection": free_bytes(PRIVATE),
    }
    DEST.write_text(json.dumps(summary, indent=2) + "\n")
    print(DEST)


if __name__ == "__main__":
    main()
