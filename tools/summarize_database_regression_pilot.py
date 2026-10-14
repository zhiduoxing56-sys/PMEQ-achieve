"""Export only the new regression/pilot evidence; never alter old baselines."""
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/n-domain-regression-pilot-20260920"


def write_csv(name, rows):
    with (OUT / name).open("x", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    complete = json.loads((OUT / "completed.json").read_text())
    assert complete["status"] == "passed"
    baseline = json.loads((ROOT / "results/phase11-queries.json").read_text())
    expected_ids = [x["Query"] for x in baseline if not x["Rejected"]]
    query_csv, static_csv, summaries, scale_csv = [], [], [], []
    errors = ["FP", "FN", "Duplicates", "WrongAnchorID", "WrongTargetID"]
    for phase, n, count in (("regression-100", 120071, 854), ("pilot-20", 24014, 20), ("pilot-100", 120071, 20)):
        rows = [json.loads(x) for x in (OUT / f"{phase}-queries.jsonl").read_text().splitlines()]
        scale = json.loads((OUT / f"{phase}-summary.json").read_text())
        assert len(rows) == count and [r["Query"] for r in rows] == expected_ids[:count]
        assert all(r["N"] == n and all(r["Errors"][key] == 0 for key in errors) for r in rows)
        for r in rows:
            m = r["Metrics"]
            assert r["Recovered"] == r["Expected"] and r["FinalPairs"] == r["OraclePairs"]
            assert r["TotalBytes"] == sum(m["UserToCloud"]) + sum(m["CloudToUser"]) + m["ServerBytes"]
            if r["Scale"] == 100:
                b = baseline[r["Query"]]
                assert r["FinalPairs"] == b["Pairs"]
                assert all(m[key] == b["Metrics"][key] for key in ("K", "Routes", "Groups", "Slots", "UserToCloud", "CloudToUser", "ServerBytes"))
            query_csv.append(dict(phase=phase, scale_pct=r["Scale"], query_id=r["Query"], tau=r["Tau"], N=n,
                                  anchor_query=r["AnchorQuery"], target_query=r["TargetQuery"],
                                  **{key + "_ns": value for key, value in m.items() if isinstance(value, int) and key not in ("K", "Routes", "Groups", "Slots", "ServerBytes", "PeakHeap")},
                                  user_to_cs0_bytes=m["UserToCloud"][0], user_to_cs1_bytes=m["UserToCloud"][1],
                                  cs0_to_user_bytes=m["CloudToUser"][0], cs1_to_user_bytes=m["CloudToUser"][1],
                                  user_to_cloud_bytes=r["UserToCloud"], cs0_cs1_bytes=r["ServerBytes"],
                                  cloud_to_user_bytes=r["CloudToUser"], total_online_bytes=r["TotalBytes"],
                                  K=m["K"], routes=m["Routes"], groups=m["Groups"], target_slots=m["Slots"],
                                  final_pairs=r["FinalPairs"], oracle_pairs=r["OraclePairs"], **r["Errors"],
                                  static_preparation_ns=r["StaticPreparationNS"], provision_ns=r["ProvisionNS"]))
        for component, sizes in scale["Static"].items():
            static_csv.append(dict(phase=phase, component=component, cs0_bytes=sizes[0], cs1_bytes=sizes[1], total_bytes=sum(sizes),
                                   basis="semantic fields, not resident memory" if "fields" in component or "factors" in component else "sealed encoded bytes"))
        latency = [r["Metrics"]["LocalE2E"] / 1e6 for r in rows]
        def summary(values):
            return dict(total=sum(values), mean=statistics.mean(values), min=min(values), max=max(values))
        item = dict(phase=phase, scale_pct=rows[0]["Scale"], N=n, queries=count,
                    anchor_records=scale["AnchorInput"]["UsableRows"], target_records=scale["TargetInput"]["UsableRows"],
                    normal_indexed_target=scale["TargetInput"]["IndexedRecords"],
                    anchor_short=scale["AnchorInput"]["ShortNames"], target_short=scale["TargetInput"]["ShortNames"],
                    errors={key: sum(r["Errors"][key] for r in rows) for key in errors},
                    final_pairs=sum(r["FinalPairs"] for r in rows),
                    e2e_ms={**summary(latency), "p50": sorted(latency)[math.ceil(count*.5)-1], "p95": sorted(latency)[math.ceil(count*.95)-1]},
                    workload={key: summary([r["Metrics"][key] for r in rows]) for key in ("K", "Routes", "Groups", "Slots")},
                    communication={key: summary([r[key] for r in rows]) for key in ("UserToCloud", "ServerBytes", "CloudToUser", "TotalBytes")},
                    stages_mean_ms={key: statistics.mean(r["Metrics"][key]/1e6 for r in rows) for key in
                                    ("Token", "Anchor", "Compaction", "Routing", "TargetPE", "TargetPosition", "TargetAggregation", "OutputEncoding", "Recovery", "Cloud")},
                    static_total_bytes=sum(sum(x) for x in scale["Static"].values()),
                    index_build_ns=scale["IndexBuildNS"] if phase.startswith("pilot") else None,
                    index_build_note="fresh Anchor+Target builders" if phase.startswith("pilot") else "original fixture rebuilds Anchor, loads sealed Target; no fabricated full build time",
                    anchor_build_ns=scale["AnchorBuildNS"], target_build_ns=scale["TargetBuildNS"] if phase.startswith("pilot") else None)
        if phase.startswith("pilot"):
            ai, ti = scale["AnchorIndex"], scale["TargetIndex"]
            scale_csv.append(dict(phase=phase, N=n, anchor_records=item["anchor_records"], target_records=item["target_records"],
                                  normal_indexed_target=item["normal_indexed_target"], anchor_short=item["anchor_short"], target_short=item["target_short"],
                                  bsmj_real_postings=ai["RealSlots"], bsmj_padded_slots=ai["PaddedSlots"], bsmj_groups=ai["LogicalGroups"],
                                  psmj_real_postings=ti["RealSlots"], psmj_padded_slots=ti["PaddedSlots"], psmj_groups=ti["LogicalGroups"],
                                  anchor_build_ns=scale["AnchorBuildNS"], target_build_ns=scale["TargetBuildNS"], index_build_ns=scale["IndexBuildNS"],
                                  payload_build_ns=scale["PayloadBuildNS"], sidecar_build_ns=scale["SidecarBuildNS"],
                                  static_accounted_bytes=item["static_total_bytes"]))
            item["index"] = scale_csv[-1]
        summaries.append(item)
    assert summaries[0]["final_pairs"] == 1510
    write_csv("queries.csv", query_csv)
    write_csv("pilot-scales.csv", scale_csv)
    write_csv("static.csv", static_csv)
    report = dict(status="passed", pilot_only=True, warmups=0, invocations_per_query=1,
                  summaries=summaries, summarizer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with (OUT / "summary.json").open("x") as f:
        json.dump(report, f, indent=2); f.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
