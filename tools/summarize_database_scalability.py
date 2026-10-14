"""Validate formal raw records and write separate, exclusive derived outputs."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
ERRORS = ("FP", "FN", "Duplicates", "WrongAnchorID", "WrongTargetID")
WORK = ("K", "Routes", "Groups", "Slots", "FinalPairs")
COMM = ("UserToCloud", "ServerBytes", "CloudToUser", "TotalBytes")


def quantile(values, p):
    values = sorted(values)
    x = (len(values) - 1) * p
    lo = math.floor(x)
    return values[lo] + (values[min(lo + 1, len(values) - 1)] - values[lo]) * (x - lo)


def stats(values):
    return dict(mean=statistics.mean(values), median=statistics.median(values),
                p95=quantile(values, .95), p99=quantile(values, .99),
                total=sum(values), minimum=min(values), maximum=max(values))


def describe(rows):
    return dict(queries=len(rows), time_ms=stats([x["LocalE2E"] / 1e6 for x in rows]),
                communication_bytes={k: stats([x[k] for x in rows]) for k in COMM},
                workload={k: stats([x[k] for x in rows]) for k in WORK},
                errors={k: sum(x[k] for x in rows) for k in ERRORS},
                stages_mean_ms={k: statistics.mean(x[k] for x in rows)/1e6 for k in
                                ("Token", "Anchor", "Compaction", "Routing", "TargetPE",
                                 "TargetPosition", "TargetAggregation", "OutputEncoding", "Recovery", "Cloud")})


def write_json(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def write_csv(path, rows):
    with path.open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(out):
    out = out.resolve()
    assert out.is_relative_to(ROOT / "results")
    complete = json.loads((out / "completed.json").read_text())
    assert complete["status"] == "passed"
    plan = json.loads((out / "plan.json").read_text())
    base = json.loads((ROOT / "results/phase11-queries.json").read_text())
    expected_ids = [x["Query"] for x in base if not x["Rejected"]][:complete["queries_per_round"]]
    assert plan["query_ids"] == expected_ids
    rounds, scales, static_rows, scale_rows, audits = [], [], [], [], []
    packet_ids = set()
    previous_ids = set()
    for scale in complete["scales"]:
        sd = out / f"scale-{scale}"
        state = json.loads((sd / "static.json").read_text())
        subset = json.loads((sd / "subset.json").read_text())
        final = json.loads((sd / "completion.json").read_text())
        s = state["scale"]
        assert state["static_build_count"] == final["static_build_count"] == 1
        assert final["provisions"] == final["unique_packet_ids"] == 1 + complete["rounds"] * len(expected_ids)
        assert state["all_indexed_anchor_buckets_materialized"]
        n = {20: 24014, 40: 48028, 60: 72042, 80: 96056, 100: 120071}[scale]
        assert n == s["N"] == subset["N"] == final["N"]
        ids = set(subset["AnchorIDs"])
        assert len(ids) == n and previous_ids < ids
        previous_ids = ids
        pooled, means = [], []
        for round_id in range(1, complete["rounds"] + 1):
            rd = sd / f"round-{round_id}"
            finish = json.loads((rd / "completion.json").read_text())
            rows, got_ids = [], []
            with (rd / "queries.jsonl").open() as raw, (rd / "queries.csv").open(newline="") as cf:
                csv_rows = csv.DictReader(cf)
                for order, line in enumerate(raw):
                    r = json.loads(line)
                    c = next(csv_rows)
                    m = r["Metrics"]
                    assert r["Scale"] == scale and r["Round"] == round_id and r["Order"] == order and r["N"] == n
                    assert r["Query"] == expected_ids[order]
                    assert r["TauAnchor"] == r["TauTarget"] == r["Tau"]
                    assert r["StaticSHA256"] == state["static_sha256"] == finish["static_sha256"]
                    assert r["PacketIDHash"] not in packet_ids
                    packet_ids.add(r["PacketIDHash"])
                    assert not any(r["Errors"].values())
                    assert r["Recovered"] == r["Expected"] and r["FinalPairs"] == r["OraclePairs"]
                    assert r["UserToCloud"] == sum(m["UserToCloud"])
                    assert r["CloudToUser"] == sum(m["CloudToUser"])
                    assert r["ServerBytes"] == m["ServerBytes"]
                    assert r["TotalBytes"] == r["UserToCloud"] + r["CloudToUser"] + r["ServerBytes"]
                    evidence = r["DomainEvidence"]
                    for key, value in evidence.items():
                        if isinstance(value, int):
                            assert value == n, (scale, round_id, r["Query"], key)
                        elif isinstance(value, list):
                            assert all(x == n for x in value)
                    assert r["Offline"]["Compaction"] == 266 * n
                    if scale == 100:
                        b = base[r["Query"]]
                        assert r["FinalPairs"] == b["Pairs"]
                        assert all(m[k] == b["Metrics"][k] for k in ("K", "Routes", "Groups", "Slots", "UserToCloud", "CloudToUser", "ServerBytes"))
                    checks = dict(scale=scale, round=round_id, query=r["Query"], order=order, N=n,
                                  tau_anchor=r["Tau"], tau_target=r["Tau"], local_e2e_ns=m["LocalE2E"],
                                  K=m["K"], routes=m["Routes"], groups=m["Groups"], target_slots=m["Slots"],
                                  final_pairs=r["FinalPairs"], oracle_pairs=r["OraclePairs"],
                                  user_cs0_bytes=m["UserToCloud"][0], user_cs1_bytes=m["UserToCloud"][1],
                                  cs0_user_bytes=m["CloudToUser"][0], cs1_user_bytes=m["CloudToUser"][1],
                                  intercloud_bytes=m["ServerBytes"], total_online_bytes=r["TotalBytes"])
                    assert all(int(c[k]) == value for k, value in checks.items())
                    assert c["static_sha256"] == r["StaticSHA256"] and c["packet_id_hash"] == r["PacketIDHash"]
                    assert json.loads(c["AnchorParts"]) == m["AnchorParts"]
                    assert json.loads(c["AnchorPartyParts"]) == m["AnchorPartyParts"]
                    for key in ("Token", "Anchor", "Compaction", "Routing", "TargetPE", "TargetPosition", "TargetAggregation", "OutputEncoding", "Recovery", "Cloud"):
                        assert int(c[key + "_ns"]) == m[key]
                    rows.append({**{k: v for k, v in m.items() if isinstance(v, int)},
                                 **{k: r[k] for k in COMM}, "FinalPairs": r["FinalPairs"], **r["Errors"]})
                    got_ids.append(r["Query"])
                assert next(csv_rows, None) is None
            assert got_ids == expected_ids and finish["queries"] == len(rows)
            item = dict(scale=scale, round=round_id, N=n, **describe(rows))
            assert abs(item["time_ms"]["mean"] - finish["mean_ms"]) < 1e-9
            if scale == 100:
                assert item["workload"]["FinalPairs"]["total"] == 1510
                assert abs(item["time_ms"]["mean"] / plan["calibration_mean_ms"] - 1) <= .1
            means.append(item["time_ms"]["mean"])
            rounds.append(item)
            pooled.extend(rows)
        spread = (max(means) - min(means)) / min(means)
        assert spread <= .1
        item = dict(scale=scale, N=n, round_means_ms=means, mean_of_round_means_ms=statistics.mean(means),
                    relative_spread=spread, pooled=describe(pooled), static=s,
                    static_construction_ns=state["static_construction_ns"], static_sha256=state["static_sha256"])
        scales.append(item)
        scale_rows.append(dict(scale=scale, N=n, anchor_records=s["AnchorInput"]["UsableRows"],
                               target_records=s["TargetInput"]["UsableRows"], normal_target=s["TargetInput"]["IndexedRecords"],
                               anchor_short=s["AnchorInput"]["ShortNames"], target_short=s["TargetInput"]["ShortNames"],
                               anchor_build_ns=s["AnchorBuildNS"], target_build_ns=s["TargetBuildNS"],
                               index_build_ns=s["IndexBuildNS"], static_build_ns=state["static_construction_ns"],
                               BSMJ=json.dumps(s["AnchorIndex"]), PSMJ=json.dumps(s["TargetIndex"])))
        for component, sizes in s["Static"].items():
            static_rows.append(dict(scale=scale, component=component, cs0_bytes=sizes[0], cs1_bytes=sizes[1], total_bytes=sum(sizes)))
        audits.append(dict(scale=scale, queries=len(pooled), errors=item["pooled"]["errors"],
                           immutable_static=True, fresh_material=True, strict_nested=True, actual_N=n))
    derived = out / "derived"
    derived.mkdir(exist_ok=False)
    write_json(derived / "formal-summary.json", dict(status="passed", mode=complete["mode"],
               quantile="linear (n-1)*p", rounds=rounds, scales=scales))
    write_json(derived / "correctness-audit.json", audits)
    write_json(derived / "round-statistics.json", rounds)
    write_csv(derived / "scale-statistics.csv", scale_rows)
    write_csv(derived / "static-state.csv", static_rows)
    write_csv(derived / "round-statistics.csv", [dict(scale=x["scale"], round=x["round"], N=x["N"],
              **x["time_ms"], communication=json.dumps(x["communication_bytes"]), workload=json.dumps(x["workload"]),
              correctness=json.dumps(x["errors"])) for x in rounds])
    write_csv(derived / "formal-summary.csv", [dict(scale=x["scale"], N=x["N"],
              round_means_ms=json.dumps(x["round_means_ms"]), mean_of_round_means_ms=x["mean_of_round_means_ms"],
              relative_spread=x["relative_spread"], pooled_mean_ms=x["pooled"]["time_ms"]["mean"],
              pooled_median_ms=x["pooled"]["time_ms"]["median"], pooled_p95_ms=x["pooled"]["time_ms"]["p95"],
              pooled_p99_ms=x["pooled"]["time_ms"]["p99"],
              **{k+"_mean_bytes": x["pooled"]["communication_bytes"][k]["mean"] for k in COMM},
              workload=json.dumps(x["pooled"]["workload"])) for x in scales])
    return derived


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        assert quantile([1, 2, 3, 4], .5) == 2.5
        assert quantile([1, 2, 3, 4], .95) == 3.8499999999999996
        assert stats([1, 2, 3])["mean"] == 2
        print("summary unit checks passed")
    else:
        assert args.output is not None
        print(summarize(args.output))
