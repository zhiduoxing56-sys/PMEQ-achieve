#!/usr/bin/env python3
"""Summarize measured Anchor partitions without changing PHASE11 evidence."""
import json
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def stats(values):
    ordered = sorted(values)
    return [statistics.mean(ordered)] + [
        ordered[math.ceil(len(ordered) * p) - 1]
        for p in (.5, .9, .95, .99, 1)
    ]


def main():
    rows = json.loads((RESULTS / "anchor-breakdown-queries.json").read_text())
    valid = [r for r in rows if not r["Rejected"]]
    assert len(rows) == 1003 and len(valid) == 854
    assert sum(r["Pairs"] for r in valid) == 1510
    metrics = [r["Metrics"] for r in valid]
    for m in metrics:
        assert sum(m["AnchorParts"].values()) == m["Anchor"]
        assert all(x >= 0 for x in m["AnchorParts"].values())
        assert max(sum(p.values()) for p in m["AnchorPartyParts"]) == m["Anchor"]

    stages = [
        ("Anchor Match / Position / Hit AND", ["Filter"]),
        ("Hit B2A", ["HitB2A"]),
        ("1. Bucket-local E_h x_h", ["Incidence"]),
        ("2a. F -> z SCMP", ["FCompare"]),
        ("2b. z B2A", ["ZB2A"]),
        ("2. F -> z + B2A subtotal (do not add again)", ["FCompare", "ZB2A"]),
        ("3. D_h -> N alignment", ["Alignment"]),
        ("4. CountParty.Add", ["Count"]),
        ("5. Keep comparison on N", ["Keep"]),
        ("Other / entry / loop / timer overhead", ["Other"]),
    ]
    data = [(name, [sum(m["AnchorParts"][k] for k in keys) / 1e6 for m in metrics])
            for name, keys in stages]
    data += [("Anchor total", [m["Anchor"] / 1e6 for m in metrics]),
             ("6. Exact-K compaction (outside Anchor)", [m["Compaction"] / 1e6 for m in metrics])]
    lines = [
        "# Anchor wall-time breakdown",
        "Repository: `/home/tenggn/projects/clean_pmeq`. Base HEAD: "
        "`49cc443a33d11e2ea3466dd39f1797b5de2a287e`; measurements include only the added instrumentation.",
        "Full actual integrated chain: 1003 historical queries;149 rejected without clamping;"
        "854 valid;1510 pairs;FP/FN/duplicates/wrong IDs all zero. Offline provisioning and "
        "oracle comparison are outside online timers. Original PHASE11 files are unchanged.",
        "These are NEW measurements, not a retrospective split or rescaling of the historical "
        "236.705800 ms Anchor mean. Hardware load, runtime scheduling and allocation/GC affect wall time. "
        "No protocol or parameter changes are included.",
        "For each query the original Anchor metric is max(CS0 Anchor,CS1 Anchor). The partition uses "
        "ALL categories from that same slower party, not independently maximized categories. Both "
        "parties' complete partitions are retained in AnchorPartyParts. Stage durations include encoded "
        "message exchange, waits, allocation and GC occurring in that interval. They are not isolated CPU timings.",
        "Milliseconds;mean primary;nearest-rank quantiles. Mean of component sums equals sum of component "
        "means. Quantiles of separate components must not be added.",
        "",
        "| component | mean | p50 | p90 | p95 | p99 | max |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, values in data:
        lines.append("| " + name + " | " + " | ".join(f"{v:.6f}" for v in stats(values)) + " |")
    lines += [
        "",
        "## Exact timing boundaries",
        "",
        "- Filter: PrepareParty through EvalPosition and both Hit AND layers, summed over occurrences.",
        "- Hit B2A: endpoint.b2a(hit,ap.hit), separate from incidence multiplication.",
        "- Incidence: NewAggregator, all 64-slot BeginChunk/FinishChunk masked exchanges, and Result. No Hit B2A included.",
        "- FCompare: endpoint.compare(f,ap.f,t.f[h],backend). ZB2A: endpoint.b2a(z,ap.z).",
        "- Alignment: both masked messages, padding/encoding/decoding, Stage0.Message2 (including "
        "ExpandRho), and Stage1.Finish; summed over occurrences. Output length N=120071.",
        "- Count: only CountParty.Add over each length-N y_h. NewCount allocation is in Other.",
        "- Keep: CountParty.Values copy, masked opening, SCMP Finish over N, and AlignOutput binding checks.",
        "- Other: Anchor total minus these nonoverlapping intervals; includes initial decode/guards/count "
        "allocation, bucket lookup, loop cleanup and instrumentation gaps.",
        "- Exact-K: unchanged original independent timer from Compaction1.Begin through both "
        "shuffle stages, Keep opening and Extract. Not part of Anchor total.",
        "",
        "Sources: internal/discovery/cloud.go (runParty), local.go (AnchorBreakdown/Metrics/RunLocal), "
        "real_native_test.go (TestIntegratedReal). No reference-derived intermediates are used.",
        "",
        "## Reproduce",
        "",
        "```sh",
        "PMEQ_PHASE11=1 PMEQ_ANCHOR_TIMING=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/anchor-timing-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestIntegratedReal$' -count=1 -timeout=90m -v",
        "python3 tools/summarize_anchor_breakdown.py",
        "```",
    ]
    (RESULTS / "anchor-breakdown.md").write_text("\n\n".join(lines[:5]) + "\n\n" + "\n".join(lines[5:]) + "\n")
    for name, values in data:
        print(f"{name}: mean={statistics.mean(values):.6f} ms")


if __name__ == "__main__":
    main()
