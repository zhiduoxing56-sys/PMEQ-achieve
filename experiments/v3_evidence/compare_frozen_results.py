#!/usr/bin/env python3
"""Compare recovered cryptographic pairs with frozen plaintext and v2 output."""

import argparse
import json
from collections import Counter
from pathlib import Path


def recovered(path):
    raw = json.loads(Path(path).read_text())
    return Counter(
        (p["Anchor"]["anchor_id"], p["Anchor"]["objectId"], p["Target"]["target_id"], p["Target"]["tconst"])
        for p in raw["Pairs"]
    )


def oracle(path):
    raw = json.loads(Path(path).read_text())
    return Counter((p["anchor_id"], p["objectId"], p["target_id"], p["tconst"]) for p in raw["pairs"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--v3", required=True)
    parser.add_argument("--v2", required=True)
    parser.add_argument("--oracle", required=True)
    args = parser.parse_args()
    got, old, want = recovered(args.v3), recovered(args.v2), oracle(args.oracle)
    report = {
        "v3_pairs": sum(got.values()),
        "v2_pairs": sum(old.values()),
        "oracle_pairs": sum(want.values()),
        "v3_duplicate_pairs": sum(n - 1 for n in got.values() if n > 1),
        "v3_missing": sum((want - got).values()),
        "v3_extra": sum((got - want).values()),
        "v2_missing": sum((want - old).values()),
        "v2_extra": sum((old - want).values()),
        "v3_equal_v2": got == old,
        "v3_equal_oracle": got == want,
    }
    print(json.dumps(report, indent=2))
    if not (report["v3_equal_v2"] and report["v3_equal_oracle"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
