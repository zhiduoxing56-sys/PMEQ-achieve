"""Sequential bucket-width feasibility check and full-data candidate benchmark."""

import csv
import hashlib
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results/bucket-count-candidate-20260923"
GO = ROOT / "artifacts/n-domain-regression-pilot-runtime/go/bin/go"
MODCACHE = ROOT / "artifacts/n-domain-regression-pilot-runtime/modcache"
NATIVE = ROOT / "artifacts/n-domain-regression-pilot-runtime/native"
RAW = Path("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write(name, content):
    with (OUTPUT / name).open("x", encoding="utf-8") as f:
        f.write(content)


def write_csv(name, rows):
    with (OUTPUT / name).open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def read_csv(name):
    with (OUTPUT / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main():
    assert ROOT == Path("/home/tenggn/projects/clean_pmeq")
    assert not OUTPUT.exists(), f"Refusing to overwrite {OUTPUT}"
    assert subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip() == str(ROOT)
    assert GO.is_file() and MODCACHE.is_dir() and (NATIVE / "libphase6scmp.a").is_file()
    formal = json.loads((ROOT / "results/database-scalability-formal-20260920/environment.json").read_text())
    raw_hashes = {name: digest(RAW / name) for name in ("area", "area_alias")}
    assert raw_hashes == formal["raw_sha256"], "Full MusicBrainz input changed"
    capability = [
        dict(bucket_bits=14, bucket_count=2**14, status="unsupported", reason="Production TargetManifest.Validate requires TargetBucketBits=16; TargetPE.Load and TargetAggregation also bind 16. Full two-sided secure executor cannot consume a B=2^14 rebuilt target index."),
        dict(bucket_bits=15, bucket_count=2**15, status="unsupported", reason="Production TargetManifest.Validate requires TargetBucketBits=16; TargetPE.Load and TargetAggregation also bind 16. Full two-sided secure executor cannot consume a B=2^15 rebuilt target index."),
        dict(bucket_bits=16, bucket_count=2**16, status="pending", reason="Supported production bucket width; full-data index and all required auxiliary state will be rebuilt."),
        dict(bucket_bits=17, bucket_count=2**17, status="unsupported", reason="targetcrypto.MaxBucketBits=16 and bucket components, shares, and Anchor bucket IDs use uint16; B=2^17 is outside the implemented domain."),
    ]
    OUTPUT.mkdir(mode=0o700)
    write_csv("capability.csv", capability)
    sources = [
        "internal/discovery/bucket_count_experiment_native_test.go", "internal/discovery/database_regression_pilot_native_test.go",
        "internal/discovery/database_scalability_native_test.go", "internal/discovery/real_native_test.go",
        "internal/discovery/local.go", "internal/discovery/offline.go", "internal/indexbuild/builder.go",
        "internal/indexbuild/target_artifact.go", "internal/targetpe/index.go", "internal/targetaggregation/protocol.go",
        "internal/targetcrypto/bucket.go", "results/phase7b-workload.jsonl.gz", "results/phase10b-queries.json",
        "results/phase11-queries.json", "results/n-domain-regression-pilot-20260920/regression-100-queries.jsonl",
    ]
    source_hashes = {name: digest(ROOT / name) for name in sources}
    with tempfile.TemporaryDirectory(prefix="pmeq-bucket-count-20260923-") as temp:
        runtime = Path(temp)
        for name in ("cache", "gopath", "tmp"):
            (runtime / name).mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PMEQ_", "GO", "CGO"))}
        env.update(GOROOT=str(GO.parents[1]), GOMODCACHE=str(MODCACHE), GOPATH=str(runtime / "gopath"),
                   GOCACHE=str(runtime / "cache"), GOTMPDIR=str(runtime / "tmp"), TMPDIR=str(runtime / "tmp"),
                   GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off", GOFLAGS="",
                   GOMAXPROCS="32", GOGC="100", GOMEMLIMIT="off", GODEBUG="", CGO_ENABLED="1",
                   CGO_CFLAGS="", CGO_CPPFLAGS="", CGO_CXXFLAGS="",
                   CGO_LDFLAGS=f"-L{NATIVE} -lphase6scmp -lcrypto -pthread")
        binary = runtime / "bucket-count.test"
        build = [str(GO), "test", "-tags", "phase6native", "-c", "-o", str(binary), "./internal/discovery"]
        result = subprocess.run(build, cwd=ROOT, env=env, text=True, capture_output=True)
        write("build.log", result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("Experiment build failed; see build.log")
        env["PMEQ_BUCKET_COUNT_OUTPUT"] = str(OUTPUT)
        command = [str(binary), "-test.run=^TestBucketCountCandidateExperiment$", "-test.count=1", "-test.v", "-test.timeout=180m"]
        write("run-command.txt", "Entry point (exclusive new output): python3 tools/run_bucket_count_candidate_experiment_20260923.py\n"
              + "Build: " + shlex.join(build) + "\nRun B=2^16: " + shlex.join(command) + "\n"
              + "Unsupported widths are recorded in capability.csv and were not submitted to the complete secure executor.\n"
              + "Environment: GOMAXPROCS=32 GOGC=100 GOMEMLIMIT=off CGO_ENABLED=1 GOPROXY=off"
              + f" PMEQ_BUCKET_COUNT_OUTPUT={OUTPUT}\n")
        with (OUTPUT / "run.log").open("x") as log:
            result = subprocess.run(command, cwd=ROOT / "internal/discovery", env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"B=2^16 experiment failed; see {OUTPUT / 'run.log'}")
        binary_hash = digest(binary)
    rows = read_csv("candidate-raw.csv")
    assert len(rows) == 854*3
    by_query = {}
    ids = set()
    for row in rows:
        q = int(row["query_id"])
        assert row["bucket_bits"] == "16" and row["bucket_count"] == "65536"
        assert 0 <= q < 1003 and int(row["local_e2e_ns"]) > 0
        assert sum(int(row[x]) for x in ("user_to_cloud_bytes", "cs_to_cs_bytes", "cloud_to_user_bytes")) == int(row["total_online_bytes"])
        assert all(int(row[x]) == 0 for x in ("FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id"))
        assert row["matches_default_bucket_result"] == "true"
        assert row["packet_id_sha256"] not in ids
        ids.add(row["packet_id_sha256"])
        by_query.setdefault(q, []).append(row)
    assert len(by_query) == 854 and len(ids) == 854*3
    medians = []
    for q, group in sorted(by_query.items()):
        assert sorted(int(r["trial"]) for r in group) == [1, 2, 3]
        assert len({(r["tau_anchor"], r["tau_target"], r["K"], r["routes"], r["groups"], r["target_slots"], r["final_pairs"], r["total_online_bytes"], r["pair_sha256"]) for r in group}) == 1
        medians.append(dict(query_id=q, e2e_median_ms=statistics.median(int(r["local_e2e_ns"]) for r in group)/1e6,
                            online_bytes_median=statistics.median(int(r["total_online_bytes"]) for r in group),
                            target_slots_median=statistics.median(int(r["target_slots"]) for r in group)))
    write_csv("query-medians.csv", medians)
    built = json.loads((OUTPUT / "build-and-storage.json").read_text())
    static = built["Static"]
    mapping = {
        "Anchor alignment full-domain factors": "Anchor alignment full-domain factors",
        "Anchor incidence full-domain fields": "Anchor incidence full-domain fields",
        "BSMJ semantic fields": "BSMJ semantic fields",
        "Global sealed payload files": "Global payload sealed bytes",
        "PSMJ sealed files": "PSMJ sealed bytes",
        "Target aggregation sealed files": "Target aggregation sealed bytes",
    }
    canonical = {key: static[value] for key, value in mapping.items()}
    assert canonical == json.loads((ROOT / "results/phase11-static.json").read_text()), "Static accounting mismatch with formal default"
    static_bytes = sum(sum(v) for v in canonical.values())
    summary = [dict(bucket_bits=16, bucket_count=65536, query_count=854, trials_per_query=3,
                    mean_candidate_discovery_ms=statistics.mean(x["e2e_median_ms"] for x in medians),
                    mean_online_bytes=statistics.mean(x["online_bytes_median"] for x in medians),
                    mean_online_mib=statistics.mean(x["online_bytes_median"] for x in medians)/(2**20),
                    cs0_static_bytes=sum(v[0] for v in canonical.values()),
                    cs1_static_bytes=sum(v[1] for v in canonical.values()),
                    total_static_bytes=static_bytes, total_static_gib=static_bytes/(2**30),
                    mean_target_slots=statistics.mean(x["target_slots_median"] for x in medians))]
    write_csv("summary.csv", summary)
    capability[2]["status"] = "completed"
    capability[2]["reason"] = "Full-data BSMJ, PSMJ, payload and aggregation sidecar rebuilt; 854 legal queries each measured three times and checked against plaintext and saved B=2^16 candidate pairs."
    # Preserve the initial preflight; the final status is an additional file.
    write_csv("capability-final.csv", capability)
    write("notes.md", "# 桶数实验结果\n\n"
          "测试范围 B=2^14、2^15、2^16、2^17。完整安全执行链仅支持 B=2^16；其余档位的具体限制见 capability-final.csv，因此没有合法的四点性能曲线。\n\n"
          "B=2^16 使用完整数据 Anchor=120071、Target=67896，原 854 条合法查询，q=4；每条查询三次。重建 BSMJ、PSMJ、payload、聚合 sidecar，并为每条查询准备所需 Anchor incidence/alignment 静态状态；索引构造、状态准备、离线 Provision 和明文核对在计时外。一次性材料每轮更新。\n\n"
          "候选发现时间使用 RunLocal 的 LocalE2E（令牌生成至用户恢复候选对）；通信为 User→Cloud、CS↔CS、Cloud→User 之和；不含最终精确编辑距离验证。每条查询三轮取中位数，然后对 854 条查询求平均。所有候选对逐条与明文及已保存默认 B=2^16 候选结果一致。\n\n"
          "静态存储沿用 phase11-static.json 的六项完整双云静态状态容量核算，单位 GiB=bytes/2^30；这不是进程实际常驻内存。\n\n"
          f"B=2^16：候选发现 {summary[0]['mean_candidate_discovery_ms']:.6f} ms，在线通信 {summary[0]['mean_online_mib']:.6f} MiB，双云静态容量 {summary[0]['total_static_gib']:.6f} GiB，平均目标槽 {summary[0]['mean_target_slots']:.3f}。\n\n"
          "默认桶数在当前已可完整测试范围内是唯一性能点，无法根据本次数据比较不同桶数，更不能判断全局最优。\n")
    provenance = dict(status="completed_with_unsupported_widths", raw_database_sha256=raw_hashes,
                      source_sha256=source_hashes, binary_sha256=binary_hash,
                      default_candidate_reference_sha256=source_hashes["results/n-domain-regression-pilot-20260920/regression-100-queries.jsonl"],
                      candidate_raw_sha256=digest(OUTPUT / "candidate-raw.csv"),
                      build_storage_sha256=digest(OUTPUT / "build-and-storage.json"),
                      legal_queries=854, trials=2562,
                      runtime_env={k: env[k] for k in ("GOMAXPROCS", "GOGC", "GOMEMLIMIT", "CGO_ENABLED", "GOPROXY")})
    write("provenance.json", json.dumps(provenance, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(summary[0], ensure_ascii=False))


if __name__ == "__main__":
    main()
