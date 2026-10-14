"""Run the two-sided threshold sensitivity experiment on original legal queries."""

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
OUTPUT = ROOT / "results/query-threshold-candidate-20260923"
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


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main():
    assert ROOT == Path("/home/tenggn/projects/clean_pmeq")
    assert not OUTPUT.exists(), f"Refusing to overwrite {OUTPUT}"
    assert subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip() == str(ROOT)
    formal = json.loads((ROOT / "results/database-scalability-formal-20260920/environment.json").read_text())
    raw_hashes = {name: digest(RAW / name) for name in ("area", "area_alias")}
    assert raw_hashes == formal["raw_sha256"], "Full MusicBrainz input changed"
    assert GO.is_file() and MODCACHE.is_dir() and (NATIVE / "libphase6scmp.a").is_file()
    source_names = [
        "internal/discovery/threshold_candidate_experiment_native_test.go",
        "internal/discovery/signature_candidate_experiment_native_test.go",
        "internal/discovery/real_native_test.go",
        "internal/discovery/database_regression_pilot_native_test.go",
        "internal/discovery/database_scalability_native_test.go",
        "internal/discovery/local.go",
        "internal/discovery/token.go",
        "internal/discovery/offline.go",
        "internal/anchorfilter/filter.go",
        "artifacts/phase7b/manifest.json",
        "artifacts/phase7b/payload-manifest.json",
        "artifacts/phase10b/manifest.json",
        "results/phase7b-workload.jsonl.gz",
        "results/phase10b-queries.json",
    ]
    sources = {name: digest(ROOT / name) for name in source_names}
    with tempfile.TemporaryDirectory(prefix="pmeq-threshold-candidate-20260923-") as temp:
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
        binary = runtime / "threshold-candidate.test"
        build = [str(GO), "test", "-tags", "phase6native", "-c", "-o", str(binary), "./internal/discovery"]
        result = subprocess.run(build, cwd=ROOT, env=env, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(f"Build failed:\n{result.stdout}\n{result.stderr}")
        OUTPUT.mkdir(mode=0o700)
        write("build.log", result.stdout + result.stderr)
        env["PMEQ_THRESHOLD_OUTPUT"] = str(OUTPUT)
        command = [str(binary), "-test.run=^TestThresholdCandidateDiscoveryExperiment$", "-test.count=1", "-test.v", "-test.timeout=120m"]
        write("run-command.txt", "Entry point (exclusive new output): python3 tools/run_threshold_candidate_experiment_20260923.py\n"
              + "Build: " + shlex.join(build) + "\nRun: " + shlex.join(command) + "\n"
              + "Environment: GOMAXPROCS=32 GOGC=100 GOMEMLIMIT=off CGO_ENABLED=1 GOPROXY=off"
              + f" PMEQ_THRESHOLD_OUTPUT={OUTPUT}\n")
        with (OUTPUT / "run.log").open("x") as log:
            result = subprocess.run(command, cwd=ROOT / "internal/discovery", env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"Experiment failed; see {OUTPUT / 'run.log'}")
        subset = json.loads((OUTPUT / "fixed-query-subset.json").read_text())
        raw = read_csv(OUTPUT / "candidate-raw.csv")
        checks = read_csv(OUTPUT / "correctness.csv")
        n = subset["selected_queries"]
        assert subset["original_legal_queries"] == 854 and 0 < n == min(50, subset["eligible_queries"])
        assert len(subset["queries"]) == n and len(raw) == 24*n and len(checks) == 8*n
        assert subset["seed"] == 20260923 and subset["q"] == 4 and subset["bucket_bits"] == 16
        by_case = {}
        packet_ids = set()
        for row in raw:
            case_id = int(row["case_id"])
            assert 0 <= case_id < 8*n
            q = subset["queries"][case_id//8]
            side = "anchor" if case_id%8 < 4 else "target"
            tau = case_id%4
            assert int(row["query_id"]) == q["query_id"] and row["variable_side"] == side
            assert int(row["tau_anchor"]) == (tau if side == "anchor" else 1)
            assert int(row["tau_target"]) == (tau if side == "target" else 1)
            assert int(row["anchor_signatures"]) == q["anchor_signatures"] and int(row["target_signatures"]) == q["target_signatures"]
            assert sum(int(row[k]) for k in ("user_to_cloud_bytes", "cs_to_cs_bytes", "cloud_to_user_bytes")) == int(row["total_online_bytes"])
            assert int(row["local_e2e_ns"]) > 0 and int(row["final_pairs"]) == int(row["oracle_pairs"])
            assert all(int(row[k]) == 0 for k in ("FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id"))
            assert row["packet_id_sha256"] not in packet_ids
            packet_ids.add(row["packet_id_sha256"])
            by_case.setdefault(case_id, []).append(row)
        medians = []
        for case_id in range(8*n):
            rows = by_case[case_id]
            assert sorted(int(x["trial"]) for x in rows) == [1,2,3]
            assert len({x["pair_sha256"] for x in rows}) == 1
            assert len({(x["K"], x["routes"], x["groups"], x["target_slots"], x["total_online_bytes"]) for x in rows}) == 1
            q = subset["queries"][case_id//8]
            side = "anchor" if case_id%8<4 else "target"
            tau = case_id%4
            medians.append(dict(case_id=case_id, query_id=q["query_id"], variable_side=side,
                                tau_anchor=tau if side=="anchor" else 1, tau_target=tau if side=="target" else 1,
                                anchor_signatures=q["anchor_signatures"], target_signatures=q["target_signatures"],
                                e2e_median_ms=statistics.median(int(x["local_e2e_ns"]) for x in rows)/1e6,
                                online_bytes_median=statistics.median(int(x["total_online_bytes"]) for x in rows),
                                K_median=statistics.median(int(x["K"]) for x in rows),
                                routes_median=statistics.median(int(x["routes"]) for x in rows),
                                groups_median=statistics.median(int(x["groups"]) for x in rows),
                                target_slots_median=statistics.median(int(x["target_slots"]) for x in rows),
                                final_pairs=statistics.median(int(x["final_pairs"]) for x in rows)))
        assert all(x["all_three_equal_oracle"] == "true" and all(int(x[k])==0 for k in ("FP","FN","duplicates","wrong_anchor_id","wrong_target_id")) for x in checks)
        write_csv("case-medians.csv", medians)
        summary=[]
        for side in ("anchor","target"):
            for tau in (0,1,2,3):
                vals=[v for v in medians if v["variable_side"]==side and (v["tau_anchor"] if side=="anchor" else v["tau_target"])==tau]
                assert len(vals)==n
                summary.append(dict(variable_side=side,tau_anchor=tau if side=="anchor" else 1,
                                    tau_target=tau if side=="target" else 1,query_count=n,
                                    mean_candidate_discovery_ms=statistics.mean(v["e2e_median_ms"] for v in vals),
                                    mean_online_bytes=statistics.mean(v["online_bytes_median"] for v in vals),
                                    mean_online_mib=statistics.mean(v["online_bytes_median"] for v in vals)/(2**20),
                                    mean_K=statistics.mean(v["K_median"] for v in vals),
                                    mean_routes=statistics.mean(v["routes_median"] for v in vals),
                                    mean_target_slots=statistics.mean(v["target_slots_median"] for v in vals),
                                    mean_groups=statistics.mean(v["groups_median"] for v in vals),
                                    mean_final_pairs=statistics.mean(v["final_pairs"] for v in vals)))
        write_csv("summary.csv",summary)
        zero=sum(int(x["K_median"])==0 for x in medians)
        report=["# 两侧编辑距离阈值对候选发现开销的影响\n",
                f"原 854 条合法查询中，签名数和全部配置合法性检查后有 {subset['eligible_queries']} 条；依规则选用 {n} 条，随机种子 20260923。固定查询子集见 fixed-query-subset.json，查询字符串及签名序列在全部配置中不变。",
                "两组各改变一侧阈值0/1/2/3，另一侧固定1。完整数据库 Anchor=120071、Target=67896；q=4，两侧B=2^16。",
                "每个配置三轮；每轮重新调用原 Provision 和 RunLocal，使用新的一次性材料。静态准备及离线Provision在计时外；LocalE2E从令牌生成前到用户候选记录对恢复后，未做最终精确编辑距离验证。",
                "在线通信为两份令牌、双云实际发送量和两份输出之和；MiB=bytes/2^20。每轮结果在计时外与同阈值配置的明文候选发现逐对核对。",
                "时间、通信、K、路由数和目标槽数先对每条查询取三轮中位数，再对档位取均值；合法零候选样本照常计入。",
                f"本批 8×{n} 个查询配置中，零候选配置 {zero} 个。",
                "\n| 变化侧 | Anchor tau | Target tau | n | 时间 ms | 在线 MiB | K | routes | Target slots |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for x in summary:
            report.append(f"| {x['variable_side']} | {x['tau_anchor']} | {x['tau_target']} | {x['query_count']} | {x['mean_candidate_discovery_ms']:.6f} | {x['mean_online_mib']:.6f} | {x['mean_K']:.3f} | {x['mean_routes']:.3f} | {x['mean_target_slots']:.3f} |")
        for j,side in ((0,"锚点"),(4,"目标")):
            rows=summary[j:j+4]
            report.append(f"\n{side}侧阈值 0/1/2/3 的实测平均候选发现时间依次为 "+"/".join(f"{x['mean_candidate_discovery_ms']:.3f}" for x in rows)+" ms；平均通信依次为 "+"/".join(f"{x['mean_online_mib']:.3f}" for x in rows)+" MiB。对应 K、路由和目标槽均值见上表；这里只陈述实测变化，不做拟合或因果推断。")
        write("notes.md","\n".join(report)+"\n")
        provenance=dict(status="passed",source_sha256=sources,raw_database_sha256=raw_hashes,
                        binary_sha256=digest(binary),query_subset_sha256=digest(OUTPUT/"fixed-query-subset.json"),
                        raw_result_sha256=digest(OUTPUT/"candidate-raw.csv"),correctness_sha256=digest(OUTPUT/"correctness.csv"),
                        legal_queries=854,eligible_queries=subset["eligible_queries"],selected_queries=n,cases=8*n,trials=24*n,
                        runtime_env={k:env[k] for k in ("GOMAXPROCS","GOGC","GOMEMLIMIT","CGO_ENABLED","GOPROXY")})
        write("provenance.json",json.dumps(provenance,indent=2,ensure_ascii=False)+"\n")
        print(f"Completed: eligible={subset['eligible_queries']} selected={n} cases={8*n} trials={24*n} output={OUTPUT}")
        for row in summary:print(row)


if __name__=="__main__":
    main()
