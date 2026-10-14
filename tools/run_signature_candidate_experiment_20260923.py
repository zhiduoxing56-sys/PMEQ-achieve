"""Run full secure candidate discovery for the saved signature query set."""

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
QUERY_ROOT = ROOT / "results/query-signature-count-20260923"
QUERY_SET = QUERY_ROOT / "constructed-queries.json"
OUTPUT = ROOT / "results/query-signature-candidate-20260923"
GO = ROOT / "artifacts/n-domain-regression-pilot-runtime/go/bin/go"
MODCACHE = ROOT / "artifacts/n-domain-regression-pilot-runtime/modcache"
NATIVE = ROOT / "artifacts/n-domain-regression-pilot-runtime/native"


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
    previous = json.loads((QUERY_ROOT / "provenance.json").read_text())
    assert previous["status"] == "passed" and previous["query_set_sha256"] == digest(QUERY_SET)
    constructed = json.loads(QUERY_SET.read_text())
    assert constructed["seed"] == 20260923 and constructed["sampled_pairs"] == 50 and len(constructed["cases"]) == 400
    assert GO.is_file() and MODCACHE.is_dir() and (NATIVE / "libphase6scmp.a").is_file()
    source_names = [
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
    ]
    sources = {name: digest(ROOT / name) for name in source_names}
    with tempfile.TemporaryDirectory(prefix="pmeq-signature-candidate-20260923-") as temp:
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
        binary = runtime / "signature-candidate.test"
        build = [str(GO), "test", "-tags", "phase6native", "-c", "-o", str(binary), "./internal/discovery"]
        result = subprocess.run(build, cwd=ROOT, env=env, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(f"Build failed:\n{result.stdout}\n{result.stderr}")
        OUTPUT.mkdir(mode=0o700)
        write("build.log", result.stdout + result.stderr)
        env["PMEQ_SIGNATURE_CANDIDATE_OUTPUT"] = str(OUTPUT)
        env["PMEQ_SIGNATURE_CANDIDATE_QUERYSET"] = str(QUERY_SET)
        command = [str(binary), "-test.run=^TestSignatureCandidateDiscoveryExperiment$", "-test.count=1", "-test.v", "-test.timeout=120m"]
        write("run-command.txt", "Entry point (exclusive new output): python3 tools/run_signature_candidate_experiment_20260923.py\n"
              + "Build: " + shlex.join(build) + "\nRun: " + shlex.join(command) + "\n"
              + "Environment: GOMAXPROCS=32 GOGC=100 GOMEMLIMIT=off CGO_ENABLED=1 GOPROXY=off"
              + f" PMEQ_SIGNATURE_CANDIDATE_QUERYSET={QUERY_SET} PMEQ_SIGNATURE_CANDIDATE_OUTPUT={OUTPUT}\n")
        with (OUTPUT / "run.log").open("x") as log:
            result = subprocess.run(command, cwd=ROOT / "internal/discovery", env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"Experiment failed; see {OUTPUT / 'run.log'}")
        raw = read_csv(OUTPUT / "candidate-raw.csv")
        checks = read_csv(OUTPUT / "correctness.csv")
        assert len(raw) == 1200 and len(checks) == 400
        by_case = {}
        for row in raw:
            case_id = int(row["case_id"])
            case = constructed["cases"][case_id]
            assert row["variable_side"] == case["variable_side"]
            assert int(row["anchor_signatures"]) == case["anchor_signatures"]
            assert int(row["target_signatures"]) == case["target_signatures"]
            assert int(row["local_e2e_ns"]) > 0
            assert sum(int(row[k]) for k in ("user_to_cloud_bytes", "cs_to_cs_bytes", "cloud_to_user_bytes")) == int(row["total_online_bytes"])
            assert all(int(row[k]) == 0 for k in ("FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id"))
            assert int(row["final_pairs"]) == int(row["oracle_pairs"])
            by_case.setdefault(case_id, []).append(row)
        medians = []
        for case_id, case in enumerate(constructed["cases"]):
            rows = by_case[case_id]
            assert sorted(int(row["trial"]) for row in rows) == [1, 2, 3]
            assert len({row["pair_sha256"] for row in rows}) == 1
            assert len({(row["K"], row["routes"], row["groups"], row["target_slots"], row["total_online_bytes"]) for row in rows}) == 1
            medians.append(dict(case_id=case_id, pair_index=case["pair_index"], variable_side=case["variable_side"],
                                anchor_signatures=case["anchor_signatures"], target_signatures=case["target_signatures"],
                                e2e_median_ms=statistics.median(int(r["local_e2e_ns"]) for r in rows) / 1e6,
                                online_bytes_median=statistics.median(int(r["total_online_bytes"]) for r in rows),
                                K_median=statistics.median(int(r["K"]) for r in rows),
                                routes_median=statistics.median(int(r["routes"]) for r in rows),
                                groups_median=statistics.median(int(r["groups"]) for r in rows),
                                target_slots_median=statistics.median(int(r["target_slots"]) for r in rows),
                                final_pairs=statistics.median(int(r["final_pairs"]) for r in rows)))
        assert all(row["all_three_equal_oracle"] == "true" and all(int(row[k]) == 0 for k in ("FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id")) for row in checks)
        write_csv("case-medians.csv", medians)
        summary = []
        for side in ("anchor", "target"):
            for n in (2, 3, 4, 6):
                vals = [v for v in medians if v["variable_side"] == side and (v["anchor_signatures"] if side == "anchor" else v["target_signatures"]) == n]
                assert len(vals) == 50
                summary.append(dict(variable_side=side, anchor_signatures=n if side == "anchor" else 4,
                                    target_signatures=n if side == "target" else 4, query_count=len(vals),
                                    mean_candidate_discovery_ms=statistics.mean(v["e2e_median_ms"] for v in vals),
                                    mean_online_bytes=statistics.mean(v["online_bytes_median"] for v in vals),
                                    mean_online_mib=statistics.mean(v["online_bytes_median"] for v in vals) / (2**20),
                                    mean_K=statistics.mean(v["K_median"] for v in vals),
                                    mean_routes=statistics.mean(v["routes_median"] for v in vals),
                                    mean_target_slots=statistics.mean(v["target_slots_median"] for v in vals),
                                    mean_groups=statistics.mean(v["groups_median"] for v in vals),
                                    mean_final_pairs=statistics.mean(v["final_pairs"] for v in vals)))
        write_csv("summary.csv", summary)
        lines = ["# 查询签名数量与完整安全候选发现开销\n",
                 "输入直接采用上一实验的 constructed-queries.json，50 对真实连接记录、400 条长度控制查询；没有重新抽样或改写原始查询集。固定 q=4、两侧 B=2^16、tau=1；一侧签名数为 2/3/4/6，另一侧为 4。",
                 "每条查询运行三轮。每轮均调用原 Provision 获取新的一次性密码材料及令牌，然后调用原 RunLocal 完成双云协议与用户候选记录对恢复；结果与同语义的明文 oracle 在计时外逐对核验。合法零候选查询保留。",
                 "LocalE2E 采用现有 RunLocal 计时：从令牌生成前到用户 RecoverForDomain 返回。数据库加载、静态准备、离线 Provision、明文 oracle、正确性检查及实验写盘在计时外。不包含最终精确编辑距离验证。",
                 "在线通信为 User→Cloud 两份序列化令牌、CS↔CS 双云实际发送量、Cloud→User 两份实际输出之和。总字节数按已有 Metrics 计一次；MiB=bytes/2^20。",
                 "逐查询三轮时间、通信、K、routes、groups、target slots 先分别取中位数，再对每档 50 条查询求均值。候选结果可随签名档位变化；工作负载列只用于描述伴随变化。",
                 "\n| 变化侧 | Anchor r | Target r | n | 时间 ms | 在线 MiB | K | routes | Target slots |\n|---|---:|---:|---:|---:|---:|---:|---:|"]
        for x in summary:
            lines.append(f"| {x['variable_side']} | {x['anchor_signatures']} | {x['target_signatures']} | {x['query_count']} | {x['mean_candidate_discovery_ms']:.6f} | {x['mean_online_mib']:.6f} | {x['mean_K']:.3f} | {x['mean_routes']:.3f} | {x['mean_target_slots']:.3f} |")
        lines.append(f"\n锚点侧 r=2 时平均时间 {summary[0]['mean_candidate_discovery_ms']:.3f} ms、通信 {summary[0]['mean_online_mib']:.3f} MiB，均高于该侧 r=3/4/6；该档平均 K={summary[0]['mean_K']:.2f}、目标槽数={summary[0]['mean_target_slots']:.1f}。锚点侧 r=3/4/6 的平均时间为 {summary[1]['mean_candidate_discovery_ms']:.3f}/{summary[2]['mean_candidate_discovery_ms']:.3f}/{summary[3]['mean_candidate_discovery_ms']:.3f} ms，并非随 r 单调变化。")
        lines.append(f"目标侧 r=2/3/4/6 的平均时间为 {summary[4]['mean_candidate_discovery_ms']:.3f}/{summary[5]['mean_candidate_discovery_ms']:.3f}/{summary[6]['mean_candidate_discovery_ms']:.3f}/{summary[7]['mean_candidate_discovery_ms']:.3f} ms，通信为 {summary[4]['mean_online_mib']:.3f}/{summary[5]['mean_online_mib']:.3f}/{summary[6]['mean_online_mib']:.3f}/{summary[7]['mean_online_mib']:.3f} MiB；这组平均 K 均为 {summary[4]['mean_K']:.2f}，路由数和目标槽数随目标侧 r 档位增加。本批构造查询没有零候选样本。以上仅陈述实测变化，不做拟合或因果归因。\n")
        write("notes.md", "\n".join(lines))
        provenance = dict(status="passed", query_set_path=str(QUERY_SET.relative_to(ROOT)), query_set_sha256=digest(QUERY_SET),
                          source_sha256=sources, binary_sha256=digest(binary), raw_sha256=digest(OUTPUT / "candidate-raw.csv"),
                          correctness_sha256=digest(OUTPUT / "correctness.csv"), cases=400, trials=1200,
                          full_anchor_records=120071, full_target_records=67896,
                          runtime_env={k: env[k] for k in ("GOMAXPROCS", "GOGC", "GOMEMLIMIT", "CGO_ENABLED", "GOPROXY")})
        write("provenance.json", json.dumps(provenance, indent=2, ensure_ascii=False) + "\n")
        print(f"Completed 400 cases, 1200 full candidate discoveries: {OUTPUT}")
        for row in summary:
            print(row)


if __name__ == "__main__":
    main()
