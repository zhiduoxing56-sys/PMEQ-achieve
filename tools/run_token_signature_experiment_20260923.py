"""Run the length-controlled token generation experiment; refuse existing outputs."""

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
OUTPUT = ROOT / "results/query-signature-count-20260923"
RAW = Path("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump")
GO = ROOT / "artifacts/n-domain-regression-pilot-runtime/go/bin/go"
MODCACHE = ROOT / "artifacts/n-domain-regression-pilot-runtime/modcache"
NATIVE = ROOT / "artifacts/n-domain-regression-pilot-runtime/native"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write(path, data):
    with path.open("x", encoding="utf-8") as f:
        f.write(data)


def table(path, rows):
    with path.open("x", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    assert ROOT == Path("/home/tenggn/projects/clean_pmeq")
    assert not OUTPUT.exists(), f"Refusing to overwrite {OUTPUT}"
    assert subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip() == str(ROOT)
    formal = json.loads((ROOT / "results/database-scalability-formal-20260920/environment.json").read_text())
    raw_hashes = {name: digest(RAW / name) for name in ("area", "area_alias")}
    assert raw_hashes == formal["raw_sha256"], "Full MusicBrainz input differs from formal experiment"
    assert GO.is_file() and (NATIVE / "libphase6scmp.a").is_file() and MODCACHE.is_dir()
    source_paths = [ROOT / name for name in (
        "internal/discovery/token.go",
        "internal/discovery/local.go",
        "internal/discovery/types.go",
        "internal/discovery/token_signature_experiment_test.go",
        "internal/anchorfilter/filter.go",
        "internal/indexbuild/parser.go",
        "internal/targetquery/query.go",
        "artifacts/phase7b/manifest.json",
        "artifacts/phase7b/payload-manifest.json",
    )]
    source_hashes = {str(p.relative_to(ROOT)): digest(p) for p in source_paths}
    with tempfile.TemporaryDirectory(prefix="pmeq-signature-20260923-") as temp:
        runtime = Path(temp)
        for name in ("cache", "gopath", "tmp"):
            (runtime / name).mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PMEQ_", "GO", "CGO"))}
        env.update(
            GOROOT=str(GO.parents[1]), GOMODCACHE=str(MODCACHE), GOPATH=str(runtime / "gopath"),
            GOCACHE=str(runtime / "cache"), GOTMPDIR=str(runtime / "tmp"), TMPDIR=str(runtime / "tmp"),
            GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off", GOFLAGS="",
            GOMAXPROCS="32", GOGC="100", GOMEMLIMIT="off", GODEBUG="", CGO_ENABLED="1",
            CGO_CFLAGS="", CGO_CPPFLAGS="", CGO_CXXFLAGS="",
            CGO_LDFLAGS=f"-L{NATIVE} -lphase6scmp -lcrypto -pthread",
        )
        binary = runtime / "token-signature.test"
        build = [str(GO), "test", "-tags", "phase6native", "-c", "-o", str(binary), "./internal/discovery"]
        build_result = subprocess.run(build, cwd=ROOT, env=env, text=True, capture_output=True)
        if build_result.returncode:
            raise RuntimeError(f"Build failed:\n{build_result.stdout}\n{build_result.stderr}")
        OUTPUT.mkdir(mode=0o700)
        write(OUTPUT / "build.log", build_result.stdout + build_result.stderr)
        env["PMEQ_SIGNATURE_OUTPUT"] = str(OUTPUT)
        env["PMEQ_SIGNATURE_RAW"] = str(RAW)
        command = [str(binary), "-test.run=^TestTokenSignatureCountExperiment$", "-test.count=1", "-test.v", "-test.timeout=20m"]
        write(OUTPUT / "run-command.txt", "Build: " + shlex.join(build) + "\nRun: " + shlex.join(command)
              + "\nEnvironment: GOMAXPROCS=32 GOGC=100 GOMEMLIMIT=off CGO_ENABLED=1 GOPROXY=off"
              + f" PMEQ_SIGNATURE_RAW={RAW} PMEQ_SIGNATURE_OUTPUT={OUTPUT}\n")
        with (OUTPUT / "run.log").open("x") as log:
            result = subprocess.run(command, cwd=ROOT / "internal/discovery", env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"Experiment failed; see {OUTPUT / 'run.log'}")
        with (OUTPUT / "constructed-queries.json").open() as f:
            constructed = json.load(f)
        with (OUTPUT / "token-raw.csv").open(newline="") as f:
            raw_rows = list(csv.DictReader(f))
        count = constructed["sampled_pairs"]
        assert count == min(50, constructed["eligible_pairs"])
        assert constructed["seed"] == 20260923 and constructed["q"] == 4 and constructed["bucket_bits"] == 16
        assert len(constructed["cases"]) == 8 * count and len(raw_rows) == 24 * count
        grouped = {}
        for row in raw_rows:
            case_id = int(row["case_id"])
            assert 0 <= case_id < len(constructed["cases"])
            case = constructed["cases"][case_id]
            assert row["variable_side"] == case["variable_side"]
            assert int(row["anchor_signatures"]) == case["anchor_signatures"]
            assert int(row["target_signatures"]) == case["target_signatures"]
            assert int(row["pair_index"]) == case["pair_index"]
            assert int(row["cs0_token_bytes"]) + int(row["cs1_token_bytes"]) == int(row["total_token_bytes"])
            assert int(row["generation_ns"]) > 0
            grouped.setdefault(case_id, []).append(row)
        medians = []
        for case_id, case in enumerate(constructed["cases"]):
            rows = grouped[case_id]
            assert sorted(int(r["trial"]) for r in rows) == [1, 2, 3]
            sizes = [int(r["total_token_bytes"]) for r in rows]
            assert len(set(sizes)) == 1
            medians.append(dict(case_id=case_id, pair_index=case["pair_index"], variable_side=case["variable_side"],
                                anchor_signatures=case["anchor_signatures"], target_signatures=case["target_signatures"],
                                generation_median_ms=statistics.median(int(r["generation_ns"]) for r in rows) / 1e6,
                                token_median_bytes=statistics.median(sizes)))
        table(OUTPUT / "query-medians.csv", medians)
        summary = []
        for side in ("anchor", "target"):
            for r in (2, 3, 4, 6):
                cases = [v for v in medians if v["variable_side"] == side and (v["anchor_signatures"] if side == "anchor" else v["target_signatures"]) == r]
                assert len(cases) == count
                summary.append(dict(variable_side=side, anchor_signatures=r if side == "anchor" else 4,
                                    target_signatures=r if side == "target" else 4, query_count=count,
                                    mean_generation_time_ms=statistics.mean(v["generation_median_ms"] for v in cases),
                                    mean_token_bytes=statistics.mean(v["token_median_bytes"] for v in cases)))
        table(OUTPUT / "summary.csv", summary)
        report = [
            "# 查询签名数量与令牌开销\n",
            f"当前完整 MusicBrainz 数据：Anchor {constructed['full_anchor_records']} 条，Target {constructed['full_target_records']} 条。",
            f"两侧名称均不少于24个Unicode码点的真实连接记录共 {constructed['eligible_pairs']} 对；种子 20260923 抽取 {count} 对。",
            "constructed-queries.json 是长度控制的构造查询集，供后续第二项实验直接复用；原854条正式查询未改动。",
            "原始名称按现有COPY解析器读取，不做额外Unicode正规化或大小写变换；截取每侧原名的8/12/16/24码点前缀，原QueryChunks重新抽取并校验签名数。",
            "固定 q=4、Anchor/Target B=2^16、两侧 tau=1；一侧 r=2/3/4/6，另一侧 r=4。",
            "每个构造查询独立生成3次。每次在计时外调用现有Preprocess入口生成新PID、随机掩码与单次材料；离线公开容量取K=S=G=0，仅测令牌生成，不执行云端查询。",
            "计时从调用原generate之前开始，到它返回两份已编码令牌后结束，与RunLocal的Token字段边界一致；包括实际DPF生成、目标词秘密分享、位置/阈值掩码与两云token编码。",
            "大小为len(CS0编码令牌)+len(CS1编码令牌)，一次用户向两云发送的总字节数；不计离线材料、网络帧或进程内存。",
            "统计先取每条构造查询3次的时间和字节数中位数，再按档位对所有查询取算术平均；采样随机种子只用于可复现地选记录，不用于密码随机材料。",
            "\n| 变化侧 | Anchor签名 | Target签名 | 查询数 | 平均令牌生成ms | 平均两云令牌bytes |\n|---|---:|---:|---:|---:|---:|",
        ]
        for row in summary:
            report.append(f"| {row['variable_side']} | {row['anchor_signatures']} | {row['target_signatures']} | {row['query_count']} | {row['mean_generation_time_ms']:.6f} | {row['mean_token_bytes']:.3f} |")
        report.append("\n每档使用同一批抽样连接对；两组r=4的字符串相同，令牌仍各自用新随机材料独立生成。\n")
        write(OUTPUT / "notes.md", "\n".join(report))
        provenance = dict(status="passed", raw_sha256=raw_hashes, source_sha256=source_hashes,
                          binary_sha256=digest(binary), query_set_sha256=digest(OUTPUT / "constructed-queries.json"),
                          raw_result_sha256=digest(OUTPUT / "token-raw.csv"), full_database=True,
                          cases=len(constructed["cases"]), trials=len(raw_rows), random_sampling_seed=20260923,
                          crypto_randomness="crypto/rand in existing preprocessing and token generation",
                          runtime_env={k: env[k] for k in ("GOMAXPROCS", "GOGC", "GOMEMLIMIT", "CGO_ENABLED", "GOPROXY")})
        write(OUTPUT / "provenance.json", json.dumps(provenance, indent=2, ensure_ascii=False) + "\n")
        print(f"Completed: {count} pairs, {len(summary)} settings, {len(raw_rows)} fresh token generations, {OUTPUT}")
        for row in summary:
            print(row)


if __name__ == "__main__":
    main()
