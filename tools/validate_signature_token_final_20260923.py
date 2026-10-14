"""Validate saved token measurements against the full-query token wire path."""

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
OUT = ROOT / "results/query-signature-count-20260923"
FULL = ROOT / "results/query-signature-candidate-20260923"
GO = ROOT / "artifacts/n-domain-regression-pilot-runtime/go/bin/go"
NATIVE = ROOT / "artifacts/n-domain-regression-pilot-runtime/native"
MODCACHE = ROOT / "artifacts/n-domain-regression-pilot-runtime/modcache"


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(4*1024*1024), b""):
            h.update(block)
    return h.hexdigest()


def rows(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write(name, text):
    with (OUT / name).open("x", encoding="utf-8") as f:
        f.write(text)


def main():
    assert ROOT == Path("/home/tenggn/projects/clean_pmeq")
    assert OUT.is_dir() and FULL.is_dir()
    for name in ("token-field-validation.csv", "final-paper-table.csv", "final-validation.md", "final-validation-run-command.txt", "final-validation-run.log"):
        assert not (OUT / name).exists(), f"Refusing to overwrite {name}"
    set_path = OUT / "constructed-queries.json"
    set_ = json.loads(set_path.read_text())
    assert set_["sampled_pairs"] == 50 and len(set_["cases"]) == 400
    raw = rows(OUT / "token-raw.csv")
    full = rows(FULL / "candidate-raw.csv")
    assert len(raw) == len(full) == 1200
    source_hashes = {str(p.relative_to(ROOT)): sha(p) for p in [
        ROOT / "internal/discovery/token.go", ROOT / "internal/discovery/local.go",
        ROOT / "internal/discovery/offline.go", ROOT / "internal/discovery/token_signature_experiment_test.go",
        ROOT / "internal/discovery/token_signature_final_validation_test.go",
        ROOT / "internal/targetquery/query.go", ROOT / "internal/targetaggregation/packet.go",
        ROOT / "internal/aggregation/compare.go", ROOT / "internal/anchorfilter/filter.go",
        ROOT / "internal/targetrouting/token_codec.go", ROOT / "internal/targetposition/position.go",
    ]}
    with tempfile.TemporaryDirectory(prefix="pmeq-signature-final-validation-") as temp:
        rt = Path(temp)
        for name in ("cache", "gopath", "tmp"): (rt / name).mkdir()
        env = {k:v for k,v in os.environ.items() if not k.startswith(("PMEQ_","GO","CGO"))}
        env.update(GOROOT=str(GO.parents[1]), GOMODCACHE=str(MODCACHE), GOPATH=str(rt/"gopath"),
                   GOCACHE=str(rt/"cache"), GOTMPDIR=str(rt/"tmp"), TMPDIR=str(rt/"tmp"),
                   GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off", GOFLAGS="",
                   GOMAXPROCS="32", GOGC="100", GOMEMLIMIT="off", GODEBUG="", CGO_ENABLED="1",
                   CGO_CFLAGS="", CGO_CPPFLAGS="", CGO_CXXFLAGS="",
                   CGO_LDFLAGS=f"-L{NATIVE} -lphase6scmp -lcrypto -pthread",
                   PMEQ_SIGNATURE_FINAL_VALIDATION_OUTPUT=str(OUT))
        binary = rt / "token-final-validation.test"
        build = [str(GO),"test","-tags","phase6native","-c","-o",str(binary),"./internal/discovery"]
        run = [str(binary),"-test.run=^TestTokenSignatureFinalFieldValidation$","-test.count=1","-test.v","-test.timeout=30m"]
        write("final-validation-run-command.txt", "Entry point: python3 tools/validate_signature_token_final_20260923.py\nBuild: " + shlex.join(build) + "\nRun: " + shlex.join(run) + "\n")
        b = subprocess.run(build,cwd=ROOT,env=env,text=True,capture_output=True)
        if b.returncode: raise RuntimeError("Validation build failed:\n"+b.stdout+b.stderr)
        with (OUT / "final-validation-run.log").open("x") as log:
            p = subprocess.run(run,cwd=ROOT/"internal/discovery",env=env,stdout=log,stderr=subprocess.STDOUT)
        if p.returncode: raise RuntimeError("Field validation failed; see final-validation-run.log")
    field = rows(OUT / "token-field-validation.csv")
    assert len(field) == 1600
    groups = {}
    for row in field:
        c = int(row["case_id"])
        groups.setdefault(c, []).append(row)
    assert len(groups) == 400
    for c, group in groups.items():
        assert len(group) == 4
        assert {(r["profile"],r["party"]) for r in group} == {(p,str(i)) for p in ("zero_capacity","nonzero_capacity") for i in (0,1)}
        cols = ("packet_id_fields","anchor_occurrences","dpf_keys","anchor_position_materials","anchor_bucket_ids","anchor_threshold_fields","target_words","target_word_point_shares","target_bucket_word_shares","target_position_materials","target_threshold_fields","routing_manifest_fields","serialized_bytes")
        assert len({tuple(row[k] for k in cols) for row in group}) == 1, c
    token_by = {}
    full_by = {}
    for group, store in ((raw,token_by),(full,full_by)):
        for row in group:
            k = (int(row["case_id"]),int(row["trial"]))
            assert k not in store
            store[k] = row
    assert token_by.keys() == full_by.keys() == {(i,j) for i in range(400) for j in (1,2,3)}
    for (c,trial), old in token_by.items():
        new = full_by[(c,trial)]
        assert int(old["total_token_bytes"]) == int(new["user_to_cloud_bytes"])
        assert int(old["total_token_bytes"]) == 2*int(groups[c][0]["serialized_bytes"])
        assert old["variable_side"] == new["variable_side"] == set_["cases"][c]["variable_side"]
        assert int(old["anchor_signatures"]) == int(new["anchor_signatures"]) == set_["cases"][c]["anchor_signatures"]
        assert int(old["target_signatures"]) == int(new["target_signatures"]) == set_["cases"][c]["target_signatures"]
    # Recompute the published estimators from untouched raw data.
    cases = []
    for c in range(400):
        q = set_["cases"][c]
        x = [token_by[(c,t)] for t in (1,2,3)]
        cases.append(dict(side=q["variable_side"],anchor_r=q["anchor_signatures"],target_r=q["target_signatures"],
                          time_ms=statistics.median(int(v["generation_ns"]) for v in x)/1e6,
                          token_bytes=statistics.median(int(v["total_token_bytes"]) for v in x)))
    existing = rows(OUT / "summary.csv")
    final = []
    for side in ("anchor","target"):
        for n in (2,3,4,6):
            a,t = (n,4) if side == "anchor" else (4,n)
            x = [v for v in cases if (v["side"],v["anchor_r"],v["target_r"]) == (side,a,t)]
            assert len(x) == 50
            mean_t = statistics.mean(v["time_ms"] for v in x)
            mean_b = statistics.mean(v["token_bytes"] for v in x)
            old = next(v for v in existing if (v["variable_side"],int(v["anchor_signatures"]),int(v["target_signatures"])) == (side,a,t))
            assert int(old["query_count"]) == 50 and abs(float(old["mean_generation_time_ms"])-mean_t)<1e-12 and abs(float(old["mean_token_bytes"])-mean_b)<1e-12
            final.append(dict(variation_side=side,anchor_r=a,target_r=t,query_count=50,
                              mean_token_generation_ms=mean_t,mean_total_token_bytes=mean_b))
    with (OUT / "final-paper-table.csv").open("x",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(final[0]));w.writeheader();w.writerows(final)
    report=["# 令牌签名数量实验最终口径核对", "",
            "结论：原令牌单测的 K=S=G=0 不改变 generate 生成的字段集合、字段数量、在线密码运算数量或两云 token 序列化长度。原实验未重跑。论文采用已有 token-raw.csv、query-medians.csv、summary.csv；final-paper-table.csv 是从原始数据重新核算的同值表。", "",
            "完整候选发现的 RunLocal 在 internal/discovery/local.go 中调用同一个 generate，随后把返回的两份 byte slice 分别发给两云，并以其长度填入 UserToCloud。独立单测也直接调用 generate。token.go 的 generate 只读取 q、密钥、桶列表、anchor/target 一次性用户材料、聚合材料的 R 与阈值；没有读取 K、S、G。", "",
            "零容量与非零容量结构探针针对相同 400 个构造查询各生成两云 token、解码并逐字段核对。非零探针 K=1、每个 Target occurrence 的容量=1、S=G=rγ；它只用于检验容量是否影响 token 结构，不是论文计时样本，也没有执行云端候选发现。完整候选发现原始记录的 1200 个 UserToCloud 字节数逐 case/trial 与原独立 token 实验字节数一致。", "",
            "| 字段/材料（每云） | 数量 | 代码依据 |", "|---|---:|---|",
            "| packet ID、keep bound、Anchor count | 各 1 | token.go encodeToken |",
            "| Anchor occurrence / DPF key / BucketID / position bounds / f bound | 各 rδ | token.go generate + encodeToken；anchorquery.MakeOccurrence 每 occurrence 一次 DPF Gen |",
            "| Target routing word-point share / bucket-word share / occurrence ID+position | 各 rγ | targetquery.GenerateTokens 每 word 各一次 KWord、FullEval、SplitPoint、WordBucketComponent、SplitBucketComponent |",
            "| Target position comparison PID 与边界 | rγ | targetquery.GeneratePositionTokens 每 word 一次 ConsumeBounds |",
            "| 聚合阈值 PacketID、QueryID、R、FBound、KeepBound | 各 1 | targetaggregation.UserMaterial.Token；FBound、KeepBound 各一次 Mask |",
            "| Routing manifest header | 1 | targetrouting.EncodeToken |", "",
            "每云序列化长度 = 122 + 2352·rδ + 66·rγ bytes；两云总长度为其两倍。400 个查询的两种容量探针共 1600 份 token 均满足该公式；原实验和完整候选发现的 1200 对 token 字节数也均满足。字段结构一致、字节统计一致。随机 PID、掩码和秘密分享值本来不同，不比较逐字节 token 内容。", "",
            "K/S/G 只改变离线 Provision/Preprocess 中的云端一次性材料量。anchorfilter.Preprocess(n) 的用户部分始终为 PID/EtaL/EtaR；aggregation.PreprocessComparison(n) 的用户部分始终为单个 BoundMask；targetposition.Preprocess(capacities) 始终给每个 Target occurrence 一个用户材料；targetaggregation.Preprocess 的用户部分为 R 和两个 BoundMask。因此在线 generate 的密码调用次数仅随 rδ、rγ 变化，不随 K/S/G 变化。离线预处理运算量会随容量变化，但不在原令牌计时边界内。", "",
            "统计口径：逐查询三次 generation_ns 取中位数并换算 ms，再对每档 50 条查询求平均；令牌大小为发送给 CS1、CS2 的实际序列化长度之和，逐查询三次取中位数再求档位平均。", "",
            "| 变化侧 | rδ | rγ | 查询数 | 令牌生成 ms | 两云 token bytes |", "|---|---:|---:|---:|---:|---:|"]
    for v in final:
        report.append(f"| {v['variation_side']} | {v['anchor_r']} | {v['target_r']} | 50 | {v['mean_token_generation_ms']:.9f} | {v['mean_total_token_bytes']:.0f} |")
    report += ["", "来源校验：", "- constructed-queries.json SHA-256: " + sha(set_path),
               "- token-raw.csv SHA-256: " + sha(OUT/"token-raw.csv"),
               "- candidate-raw.csv SHA-256: " + sha(FULL/"candidate-raw.csv"),
               "- token-field-validation.csv SHA-256: " + sha(OUT/"token-field-validation.csv"),
               "- 源码 SHA-256: `" + json.dumps(source_hashes,ensure_ascii=False,sort_keys=True) + "`", ""]
    write("final-validation.md","\n".join(report))
    print("Validated 400 cases, 1200 saved trial comparisons, 1600 field probe tokens")
    for v in final: print(v)


if __name__ == "__main__": main()
