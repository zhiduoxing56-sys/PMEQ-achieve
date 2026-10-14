"""Build once, smoke-test, then serially run the fixed formal experiment.

No automatic retries, result replacement, environment tuning or deletions.
Only two explicitly authorized external raw data files are read by the Go test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PREVIOUS = ROOT / "artifacts/n-domain-regression-pilot-runtime"
RUNTIME = ROOT / "results/database-scalability-formal-20260920-runtime"
SMOKE = ROOT / "results/database-scalability-formal-20260920-smoke"
FORMAL = ROOT / "results/database-scalability-formal-20260920"
NEW = {"internal/discovery/database_scalability_native_test.go",
       "tools/run_database_scalability.py", "tools/summarize_database_scalability.py"}
RAW = Path("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump")


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def save(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def main():
    global RUNTIME, FORMAL
    parser = argparse.ArgumentParser()
    parser.add_argument("--only-100", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.only_100 != (args.output is not None):
        parser.error("--only-100 and --output must be supplied together")
    if args.only_100:
        FORMAL = args.output.resolve()
        assert FORMAL.is_relative_to(ROOT / "results"), "Output must be inside repository results"
        RUNTIME = FORMAL.with_name(FORMAL.name + "-runtime")
    assert ROOT == Path("/home/tenggn/projects/clean_pmeq")
    assert subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip() == str(ROOT)
    for path in ((RUNTIME, FORMAL) if args.only_100 else (RUNTIME, SMOKE, FORMAL)):
        assert not path.exists(), f"Refusing existing output: {path}"
    old = json.loads((ROOT / "results/timing-calibration-20260920/environment.json").read_text())
    assert all(sha(ROOT / name) == value for name, value in old["source_sha256"].items()), "Frozen source changed"
    current_sources = {str(p.relative_to(ROOT)): sha(p) for top in ("internal", "tools")
                       for p in sorted((ROOT / top).rglob("*")) if p.is_file()}
    current_sources.update({name: sha(ROOT / name) for name in ("go.mod", "go.sum")})
    assert set(current_sources) - set(old["source_sha256"]) == NEW
    source_hash = hashlib.sha256("".join(f"{current_sources[p]}  {p}\n" for p in sorted(current_sources)).encode()).hexdigest()
    raw_hash = {n: sha(RAW / n) for n in ("area", "area_alias")}
    assert raw_hash == old["raw_sha256"]
    disk = shutil.disk_usage(ROOT)
    pilot = ROOT / "results/n-domain-regression-pilot-20260920"
    actual = {n: (pilot / n).stat().st_size for n in
              ("pilot-20-queries.jsonl", "pilot-100-queries.jsonl", "regression-100-queries.jsonl")}
    # With every static bucket retained, pilot domain evidence now contains up
    # to 65536 sigma lengths per record. Include that expansion explicitly.
    estimate = 15 * 854 * (actual["regression-100-queries.jsonl"] / 854 + 65536 * 8)
    reserve = 150 * (1 << 30)  # includes possible full static exports and ample headroom
    assert disk.free >= reserve, f"Insufficient safe free disk: {disk.free}, require {reserve}; delete nothing"
    protected = {str(p.relative_to(ROOT)): sha(p) for p in sorted(ROOT.rglob("*"))
                 if ".git" not in p.relative_to(ROOT).parts and p.is_file()}
    RUNTIME.mkdir()
    for name in ("cache", "tmp", "gopath"):
        (RUNTIME / name).mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PMEQ_", "GO", "CGO"))}
    env.update(GOROOT=str(PREVIOUS / "go"), GOMODCACHE=str(PREVIOUS / "modcache"),
               GOPATH=str(RUNTIME / "gopath"), GOCACHE=str(RUNTIME / "cache"),
               GOTMPDIR=str(RUNTIME / "tmp"), TMPDIR=str(RUNTIME / "tmp"),
               GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off", GOFLAGS="",
               GOMAXPROCS="32", GOGC="100", GOMEMLIMIT="off", GODEBUG="", CGO_ENABLED="1",
               CGO_CFLAGS="", CGO_CPPFLAGS="", CGO_CXXFLAGS="",
               CGO_LDFLAGS=f"-L{PREVIOUS / 'native'} -lphase6scmp -lcrypto -pthread",
               PYTHONDONTWRITEBYTECODE="1")
    go = str(PREVIOUS / "go/bin/go")
    assert subprocess.check_output([go, "version"], env=env, text=True).strip() == "go version go1.27.1 linux/amd64"
    native_hash = sha(PREVIOUS / "native/libphase6scmp.a")
    assert native_hash == "6281a4740af6bbc6a788fd26c63614db5aa39db798731d91d5979167e70a75c3"
    meta = dict(source_sha256=current_sources, source_tree_sha256=source_hash,
                raw_sha256=raw_hash, native_sha256=native_hash,
                head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                env={k: v for k, v in env.items() if k.startswith(("GO", "CGO", "PMEQ_")) or k == "TMPDIR"},
                cpu_affinity=sorted(os.sched_getaffinity(0)), uname=list(os.uname()),
                disk_free=disk.free, disk_reserve=reserve, pilot_actual_bytes=actual,
                projected_jsonl_bytes_with_full_static_evidence=estimate,
                timer="unchanged RunLocal Token + actual local clouds + Recovery; no index/static/Provision/oracle",
                communication="actual encoded sends; sum token lengths + both cloud sends + sum output lengths")
    save(RUNTIME / "environment.json", meta)
    save(RUNTIME / "preservation-before.json", protected)
    binary = RUNTIME / "database-scalability.test"
    build = [go, "test", "-tags", "phase6native", "-c", "-o", str(binary), "./internal/discovery"]
    with (RUNTIME / "build.log").open("x") as f:
        subprocess.run(build, cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT, check=True)
    info = subprocess.check_output([go, "version", "-m", str(binary)], env=env, text=True)
    assert "-race=true" not in info and "-tags=phase6native" in info
    save(RUNTIME / "binary.json", dict(sha256=sha(binary), build_info=info, build_command=build))
    with (RUNTIME / "unit-tests.log").open("x") as f:
        subprocess.run([str(binary), "-test.run=^TestDatabaseScalabilityHelpers$", "-test.v"],
                       cwd=ROOT / "internal/discovery", env=env, stdout=f, stderr=subprocess.STDOUT, check=True)
        subprocess.run([sys.executable, str(ROOT / "tools/summarize_database_scalability.py"), "--self-test"],
                       cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT, check=True)
    runs = (("formal-100", FORMAL),) if args.only_100 else (("smoke", SMOKE), ("formal", FORMAL))
    for mode, out in runs:
        assert all(sha(ROOT / p) == h for p, h in current_sources.items())
        out.mkdir()
        runenv = dict(env, PMEQ_DATABASE_SCALABILITY=mode, PMEQ_DATABASE_SCALABILITY_OUTPUT=str(out))
        cmd = [str(binary), "-test.run=^TestDatabaseScalabilityFormal$", "-test.count=1", "-test.v", "-test.timeout=24h"]
        save(out / "environment.json", dict(meta, mode=mode, command=cmd, binary_sha256=sha(binary)))
        print("START", mode, out, flush=True)
        start = time.time()
        with (out / "run.log").open("x") as log:
            p = subprocess.Popen(cmd, cwd=ROOT / "internal/discovery", env=runenv, stdout=log, stderr=subprocess.STDOUT)
            save(out / "execution.json", dict(pid=p.pid, start_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                             cwd=str(ROOT / "internal/discovery")))
            code = p.wait()
        changed = [name for name, h in protected.items() if not (ROOT / name).is_file() or sha(ROOT / name) != h]
        save(out / "preservation-after.json", dict(checked=len(protected), changed=changed))
        assert not changed, changed
        assert all(sha(RAW / n) == h for n, h in raw_hash.items())
        save(out / "process-exit.json", dict(exit_code=code, elapsed_seconds=time.time()-start))
        if code:
            failures = [str(x.relative_to(out)) for x in out.rglob("first-difference.json")]
            save(out / "stopped.json", dict(reason="test failure or early exit; no retries", failures=failures))
            raise SystemExit(f"STOPPED {mode}; inspect {out / 'run.log'} and {failures}")
        with (out / "summary.log").open("x") as log:
            result = subprocess.run([sys.executable, str(ROOT / "tools/summarize_database_scalability.py"), str(out)],
                                    cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise SystemExit(f"STOPPED {mode}: derived audit failed; {out / 'summary.log'}")
        print("PASSED", mode, flush=True)
    print("ALL FORMAL SCALES COMPLETE; no figures generated", flush=True)


if __name__ == "__main__":
    main()
