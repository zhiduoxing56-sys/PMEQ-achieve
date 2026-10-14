"""Run the authorized full regression, then exactly two 20-query pilots.

No existing implementation, oracle, query, baseline or result is overwritten.
All build/run caches, native library copies and new outputs stay in this repo.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/n-domain-regression-pilot-20260920"
RUNTIME = ROOT / "artifacts/n-domain-regression-pilot-runtime"
RAW = Path("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    assert ROOT == Path("/home/tenggn/projects/clean_pmeq")
    assert subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip() == str(ROOT)
    # Only these two files are read from the external data directory.
    raw_hashes = {name: digest(RAW / name) for name in ("area", "area_alias")}
    protected = {}
    for top in ("internal", "tools", "results", "artifacts"):
        for path in sorted((ROOT / top).rglob("*")):
            if path.is_file():
                assert not path.is_symlink(), path
                protected[str(path.relative_to(ROOT))] = digest(path)
    OUT.mkdir(exist_ok=False)
    RUNTIME.mkdir(exist_ok=False)
    for name in ("tmp", "cache", "native", "gopath", "modcache"):
        (RUNTIME / name).mkdir()
    # Installed toolchain and the already validated local library; never use
    # any source, executable or artifact under the external data repository.
    shutil.copytree("/tmp/go", RUNTIME / "go")
    native = Path("/tmp/phase6-native/libphase6scmp.a")
    expected = json.loads((ROOT / "results/global-scale-environment.json").read_text())["native_library_sha256"]
    assert digest(native) == expected, "local native library differs from retained baseline"
    shutil.copy2(native, RUNTIME / "native/libphase6scmp.a")
    modules = ("github.com/gtank/ristretto255", "filippo.io/edwards25519")
    versions = ("v0.2.0", "v1.1.0")
    modsrc = Path("/home/tenggn/go/pkg/mod")
    for module, version in zip(modules, versions):
        shutil.copytree(modsrc / f"{module}@{version}", RUNTIME / "modcache" / f"{module}@{version}")
        shutil.copytree(modsrc / "cache/download" / module, RUNTIME / "modcache/cache/download" / module)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PMEQ_")}
    env.update(GOROOT=str(RUNTIME / "go"), GOPATH=str(RUNTIME / "gopath"),
               GOMODCACHE=str(RUNTIME / "modcache"), GOCACHE=str(RUNTIME / "cache"),
               GOTMPDIR=str(RUNTIME / "tmp"), TMPDIR=str(RUNTIME / "tmp"),
               GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off",
               CGO_LDFLAGS=f"-L{RUNTIME / 'native'} -lphase6scmp -lcrypto -pthread",
               PMEQ_DATABASE_REGRESSION_PILOT="1", PMEQ_DATABASE_OUTPUT=str(OUT))
    go = str(RUNTIME / "go/bin/go")
    binary = RUNTIME / "database-regression-pilot.test"
    explicit = {
        "internal/discovery/cloud.go": ["NewCount(st.payload.LayoutID, n)", "DecodeShuffleForDomain(peer, n)", "DecodeKeepOpeningForDomain", "EncodeSharesForDomain"],
        "internal/discovery/local.go": ["RecoverForDomain"],
        "internal/discovery/offline.go": ["n := len(a.payload.Slots)", "PreprocessComparison(n", "PreprocessCompactionWithBucketBits(a.payload.LayoutID, n, 16)"],
    }
    for name, required in explicit.items():
        source = (ROOT / name).read_text()
        assert "CandidateCount" not in source
        assert all(text in source for text in required), name
    metadata = dict(started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    protected_sha256=protected, raw_sha256=raw_hashes, native_sha256=expected,
                    explicit_domain_calls=explicit, seed=20260920,
                    go=subprocess.check_output([go, "version"], cwd=ROOT, env=env, text=True).strip(),
                    timer="existing RunLocal Metrics.LocalE2E; Token + actual cloud online + Recovery; excludes index/offline/oracle",
                    communication="actual encoded sends; ServerBytes already includes both directions, counted once",
                    pilot_only=True)
    (OUT / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    with (OUT / "build.log").open("x") as log:
        subprocess.run([go, "test", "-tags", "phase6native", "-c", "-o", str(binary), "./internal/discovery"],
                       cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    with (OUT / "run.log").open("x") as log:
        result = subprocess.run([str(binary), "-test.run=^TestDatabaseRegressionThenPilot$", "-test.v", "-test.timeout=2h"],
                                cwd=ROOT / "internal/discovery", env=env, stdout=log, stderr=subprocess.STDOUT)
    changed = [name for name, before in protected.items() if not (ROOT / name).is_file() or digest(ROOT / name) != before]
    (OUT / "preservation.json").write_text(json.dumps({"checked": len(protected), "changed": changed}, indent=2) + "\n")
    assert not changed, changed
    if result.returncode:
        raise SystemExit(f"Regression/pilot stopped, exit {result.returncode}; inspect {OUT / 'run.log'} and first-difference.json")
    assert (OUT / "completed.json").exists()
    print("Regression and both pilots passed:", OUT, flush=True)


if __name__ == "__main__":
    main()
