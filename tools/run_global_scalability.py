"""Run fresh-material, production operator benchmarks sequentially."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
ENV = dict(os.environ, CGO_LDFLAGS="-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread",
           GOCACHE="/tmp/anchor-timing-cache")
GO = "/tmp/go/bin/go"
BINARY = "/tmp/pmeq-global-scalability.test"

def main():
    subprocess.run([GO, "test", "-tags", "phase6native", "-c", "-o", BINARY,
                    "./internal/discovery"], cwd=ROOT, env=ENV, check=True)
    sources = ["internal/discovery/global_scalability_native_test.go",
               "internal/discovery/cloud.go", "internal/aggregation/compare.go",
               "internal/aggregation/compaction.go", "internal/aggregation/compaction_codec.go",
               "internal/scmpnative/native.go"]
    metadata = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "platform": platform.platform(), "cpu_count": os.cpu_count(),
                "go": subprocess.check_output([GO, "version"], text=True).strip(),
                "GOMAXPROCS": ENV.get("GOMAXPROCS", "Go default"),
                "GOGC": ENV.get("GOGC", "Go default (100)"),
                "transport": "production framed byte messages over local channels; two goroutines",
                "memory": "10ms sampled online combined-process Go HeapAlloc and RSS, including provisioned material and harness; not per-cloud",
                "latency": "online only; excludes fresh offline preprocessing, input generation, pre-timer GC, correctness check",
                "warmup": 10, "measured": 50,
                "source_sha256": {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
                                  for p in sources if (ROOT/p).exists()},
                "native_library_sha256": hashlib.sha256(Path("/tmp/phase6-native/libphase6scmp.a").read_bytes()).hexdigest()}
    (RESULTS / "global-scale-environment.json").write_text(json.dumps(metadata, indent=2)+"\n")
    for n in (120071, 250000, 500000, 1000000):
        for operator, distributions in (("keep", ("empirical", "uniform")),
                                         ("exact_k", ("median", "p95", "max"))):
            for distribution in distributions:
                stem = f"global-scale-{operator}-{n}-{distribution}"
                output = RESULTS / (stem+".jsonl")
                if output.exists():
                    rows = [json.loads(x) for x in output.read_text().splitlines()]
                    if len(rows) == 60 and all(x.get("PeakRSSBytes", 0)>0 for x in rows):
                        print("Already complete:", stem, flush=True)
                        continue
                    raise RuntimeError(f"Incomplete output must be inspected before rerun: {output}")
                env = dict(ENV, PMEQ_SCALE_N=str(n), PMEQ_SCALE_OPERATOR=operator,
                           PMEQ_SCALE_DISTRIBUTION=distribution)
                print("Running:", stem, flush=True)
                with (RESULTS / (stem+".log")).open("w") as log:
                    subprocess.run(["/usr/bin/time", "-v", "-o", str(RESULTS/(stem+"-resources.txt")),
                                    BINARY, "-test.run=^TestGlobalScaleOperator$", "-test.v", "-test.timeout=4h"],
                                   cwd=ROOT/"internal/discovery", env=env, stdout=log,
                                   stderr=subprocess.STDOUT, check=True)
                print("Complete:", stem, flush=True)
    metadata["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (RESULTS / "global-scale-environment.json").write_text(json.dumps(metadata, indent=2)+"\n")

if __name__ == "__main__":
    main()
