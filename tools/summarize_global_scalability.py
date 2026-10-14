"""Summarize only completed actual operator runs; standard library only."""
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics as st

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results"
NS = (120071, 250000, 500000, 1000000)

def quantile(xs, q):
    return sorted(xs)[max(0, math.ceil(len(xs)*q)-1)]

def write_csv(name, rows):
    with (OUT/name).open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

def fit(rows, features):
    # Least squares on scaled regressors avoids poorly conditioned raw N.
    x = [[1.0]+[r[f]/100000 for f in features] for r in rows]
    y = [r["mean_ms"] for r in rows]
    d = len(x[0])
    mat = [[sum(z[i]*z[j] for z in x) for j in range(d)] +
           [sum(z[i]*v for z, v in zip(x, y))] for i in range(d)]
    for i in range(d):
        pivot = max(range(i, d), key=lambda j: abs(mat[j][i]))
        mat[i], mat[pivot] = mat[pivot], mat[i]
        den = mat[i][i]
        assert abs(den)>1e-14
        mat[i] = [v/den for v in mat[i]]
        for j in range(d):
            if j != i:
                factor = mat[j][i]
                mat[j] = [a-factor*b for a, b in zip(mat[j], mat[i])]
    coef = [row[-1] for row in mat]
    predicted = [sum(a*b for a,b in zip(z, coef)) for z in x]
    residual = [a-b for a,b in zip(y,predicted)]
    r2 = 1-sum(r*r for r in residual)/sum((v-st.mean(y))**2 for v in y)
    return {"intercept_ms": coef[0], "coefficients_ms_per_record":
            {f: coef[i+1]/100000 for i,f in enumerate(features)}, "r_squared": r2,
            "rmse_ms": math.sqrt(st.mean(r*r for r in residual)),
            "max_absolute_residual_ms": max(map(abs,residual)),
            "points": len(rows), "fitted_to": "equally weighted means of actual 50 measured invocations"}

def main():
    summary, raw = [], []
    for n in NS:
        for operator, distributions in (("keep", ("empirical", "uniform")),
                                        ("exact_k", ("median", "p95", "max"))):
            for distribution in distributions:
                path = OUT/f"global-scale-{operator}-{n}-{distribution}.jsonl"
                samples = [json.loads(x) for x in path.read_text().splitlines()]
                assert len(samples)==60 and [x["Iteration"] for x in samples]==list(range(60)), path
                measured = [x for x in samples if not x["Warmup"]]
                assert len(measured)==50
                for s in samples:
                    assert s["N"]==n and s["Operator"]==operator and s["Distribution"]==distribution
                    assert s["Status"]=="ok" and s["Sent"]==list(reversed(s["Received"]))
                    assert s["Rounds"]==([1,1] if operator=="keep" else [3,3])
                    raw.append({**{k:v for k,v in s.items() if k not in ("Sent","Received","Rounds")},
                                **{f"{field.lower()}_cs{p}": s[field][p]
                                   for field in ("Sent","Received","Rounds") for p in (0,1)}})
                latency = [x["Milliseconds"] for x in measured]
                assert len({tuple(x["Sent"]) for x in measured})==1
                ks = [x["K"] for x in measured]
                row = dict(operator=operator, distribution=distribution, N=n,
                           K=ks[0] if len(set(ks))==1 else "varies", mean_K=st.mean(ks),
                           ratio=st.mean(ks)/n, warmup=10, measured=50,
                           mean_ms=st.mean(latency), p50_ms=quantile(latency,.5),
                           p95_ms=quantile(latency,.95), p99_ms=quantile(latency,.99),
                           min_ms=min(latency), max_ms=max(latency), stdev_ms=st.stdev(latency),
                           mean_standard_error_ms=st.stdev(latency)/math.sqrt(50),
                           ms_per_100k=st.mean(latency)*100000/n,
                           sent_cs0_bytes=measured[0]["Sent"][0], sent_cs1_bytes=measured[0]["Sent"][1],
                           received_cs0_bytes=measured[0]["Received"][0], received_cs1_bytes=measured[0]["Received"][1],
                           communication_bytes=sum(measured[0]["Sent"]),
                           online_rounds=measured[0]["Rounds"][0],
                           peak_heap_bytes=max(x["PeakHeapBytes"] for x in measured),
                           peak_rss_bytes=max(x["PeakRSSBytes"] for x in measured),
                           mean_offline_ms=st.mean(x["OfflineMilliseconds"] for x in measured))
                resources=(OUT/f"global-scale-{operator}-{n}-{distribution}-resources.txt").read_text()
                row["process_lifetime_peak_rss_bytes"]=int(next(line.rsplit(":",1)[1] for line in resources.splitlines()
                                                                 if "Maximum resident set size (kbytes)" in line))*1024
                summary.append(row)
    profiles=json.loads((OUT/"global-scale-profiles.json").read_text())
    ks=[x["K"] for x in profiles]
    ratios={label:{"K_at_120071":value,"ratio":value/120071}
            for label,value in (("median",st.median(ks)),("p95",quantile(ks,.95)),("max",max(ks)))}
    keep=[r for r in summary if r["operator"]=="keep" and r["distribution"]=="empirical"]
    exact=[r for r in summary if r["operator"]=="exact_k"]
    fits={"keep_aN_b":fit(keep,["N"]),"exact_aN_bK_c":fit(exact,["N","K"]),
          "exact_aN_b_baseline":fit(exact,["N"])}
    growth={}
    comparisons=[]
    for op, ds in (("keep",("empirical","uniform")),("exact_k",("median","p95","max"))):
        for dist in ds:
            r=[x for x in summary if x["operator"]==op and x["distribution"]==dist]
            growth[f"{op}_{dist}"]=r[-1]["mean_ms"]/r[0]["mean_ms"]
    for n in NS:
        e=next(r for r in summary if r["N"]==n and r["distribution"]=="empirical")
        u=next(r for r in summary if r["N"]==n and r["distribution"]=="uniform")
        comparisons.append(dict(N=n, empirical_ms=e["mean_ms"], uniform_ms=u["mean_ms"],
                                uniform_over_empirical=u["mean_ms"]/e["mean_ms"],
                                relative_difference_percent=100*(u["mean_ms"]/e["mean_ms"]-1)))
    environment=json.loads((OUT/"global-scale-environment.json").read_text())
    environment["cpu_model"]=next((x.split(":",1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name")),"unknown")
    environment["input_sha256"]={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                                  (OUT/"anchor-breakdown-queries.json",OUT/"phase7b-workload.jsonl.gz",OUT/"global-scale-profiles.json")}
    result={"environment":environment,
            "empirical_queries":len(profiles),"candidate_ratios":ratios,"summary":summary,
            "fits":fits,"growth_120071_to_1m":growth,"keep_distribution_comparison":comparisons,
            "samples":raw}
    (OUT/"global-scale-results.json").write_text(json.dumps(result,indent=2)+"\n")
    write_csv("global-scale-summary.csv",summary)
    write_csv("global-scale-samples.csv",raw)
    write_csv("global-scale-chart-data.csv",[{k:r[k] for k in
              ("operator","distribution","N","K","ratio","mean_ms","p50_ms","p95_ms","p99_ms",
               "ms_per_100k","communication_bytes","online_rounds","peak_heap_bytes","peak_rss_bytes")}
              for r in summary])
    write_csv("global-scale-distribution-comparison.csv",comparisons)
    lines=["# Global-domain production operator scalability", "",
           "All values below are newly executed production protocol measurements, not extrapolations.","",
           "Four N values; each operator/distribution cell has 10 warmups + 50 measured invocations. "
           "No index build and no E2E invocation. Exact-K explicitly parameterizes only decoder domain checks; "
           "default decoder limits remain 120071. Wire format, masks, shuffle, opening, extraction and comparison are unchanged.","",
           "Latency is combined two-party completion time over production framed local byte messages (not network RTT). "
           "Fresh offline material, synthetic input generation, pre-timer GC and correctness checks are excluded. "
           "Peak RSS/Go heap are sampled every 10ms plus boundaries across BOTH parties in one process, including prepared "
           "material and benchmark inputs; RSS can include pages retained from offline preparation. They are not per-cloud "
           "or incremental allocation measurements. Process lifetime maximum RSS is also retained in per-case resources.txt files.","",
           "Quantiles use nearest rank: with 50 samples, p99 equals maximum. Communication counts actual framed "
           "CS0/CS1 sends once, excluding offline delivery and user token ingress (private lambda masking is outside the operator timer). "
           "For these symmetric cases each party receives the other party's sent bytes. Online rounds count synchronous exchanges.","",
           "All 854 c histograms were recovered read-only from existing raw names and query chunks/position tolerances; "
           "their thresholded K values match the historical production outputs for every query. These are trusted benchmark "
           "input statistics, not claims that clouds opened c. Each Keep invocation selects an empirical (r,lambda,histogram) "
           "profile on a deterministic schedule and samples c in [0,r]. The uniform control uses the same query/threshold "
           "schedule with uniform c. Lambda is supplied to the parties only through production BoundMask.Mask. "
           "Every Keep output bit and every Exact-K selected ID/scalar/bucket is verified outside timing. "
           "Compaction masks and permutations and comparison keys are freshly generated on every invocation.","",
           "Candidate ratio source: "+json.dumps(ratios),"",
           "## Keep", "", "| N | distribution | mean ms | p50 | p95 | p99 | ms/100k | send/receive per party B | rounds | peak heap MiB | peak RSS MiB |",
           "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in summary:
        if r["operator"]=="keep":
            lines.append(f'| {r["N"]} | {r["distribution"]} | {r["mean_ms"]:.3f} | {r["p50_ms"]:.3f} | {r["p95_ms"]:.3f} | {r["p99_ms"]:.3f} | {r["ms_per_100k"]:.3f} | {r["sent_cs0_bytes"]} | {r["online_rounds"]} | {r["peak_heap_bytes"]/2**20:.1f} | {r["peak_rss_bytes"]/2**20:.1f} |')
    lines += ["", "## Exact-K", "", "| N | ratio tier | K | K/N | mean ms | p50 | p95 | p99 | ms/100k | total wire B | rounds | peak heap MiB | peak RSS MiB |",
              "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in exact:
        lines.append(f'| {r["N"]} | {r["distribution"]} | {r["K"]} | {r["ratio"]:.8f} | {r["mean_ms"]:.3f} | {r["p50_ms"]:.3f} | {r["p95_ms"]:.3f} | {r["p99_ms"]:.3f} | {r["ms_per_100k"]:.3f} | {r["communication_bytes"]} | {r["online_rounds"]} | {r["peak_heap_bytes"]/2**20:.1f} | {r["peak_rss_bytes"]/2**20:.1f} |')
    lines += ["", "## Fits and measured growth", "", "Time in milliseconds, N/K in records. Models describe only the tested ranges; K/N is at most the empirical maximum. With narrow K variation, the K coefficient may be dominated by timing noise.", "", "```json",json.dumps({"fits":fits,"growth":growth,"distribution_comparison":comparisons},indent=2),"```","",
              "The Keep loop performs exactly N native SCMP evaluations per party regardless of c. Distribution timing "
              "comparisons assess practical timing sensitivity; they are not a constant-time or side-channel proof.","",
              "## Reproduce", "", "```sh", "PMEQ_SCALE_PROFILE=1 CGO_LDFLAGS='-L/tmp/phase6-native -lphase6scmp -lcrypto -pthread' GOCACHE=/tmp/anchor-timing-cache /tmp/go/bin/go test -tags phase6native ./internal/discovery -run '^TestGlobalScaleProfiles$' -count=1 -v",
              "python3 tools/run_global_scalability.py", "python3 tools/summarize_global_scalability.py", "```", "",
              "The runner resumes completed cells and refuses to overwrite incomplete results. Raw JSONL retains warmups. "
              "The initial pilot is excluded from all final statistics. CSV/JSON/chart data: global-scale-summary.csv, "
              "global-scale-samples.csv, global-scale-results.json, global-scale-chart-data.csv."]
    k1=keep[-1]
    e1=[r for r in exact if r["N"]==1000000]
    kfit=fits["keep_aN_b"]
    efit=fits["exact_aN_bK_c"]
    lines += ["", "## Interpretation", "",
              f'Keep: T_ms = {kfit["coefficients_ms_per_record"]["N"]:.9f} N + {kfit["intercept_ms"]:.6f}; R²={kfit["r_squared"]:.6f}.', "",
              f'Exact-K: T_ms = {efit["coefficients_ms_per_record"]["N"]:.9f} N + {efit["coefficients_ms_per_record"]["K"]:.9f} K + {efit["intercept_ms"]:.6f}; R²={efit["r_squared"]:.6f}.', "",
              f'Actual 1M mean Keep: {k1["mean_ms"]:.3f} ms. Actual 1M Exact-K means: '+
              ", ".join(f'{r["distribution"]} K={r["K"]}: {r["mean_ms"]:.3f} ms' for r in e1)+".", "",
              ("Keep has the larger measured mean online latency at 1M in all three Exact-K ratios."
               if k1["mean_ms"]>max(r["mean_ms"] for r in e1) else
               "The larger stage at 1M depends on candidate ratio; compare the measured means above."), "",
              "Approximate linearity should be judged from the fits, residuals, and ms/100k columns together. "
              "The domain grows by 8.3284x; exact measured timing growth is provided above. "
              "No inference here covers untested dense K/N or distributed-network performance."]
    (OUT/"global-scale-report.md").write_text("\n".join(lines)+"\n")
    print(json.dumps({"fits":fits,"growth":growth,"comparisons":comparisons},indent=2))

if __name__=="__main__":
    main()
