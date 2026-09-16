# PHASE7B experiments

All commands run from the clean repository using Go1.27.1. Use a writable
GOCACHE. Old MusicBrainz/source paths are read-only. No production runner or
Target equality/position implementation is introduced.

1. Recover the missing detailed PHASE7 workload by the same seeded FULL native
   replay (takes about22 minutes). Output path MUST be new/empty; the optional
   trace is append-only. The native bridge is built by the existing PHASE6 recipe
   in results/phase6-audit.md. Plaintext trace is trusted-test-only.

```sh
CGO_LDFLAGS=/tmp/phase6-native/libphase6scmp.a PMEQ_AGG_FULL=1 \
 PMEQ_ROUTING_SKIP_GROUPS=1 PMEQ_ROUTING_WORKLOAD=/tmp/phase7b-workload.jsonl \
 go test -tags 'phase6native phase7integration' ./internal/aggregation \
 -run '^TestReal1000Queries$' -count=1 -v -timeout=120m
```

2. Run same-key/same-logical-group layouts and concrete workload sweep:

```sh
PMEQ_7B_SWEEP=/tmp/phase7b-layouts.json go test ./internal/indexbuild \
 -run '^TestPhase7BSweep$' -count=1 -v
PMEQ_7B_LAYOUTS=/tmp/phase7b-layouts.json \
 PMEQ_7B_WORKLOAD=/tmp/phase7b-workload.jsonl PMEQ_7B_LOADS=/tmp/phase7b-loads.json \
 go test ./internal/targetartifact -run '^TestPhase7BWorkloadSweep$' -count=1 -v
```

3. Fully materialize the chosen final production width. Directory must not
   already contain share files. The file writer intentionally uses O_EXCL.

```sh
PMEQ_7B_ARTIFACT=/tmp/phase7b-final-artifacts go test ./internal/indexbuild \
 -run '^TestPhase7BMaterialize$' -count=1 -v -timeout=30m
PMEQ_7B_ROUTE_ARTIFACT=/tmp/phase7b-final-artifacts \
 PMEQ_7B_WORKLOAD=/tmp/phase7b-workload.jsonl go test ./internal/targetartifact \
 -run '^TestFinalPayloadAndRoutes$' -count=1 -v -timeout=30m
```

The final regression generates new width-bound offline global payload material,
retains the saved candidate order, and performs current private routing against
actual final party files. It does not rerun Anchor cryptography for every width.
The global LayoutID is newly provisioned, not an old-layout migration. Future
Anchor provisioning must use its matching existing DealerLayout/alignment.

4. Render counts/projections from raw outputs and the existing standalone PE
   audit's five saved results (not a PE integration):

```sh
python3 tools/phase7b/report.py . /tmp/phase7b-layouts.json \
 /tmp/phase7b-loads.json /tmp/phase7b-final-artifacts /tmp/phase7b-pe.jsonl
```

Original source hash and benchmark assumptions are in the results report.
The committed compressed trace/layouts/loads are test-only reproducibility data.
Do not place them in a cloud artifact directory or a query-time dependency.
