# IMDb reverse-direction outsourcing measurement

This command builds only the missing static outsourcing artifacts for
`MOVIE.primaryTitle` as BSMJ and `MOVIECAST.aliasTitle` as PSMJ plus the
target-object matrix. It deliberately issues no query ticket and does not
implement the reverse online query. Its output has a separate index ID,
layout ID, table-specific keyed domains, private files and report namespace.
The existing `MOVIECAST.BSMJ -> MOVIE.PSMJ` sealed query index is read-only.

The frozen 100,000+10,000 sample and existing owner keys are verified and read
only. The reverse target dimension is the actual maximum number of MOVIECAST
objects sharing one movie join value; the repeated q-gram bound is measured
from the full sample. The matrix producer uses the original GF127 coefficient
and Ring64 object-ID sharing equations, but writes matrix manifest version 2.
The official query loader accepts neither this D nor version 2; this is an
offline-only index artifact, as requested.

The builder requires a new empty output namespace and refuses overwrite. It
preflights the actual keyed layout, checks Windows C and WSL free space before
writing, and checks Windows C again during large writes. The full build writes
to a distinct incomplete directory and publishes the final path only after
all output, layout, count and hash checks complete. The final report contains
role-separated file sizes and SHA-256 hashes, stage times and peak RSS.

From this repository root, with the installed Go toolchain on `PATH`:

```sh
go test ./tools/imdb_reverse_outsource -run TestReverseOfflineCryptoArtifacts -count=1
go run ./tools/imdb_reverse_outsource --phase preflight \
  --sample /home/tenggn/projects/clean_pmeq/imdb_production_20261015 \
  --keys /home/tenggn/projects/clean_pmeq/.private/imdb-production-keypair.json \
  --private-root /home/tenggn/projects/clean_pmeq/.private \
  --output /home/tenggn/projects/clean_pmeq/.private/imdb-reverse-outsource-v1
go run ./tools/imdb_reverse_outsource --phase build \
  --sample /home/tenggn/projects/clean_pmeq/imdb_production_20261015 \
  --keys /home/tenggn/projects/clean_pmeq/.private/imdb-production-keypair.json \
  --private-root /home/tenggn/projects/clean_pmeq/.private \
  --output /home/tenggn/projects/clean_pmeq/.private/imdb-reverse-outsource-v1
```

The `build` phase cannot run again against an existing published directory.
For another database scale, select a distinct namespace and adjust the frozen
sample contract in an isolated branch; never overwrite the sealed query index.
