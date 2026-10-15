#!/usr/bin/env python3
"""Freeze the approved IMDb 100000 x 10000 sample from the read-only mother DB."""

import hashlib
import itertools
import json
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "imdb_final_dataset/data/imdb_final.duckdb"
OUT = ROOT / "imdb_production_20261015"
HANDOFF = ROOT / "reports/production-handoff-20261015/evidence/final-scale-proposals.json"
SEED = 20261015


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sequence_digest(values):
    return hashlib.sha256("\n".join(values).encode()).hexdigest()


def main():
    if OUT.exists():
        raise SystemExit(f"refusing to overwrite frozen sample: {OUT}")
    expected = json.loads(HANDOFF.read_text())
    db = duckdb.connect(str(SOURCE), read_only=True)
    db.execute("""CREATE TEMP TABLE selected_movie AS
        SELECT row_number() OVER (ORDER BY sha256(m.tconst || '|target|20261015'), m.tconst) AS sample_order,
               m.tconst, m.primaryTitle, m.originalTitle
        FROM MOVIE m JOIN MOVIE_COUNTS c USING (tconst)
        WHERE c.expectedRows > 0
        QUALIFY row_number() OVER (ORDER BY sha256(m.tconst || '|target|20261015'), m.tconst) <= 10000""")
    db.execute("""CREATE TEMP TABLE selected_anchor AS
        SELECT row_number() OVER (ORDER BY sha256(a.objectId || '|anchor|20261015'), a.objectId) AS sample_order,
               a.objectId, a.tconst, a.aliasTitle, a.actorId, a.directorId,
               a.actorName, a.directorName
        FROM MOVIECAST_OBJECTS a JOIN selected_movie m USING (tconst)
        QUALIFY row_number() OVER (ORDER BY sha256(a.objectId || '|anchor|20261015'), a.objectId) <= 100000""")
    movie_ids = [r[0] for r in db.execute("SELECT tconst FROM selected_movie ORDER BY sample_order").fetchall()]
    anchor_ids = [r[0] for r in db.execute("SELECT objectId FROM selected_anchor ORDER BY sample_order").fetchall()]
    target_hash, anchor_hash = sequence_digest(movie_ids), sequence_digest(anchor_ids)
    assert len(movie_ids) == 10000 and len(set(movie_ids)) == 10000
    assert len(anchor_ids) == 100000 and len(set(anchor_ids)) == 100000
    assert target_hash == expected["configurations"][0]["target_id_digest"]
    assert anchor_hash == expected["anchor"]["id_digest"]
    assert db.execute("SELECT count(*) FROM selected_anchor a ANTI JOIN selected_movie m USING(tconst)").fetchone()[0] == 0
    distinct_joins = db.execute("SELECT count(DISTINCT tconst) FROM selected_anchor").fetchone()[0]
    assert distinct_joins == 8895
    # Every source tuple is retained. Duplicate titles/movie joins remain separate objects.
    db.execute("""CREATE TEMP TABLE selected_source AS
        SELECT a.sample_order, s.objectId, s.tconst, s.actorOrdering,
               s.directorId, s.aliasOrdering
        FROM selected_anchor a JOIN MOVIECAST_SOURCE s USING (objectId)
        ORDER BY a.sample_order""")
    assert db.execute("SELECT count(*) FROM selected_source").fetchone()[0] == 100000
    assert db.execute("SELECT count(DISTINCT objectId) FROM selected_source").fetchone()[0] == 100000
    assert db.execute("SELECT count(*) FROM selected_source s JOIN selected_anchor a USING(sample_order) WHERE s.tconst<>a.tconst OR s.directorId<>a.directorId").fetchone()[0] == 0
    # The numeric suffix is the shared, reversible uint64 movie join and target object ID.
    assert all(t.startswith("tt") and t[2:].isdigit() and int(t[2:]) > 0 and int(t[2:]) < 2**64 for t in movie_ids)
    assert len({int(t[2:]) for t in movie_ids}) == 10000
    OUT.mkdir()
    for name, table in [("MOVIE", "selected_movie"), ("MOVIECAST", "selected_anchor"), ("MOVIECAST_SOURCE", "selected_source")]:
        path = OUT / f"{name}.parquet"
        db.execute(f"COPY (SELECT * FROM {table} ORDER BY sample_order) TO '{path}' (FORMAT PARQUET, COMPRESSION ZSTD)")
    mapping = OUT / "identity_map.jsonl"
    with mapping.open("w") as f:
        for r in db.execute("""SELECT a.sample_order,a.objectId,a.tconst,a.aliasTitle,
                s.actorOrdering,s.directorId,s.aliasOrdering
                FROM selected_anchor a JOIN selected_source s USING(sample_order)
                ORDER BY a.sample_order""").fetchall():
            f.write(json.dumps({"anchor_id": r[0], "objectId": r[1], "tconst": r[2],
                                "join_id": int(r[2][2:]), "aliasTitle": r[3],
                                "actorOrdering": r[4], "directorId": r[5],
                                "aliasOrdering": r[6]}, ensure_ascii=False) + "\n")
    target_mapping = OUT / "target_map.jsonl"
    with target_mapping.open("w") as f:
        for r in db.execute("SELECT sample_order,tconst,primaryTitle,originalTitle FROM selected_movie ORDER BY sample_order").fetchall():
            f.write(json.dumps({"sample_order": r[0], "target_id": int(r[1][2:]),
                                "join_id": int(r[1][2:]), "tconst": r[1],
                                "primaryTitle": r[2], "originalTitle": r[3]}, ensure_ascii=False) + "\n")
    rows = db.execute("""SELECT a.tconst,a.aliasTitle,a.sample_order,a.objectId,
        s.actorOrdering,s.directorId,s.aliasOrdering
        FROM selected_anchor a JOIN selected_source s USING(sample_order)
        ORDER BY a.tconst,a.aliasTitle,a.sample_order""").fetchall()
    repeated = OUT / "repeated_sources.jsonl"
    duplicate_groups = duplicate_objects = 0
    with repeated.open("w") as f:
        for (tconst, title), group in itertools.groupby(rows, key=lambda r: r[:2]):
            members = list(group)
            if len(members) < 2:
                continue
            duplicate_groups += 1
            duplicate_objects += len(members)
            f.write(json.dumps({"tconst": tconst, "aliasTitle": title, "count": len(members),
                                "sources": [{"sample_order": r[2], "objectId": r[3], "actorOrdering": r[4],
                                             "directorId": r[5], "aliasOrdering": r[6]} for r in members]}, ensure_ascii=False) + "\n")
    manifest = {
        "version": "IMDB-100K-10K-20261015-v1", "seed": SEED,
        "status": "FROZEN_FROM_READ_ONLY_MOTHER_DATABASE",
        "mother_database": str(SOURCE.relative_to(ROOT)), "mother_database_sha256": digest(SOURCE),
        "source_manifest_sha256": digest(ROOT / "imdb_final_dataset/provenance/source_manifest.json"),
        "sampling_rule": {k: v for k, v in expected["sampling_rule"].items() if k != "freeze"},
        "order": "sample_order is 1-based SHA256 rank; no title normalization or source deduplication",
        "anchor_count": len(anchor_ids), "target_count": len(movie_ids),
        "anchor_connected_movies": distinct_joins,
        "target_without_anchor": len(movie_ids) - distinct_joins,
        "anchor_object_id_sequence_sha256": anchor_hash,
        "target_tconst_sequence_sha256": target_hash,
        "repeated_title_groups": duplicate_groups,
        "repeated_source_objects": duplicate_objects,
        "files": {p.name: {"bytes": p.stat().st_size, "sha256": digest(p)} for p in sorted(OUT.iterdir()) if p.is_file()},
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({k: manifest[k] for k in ("anchor_count", "target_count", "anchor_connected_movies", "anchor_object_id_sequence_sha256", "target_tconst_sequence_sha256", "repeated_source_objects")}, indent=2))


if __name__ == "__main__":
    main()
