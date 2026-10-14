#!/usr/bin/env python3
"""Validate/freeze the existing official snapshots, then clean explicitly named old IMDb workspaces."""
import concurrent.futures, datetime, gzip, hashlib, json, os, pathlib, shutil, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / 'imdb_final_dataset'
OLD = [ROOT / x for x in (
    'imdb_feasibility_20261014', 'imdb_actor_writer_validation_20261014',
    'imdb_experiment_initial_100k_20261014', 'imdb_experiment_17500_movies_20261014',
    'imdb_experiment_full_20261014', 'imdb_experiment_full_csv_20261014',
    'imdb_freeze_audit_20261014')]

def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(8<<20), b''): h.update(b)
    return h.hexdigest()

def save(name, value):
    p = OUT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')

def check(old):
    src = pathlib.Path(old['path'])
    assert src.is_file()
    digest = sha(src)
    assert digest == old['sha256'], (src, 'historical hash mismatch')
    assert src.stat().st_size == old['bytes']
    size = 0
    with gzip.open(src, 'rb') as f:
        header = f.readline().decode('utf-8').rstrip('\r\n')
        size += len((header+'\n').encode())
        for b in iter(lambda: f.read(8<<20), b''): size += len(b)
    assert header == old['header']
    dest = OUT / 'raw' / src.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists(): shutil.copy2(src, dest)
    assert sha(dest) == digest
    meta = dict(old)
    meta.update(path=str(dest.relative_to(OUT)), original_local_path=str(src),
                sha256=digest, gzip_crc_ok=True, decompressed_bytes=size,
                reused=True, downloaded_this_run=False,
                acquisition_date_utc=datetime.datetime.fromtimestamp(src.stat().st_mtime, datetime.timezone.utc).isoformat(),
                verified_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    print('VERIFIED', src.name, meta['bytes'], digest, flush=True)
    return meta

def protected():
    paths = [ROOT/p for p in ['cmd','internal','tools','tests','docs','verification','data','third_party']]
    paths += list(ROOT.glob('*.md')) + [ROOT/'go.mod', ROOT/'go.sum']
    result = {}
    for p in paths:
        for f in ([p] if p.is_file() else p.rglob('*')):
            if f.is_file() and not f.is_symlink(): result[str(f.relative_to(ROOT))] = sha(f)
    return result

def main():
    assert all(p.parent == ROOT and p.name.startswith('imdb_') for p in OLD)
    for d in ['raw','data','provenance','checks','reports','logs','scripts']:
        (OUT/d).mkdir(parents=True,exist_ok=True)
    records = json.loads((ROOT/'imdb_feasibility_20261014/logs/data_manifest.json').read_text())['files']
    records += [json.loads((ROOT/'imdb_actor_writer_validation_20261014/crew_manifest.json').read_text())]
    # Preserve HTTP acquisition evidence, not just a later HEAD response.
    for old in records:
        src = pathlib.Path(old['path'])
        hp = src.parent.parent / 'logs' / (src.name.removesuffix('.tsv.gz')+'.headers')
        if hp.exists(): shutil.copy2(hp, OUT/'provenance'/hp.name)
    save('provenance/historical_acquisition_receipts.json', records)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        frozen = list(ex.map(check, records))
    save('provenance/source_manifest.json', dict(frozen_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
         official_documentation='https://data.imdb.com/non-commercial-datasets/',
         policy='Frozen mixed official update batches. Preserve each x-amz-meta-run-date and Last-Modified separately.', files=frozen))
    # Retain the installed DuckDB dependency in a fresh self-contained runtime.
    subprocess.run(['/usr/bin/python3','-m','venv',str(OUT/'.venv')],check=True)
    site = next((ROOT/'imdb_feasibility_20261014/.venv/lib').glob('python*/site-packages'))
    target = next((OUT/'.venv/lib').glob('python*/site-packages'))
    for p in site.iterdir():
        if p.name.lower().startswith(('duckdb','_duckdb','adbc_driver_duckdb')):
            if p.is_dir(): shutil.copytree(p,target/p.name,dirs_exist_ok=True)
            else: shutil.copy2(p,target/p.name)
    subprocess.run([str(OUT/'.venv/bin/python'),'-c','import duckdb; print(duckdb.__version__)'],check=True)
    before = protected()
    save('checks/protected_files_before.json', before)
    inventory=[]
    for folder in OLD:
        for f in folder.rglob('*'):
            if f.is_file() or f.is_symlink():
                rel=str(f.relative_to(ROOT))
                israw=f.parent.name=='raw' and f.name.endswith('.tsv.gz')
                inventory.append(dict(path=rel,bytes=f.lstat().st_size,
                    classification='official_raw_migrated' if israw else ('obsolete_dependency_runtime' if '.venv' in f.parts else 'obsolete_imdb_derived_or_associated_script_report_test'),
                    action='remove_old_raw_location_after_verified_copy' if israw else 'delete',
                    deletion_status='pending'))
    save('reports/cleanup_inventory.json',inventory)
    # No broad recursive delete: unlink the exact inventoried paths, then remove empty dirs.
    for r in inventory:
        f=ROOT/r['path']
        assert any(f.is_relative_to(p) for p in OLD)
        if r['classification']=='official_raw_migrated':
            assert sha(f)==sha(OUT/'raw'/f.name)
        f.unlink()
        r['deletion_status']='deleted'
    for folder in OLD:
        for p in sorted((p for p in folder.rglob('*') if p.is_dir() and not p.is_symlink()), key=lambda p:len(p.parts), reverse=True): p.rmdir()
        folder.rmdir()
    save('reports/cleanup_inventory.json',inventory)
    after=protected()
    assert before==after,'Protected project content changed'
    save('checks/protected_files_after.json',after)
    save('checks/cleanup_verification.json',dict(protected_files=len(before),all_hashes_unchanged=before==after,
        preserved_raw_files=5,deleted_entries=len(inventory),deleted_old_locations_bytes=sum(r['bytes'] for r in inventory),
        deleted_workspace_names=[p.name for p in OLD],other_projects_untouched=True,
        retained_unknown='All directories outside the seven confirmed obsolete IMDb workspaces.'))
    print('CLEANUP_COMPLETE',len(inventory),flush=True)

if __name__=='__main__': main()
