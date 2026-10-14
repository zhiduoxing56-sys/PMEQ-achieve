#!/usr/bin/env python3
"""Delete only five reviewed obsolete IMDb temporary dataset directories."""
import json,pathlib
from common import BASE,save
NAMES=['imdb_full_subset_10k_b_20261014','imdb_initial_rebuild_20261014_1336',
       'imdb_full_subset_10k_a_20261014','imdb_full_subset_200movies_titleclosure_20261014',
       'imdb_17500_movies_rebuild_20261014']
def main():
    records=[]
    for name in NAMES:
        p=pathlib.Path('/tmp')/name
        if not p.exists(): continue
        assert not p.is_symlink()
        for f in p.rglob('*'):
            if f.is_file():
                assert not f.name.endswith('.tsv.gz') and not f.is_symlink(),f
                records.append(dict(path=str(f),bytes=f.stat().st_size,classification='obsolete_imdb_temporary_rebuild_or_subset',deletion_status='pending'))
    save('reports/cleanup_temp_inventory.json',records)
    for r in records:
        pathlib.Path(r['path']).unlink();r['deletion_status']='deleted'
    for name in NAMES:
        p=pathlib.Path('/tmp')/name
        if p.exists():
            for d in sorted((d for d in p.rglob('*') if d.is_dir()),key=lambda x:len(x.parts),reverse=True):d.rmdir()
            p.rmdir()
    save('reports/cleanup_temp_inventory.json',records)
    print('TEMP_CLEANUP_COMPLETE',len(records),sum(r['bytes'] for r in records))
if __name__=='__main__':main()
