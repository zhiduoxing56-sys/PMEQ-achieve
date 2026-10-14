#!/usr/bin/env python3
"""Small temporary checks, not a paper dataset size or query workload."""
import json,pathlib,subprocess,sys,tempfile
from common import BASE,connection,lit,save,sha

def main():
    with tempfile.TemporaryDirectory(prefix='imdb_final_sampler_check_') as td:
        temp=pathlib.Path(td);records=[]
        configurations=[('a',[]),('b',[]),('c',['--join-attributes','tconst,actorId','--moviecast-search-count','1','--movie-search-count','1','--person-search-count','1']),
                        ('d',['--join-count','1','--moviecast-search-count','2','--movie-search-count','2','--person-search-count','0'])]
        for name,extra in configurations:
            args=[sys.executable,str(BASE/'scripts/sample.py'),'--moviecast-size','23','--movie-size','50','--person-size','100','--seed','20261014','--output',str(temp/name)]+extra
            subprocess.run(args,check=True)
            m=json.loads((temp/name/'sampling_manifest.json').read_text());c=connection(':memory:')
            actual={t:c.execute(f'SELECT count(*) FROM read_parquet({lit(temp/name/(t+".parquet"))})').fetchone()[0] for t in ['MOVIECAST','MOVIE','PERSON']}
            assert actual=={'MOVIECAST':23,'MOVIE':50,'PERSON':100}
            assert c.execute(f'SELECT count(DISTINCT objectId) FROM read_parquet({lit(temp/name/"MOVIECAST_SOURCE.parquet")})').fetchone()[0]==23
            c.close();records.append(dict(configuration=name,counts=actual,business_attributes=m['business_attributes'],foreign_keys=m['foreign_keys'],files=m['files']))
        first=json.loads((temp/'a/sampling_manifest.json').read_text())['files']
        second=json.loads((temp/'b/sampling_manifest.json').read_text())['files']
        assert first==second,'Same-seed Parquet byte hashes changed'
        save('checks/sampling_verification.json',dict(all_passed=True,same_seed_identical_file_hashes=True,
            independent_sizes_verified=True,source_ids_retained=True,configurations=records,
            scope='23-object temporary script checks only; no formal sample or protocol workload saved',temporary_files_removed=True))
if __name__=='__main__':main()
