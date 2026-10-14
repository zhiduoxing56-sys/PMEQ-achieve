#!/usr/bin/env python3
"""Exact-size deterministic object sampling, independent entity sizes, and chosen attribute projections."""
import argparse,json,pathlib,time
from common import BASE,BUSINESS,connection,lit,now,sha

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--moviecast-size',type=int,required=True)
    p.add_argument('--movie-size',type=int,help='Exact MOVIE size; default is required movie closure')
    p.add_argument('--person-size',type=int,help='Exact PERSON size; default is required person closure')
    p.add_argument('--seed',type=int,required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--join-count',type=int,choices=range(4),default=3,help='Select the first k of tconst,actorId,directorId')
    p.add_argument('--join-attributes',help='Override join-count, e.g. tconst,directorId')
    p.add_argument('--moviecast-search-count',type=int,choices=range(4),default=3)
    p.add_argument('--movie-search-count',type=int,choices=range(3),default=2)
    p.add_argument('--person-search-count',type=int,choices=range(3),default=2)
    a=p.parse_args();joins=['tconst','actorId','directorId'][:a.join_count]
    if a.join_attributes is not None:
        joins=[x for x in a.join_attributes.split(',') if x]
        if len(set(joins))!=len(joins) or not set(joins)<=set(['tconst','actorId','directorId']):p.error('Invalid join-attributes')
    if any(n is not None and n<0 for n in [a.moviecast_size,a.movie_size,a.person_size]):p.error('Sizes must be nonnegative')
    out=a.output.resolve()
    if out==BASE or out.is_relative_to(BASE/'data') or out.is_relative_to(BASE/'raw') or out.is_relative_to(BASE/'provenance'):
        p.error('Output must not overwrite the full frozen dataset')
    if out.exists() and any(out.iterdir()):p.error('Output directory must be empty')
    out.mkdir(parents=True,exist_ok=True)
    c=connection(out/'sample.duckdb');c.execute('SET temp_directory='+lit(out/'tmp'))
    for table in ['MOVIE','PERSON']:
        c.execute(f'CREATE VIEW FULL_{table} AS SELECT * FROM read_parquet({lit(BASE/f"data/{table}.parquet")})')
    c.execute(f'CREATE VIEW FULL_MC AS SELECT * FROM read_parquet({lit(BASE/"data/MOVIECAST/*.parquet")})')
    total=c.execute('SELECT count(*) FROM FULL_MC').fetchone()[0]
    if a.moviecast_size>total:p.error(f'MOVIECAST size exceeds full table ({total})')
    # SHA-256 order + source ID breaks every tie deterministically; independent of physical row order/threads.
    c.execute(f'CREATE TABLE SELECTED_MC AS SELECT * FROM FULL_MC ORDER BY sha256(objectId||{lit("|"+str(a.seed))}),objectId LIMIT {a.moviecast_size}')
    c.execute('CREATE TABLE REQUIRED_MOVIE AS SELECT DISTINCT tconst FROM SELECTED_MC '+('' if 'tconst' in joins else 'WHERE false'))
    person_sql=[]
    if 'actorId' in joins:person_sql.append('SELECT DISTINCT actorId nconst FROM SELECTED_MC')
    if 'directorId' in joins:person_sql.append('SELECT DISTINCT directorId nconst FROM SELECTED_MC')
    c.execute('CREATE TABLE REQUIRED_PERSON AS '+(' UNION '.join(person_sql) if person_sql else 'SELECT nconst FROM FULL_PERSON WHERE false'))
    wanted={};required={}
    for table,key,size in [('MOVIE','tconst',a.movie_size),('PERSON','nconst',a.person_size)]:
        n=c.execute(f'SELECT count(*) FROM REQUIRED_{table}').fetchone()[0]
        m=c.execute(f'SELECT count(*) FROM FULL_{table}').fetchone()[0]
        wanted[table]=n if size is None else size;required[table]=n
        if wanted[table]<n or wanted[table]>m:
            p.error(f'{table} requested {wanted[table]}; maintaining all specified joins needs at least {n}, full source has {m}. Choose a feasible size or fewer join attributes.')
        c.execute(f"""CREATE TABLE SELECTED_{table} AS
           SELECT f.* FROM FULL_{table} f JOIN REQUIRED_{table} r USING({key})
           UNION ALL SELECT * FROM (SELECT f.* FROM FULL_{table} f ANTI JOIN REQUIRED_{table} r USING({key})
             ORDER BY sha256(f.{key}||{lit('|'+str(a.seed))}),f.{key} LIMIT {wanted[table]-n})""")
    chosen={'MOVIECAST':joins+BUSINESS['MOVIECAST'][3:3+a.moviecast_search_count],
      'MOVIE':(['tconst'] if 'tconst' in joins else [])+BUSINESS['MOVIE'][1:1+a.movie_search_count],
      'PERSON':(['nconst'] if set(joins)&{'actorId','directorId'} else [])+BUSINESS['PERSON'][1:1+a.person_search_count]}
    for table,key,src in [('MOVIECAST','objectId','SELECTED_MC'),('MOVIE','tconst','SELECTED_MOVIE'),('PERSON','nconst','SELECTED_PERSON')]:
        cols=chosen[table]+([key] if table=='MOVIECAST' else [f'{key} AS sourceId'])
        c.execute(f'COPY (SELECT {",".join(cols)} FROM {src} ORDER BY {key}) TO {lit(out/f"{table}.parquet")} (FORMAT PARQUET,COMPRESSION ZSTD)')
    c.execute(f"COPY (SELECT s.* FROM read_parquet({lit(BASE/'provenance/MOVIECAST_SOURCE/*.parquet')}) s JOIN SELECTED_MC m USING(objectId) ORDER BY s.objectId) TO {lit(out/'MOVIECAST_SOURCE.parquet')} (FORMAT PARQUET,COMPRESSION ZSTD)")
    fk={}
    for attr in joins:
        target,key=('SELECTED_MOVIE','tconst') if attr=='tconst' else ('SELECTED_PERSON','nconst')
        dangling=c.execute(f'SELECT count(*) FROM SELECTED_MC m ANTI JOIN {target} p ON m.{attr}=p.{key}').fetchone()[0]
        assert dangling==0;fk[attr]={'successful':a.moviecast_size,'dangling':dangling}
    counts={'MOVIECAST':a.moviecast_size,**wanted}
    for table,src in [('MOVIECAST','SELECTED_MC'),('MOVIE','SELECTED_MOVIE'),('PERSON','SELECTED_PERSON')]:
        assert c.execute('SELECT count(*) FROM '+src).fetchone()[0]==counts[table]
    c.close()
    # Keep only formal sample files + manifest; the transient selection DB is not an extra table version.
    (out/'sample.duckdb').unlink()
    if (out/'tmp').exists():
        for f in (out/'tmp').iterdir():
            if f.is_file():f.unlink()
        (out/'tmp').rmdir()
    files={f.name:{'bytes':f.stat().st_size,'sha256':sha(f)} for f in out.glob('*.parquet')}
    manifest=dict(created_at_utc=now(),seed=a.seed,counts=counts,required_entity_closure=required,
      join_attributes=joins,business_attributes=chosen,metadata={'MOVIECAST':['objectId'],'MOVIE':['sourceId'],'PERSON':['sourceId']},
      algorithm="smallest SHA256(UTF8(objectId+'|'+decimal_seed)), ties by objectId; entity extras use source key identically",
      foreign_keys=fk,files=files,source_snapshot=json.loads((BASE/'provenance/source_manifest.json').read_text()))
    (out/'sampling_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(counts=counts,joins=joins,output=str(out)),ensure_ascii=False))

if __name__=='__main__':main()
