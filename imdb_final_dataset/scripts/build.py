#!/usr/bin/env python3
"""No sampling or per-movie caps. Filter raw inputs to movie scope, count, then expand all valid combinations."""
import json, os, shutil, time
from common import BASE, BUSINESS, connection, copy, lit, now, read_raw, rows, save, scalar

PARTITIONS=32
JOIN='FROM ACTOR a JOIN DIRECTOR d USING(tconst) JOIN ALIAS b USING(tconst)'
PROJECTION="""a.tconst,a.actorId,d.directorId,b.aliasTitle,a.actorName,d.directorName,
 'mc1|'||a.tconst||'|'||a.actorOrdering::VARCHAR||'|'||d.directorId||'|'||b.aliasOrdering::VARCHAR AS objectId"""

def main():
    t0=time.monotonic();start=now()
    if (BASE/'checks/build_complete.json').exists(): raise RuntimeError('Frozen completed build exists; do not overwrite')
    c=connection()
    def step(label,sql):
        print(now(),label,flush=True);c.execute(sql);c.execute('CHECKPOINT')
    step('MOVIE: all titleType=movie',f"CREATE TABLE MOVIE AS SELECT tconst,primaryTitle,originalTitle FROM {read_raw('title.basics')} WHERE titleType='movie'")
    step('PERSON: all official name records, original profession string',f"CREATE TABLE PERSON AS SELECT nconst,primaryName,primaryProfession FROM {read_raw('name.basics')}")
    step('Movie principals actor/actress source',f"CREATE TABLE ACTOR_RAW AS SELECT p.* FROM {read_raw('title.principals')} p JOIN MOVIE m USING(tconst) WHERE category IN ('actor','actress')")
    step('Movie aliases: all original records',f"CREATE TABLE ALIAS_RAW AS SELECT b.* FROM {read_raw('title.akas')} b JOIN MOVIE m ON b.titleId=m.tconst")
    step('Movie crew: official directors field only',f"CREATE TABLE CREW_RAW AS SELECT r.* FROM {read_raw('title.crew')} r JOIN MOVIE m USING(tconst)")
    # Natural source identifiers must be unique; fail instead of accidentally merging source records.
    source_checks={
      'movie_duplicate_keys':scalar(c,'SELECT count(*)-count(DISTINCT tconst) FROM MOVIE'),
      'person_duplicate_keys':scalar(c,'SELECT count(*)-count(DISTINCT nconst) FROM PERSON'),
      'actor_duplicate_source_keys':scalar(c,'SELECT count(*)-count(DISTINCT (tconst,ordering)) FROM ACTOR_RAW'),
      'alias_duplicate_source_keys':scalar(c,'SELECT count(*)-count(DISTINCT (titleId,ordering)) FROM ALIAS_RAW'),
      'crew_duplicate_source_keys':scalar(c,'SELECT count(*)-count(DISTINCT tconst) FROM CREW_RAW'),
      'invalid_movie_ids':scalar(c,"SELECT count(*) FROM MOVIE WHERE tconst IS NULL OR NOT regexp_full_match(tconst,'tt[0-9]+')"),
      'invalid_person_ids':scalar(c,"SELECT count(*) FROM PERSON WHERE nconst IS NULL OR NOT regexp_full_match(nconst,'nm[0-9]+')"),
      'invalid_actor_ordering':scalar(c,'SELECT count(*) FROM ACTOR_RAW WHERE try_cast(ordering AS BIGINT) IS NULL OR try_cast(ordering AS BIGINT)<1'),
      'invalid_alias_ordering':scalar(c,'SELECT count(*) FROM ALIAS_RAW WHERE try_cast(ordering AS BIGINT) IS NULL OR try_cast(ordering AS BIGINT)<1')}
    save('checks/source_key_checks.json',source_checks)
    assert not any(source_checks.values()),source_checks
    step('Valid actors: real person + nonempty primaryName',"""CREATE TABLE ACTOR AS
      SELECT r.tconst,r.ordering::BIGINT actorOrdering,r.nconst actorId,p.primaryName actorName
      FROM ACTOR_RAW r JOIN PERSON p ON r.nconst=p.nconst
      WHERE p.primaryName IS NOT NULL AND p.primaryName<>''""")
    step('Split directors, keep every distinct director and every original list position',"""CREATE TABLE DIRECTOR_RAW AS
      SELECT tconst,x.directorId,list(x.directorPosition ORDER BY x.directorPosition) directorPositions
      FROM CREW_RAW, UNNEST(string_split(directors,',')) WITH ORDINALITY x(directorId,directorPosition)
      WHERE directorId IS NOT NULL AND directorId<>'' GROUP BY tconst,directorId""")
    step('Valid directors: real person + nonempty primaryName',"""CREATE TABLE DIRECTOR AS
      SELECT d.tconst,d.directorId,p.primaryName directorName,d.directorPositions
      FROM DIRECTOR_RAW d JOIN PERSON p ON d.directorId=p.nconst
      WHERE p.primaryName IS NOT NULL AND p.primaryName<>''""")
    step('Valid aliases: retain each source ordering even when text repeats',"""CREATE TABLE ALIAS AS
      SELECT titleId tconst,ordering::BIGINT aliasOrdering,title aliasTitle FROM ALIAS_RAW
      WHERE title IS NOT NULL AND title<>''""")
    step('Per-movie exact product ledger',"""CREATE TABLE MOVIE_COUNTS AS
      WITH ac AS (SELECT tconst,count(*) A FROM ACTOR GROUP BY tconst),
           dc AS (SELECT tconst,count(*) D FROM DIRECTOR GROUP BY tconst),
           bc AS (SELECT tconst,count(*) B FROM ALIAS GROUP BY tconst)
      SELECT m.tconst,coalesce(A,0)::BIGINT A,coalesce(D,0)::BIGINT D,coalesce(B,0)::BIGINT B,
             (coalesce(A,0)::HUGEINT*coalesce(D,0)*coalesce(B,0))::BIGINT expectedRows,
             (substring(m.tconst,3)::BIGINT%32)::INTEGER partitionId
      FROM MOVIE m LEFT JOIN ac USING(tconst) LEFT JOIN dc USING(tconst) LEFT JOIN bc USING(tconst)""")
    # The exclusion masks are mutually exclusive. Detailed flags remain in the ledger.
    c.execute("CREATE TABLE EXCLUDED_MOVIES AS SELECT *, concat_ws(';',CASE WHEN A=0 THEN 'no_valid_actor' END,CASE WHEN D=0 THEN 'no_valid_director' END,CASE WHEN B=0 THEN 'no_valid_alias' END) reason FROM MOVIE_COUNTS WHERE expectedRows=0")
    copy(c,'SELECT * FROM MOVIE_COUNTS ORDER BY tconst','checks/per_movie_counts.parquet')
    copy(c,'SELECT * FROM EXCLUDED_MOVIES ORDER BY tconst','checks/excluded_movies.parquet')
    exclusions=rows(c,'SELECT reason,count(*) movies FROM EXCLUDED_MOVIES GROUP BY reason ORDER BY reason')
    invalid=rows(c,"""SELECT 'actor_person_not_found' reason,count(*) records FROM ACTOR_RAW r LEFT JOIN PERSON p ON r.nconst=p.nconst WHERE p.nconst IS NULL
      UNION ALL SELECT 'actor_missing_name',count(*) FROM ACTOR_RAW r JOIN PERSON p ON r.nconst=p.nconst WHERE p.primaryName IS NULL OR p.primaryName=''
      UNION ALL SELECT 'director_person_not_found',count(*) FROM DIRECTOR_RAW r LEFT JOIN PERSON p ON r.directorId=p.nconst WHERE p.nconst IS NULL
      UNION ALL SELECT 'director_missing_name',count(*) FROM DIRECTOR_RAW r JOIN PERSON p ON r.directorId=p.nconst WHERE p.primaryName IS NULL OR p.primaryName=''
      UNION ALL SELECT 'alias_missing_title',count(*) FROM ALIAS_RAW WHERE title IS NULL OR title=''""")
    expected=scalar(c,'SELECT sum(expectedRows) FROM MOVIE_COUNTS')
    totals={t:scalar(c,'SELECT count(*) FROM '+t) for t in ['MOVIE','PERSON','ACTOR_RAW','ALIAS_RAW','CREW_RAW','ACTOR','DIRECTOR_RAW','DIRECTOR','ALIAS']}
    totals['MOVIECAST']=expected
    # Exact UTF-8 text payload upper estimate for uncompressed TSV including source-derived IDs.
    text_estimate=scalar(c,"""WITH ac AS (SELECT tconst,sum(octet_length(encode(actorId))+octet_length(encode(actorName))+length(actorOrdering::VARCHAR)) L FROM ACTOR GROUP BY tconst),
      dc AS (SELECT tconst,sum(octet_length(encode(directorId))*2+octet_length(encode(directorName))) L FROM DIRECTOR GROUP BY tconst),
      bc AS (SELECT tconst,sum(octet_length(encode(aliasTitle))+length(aliasOrdering::VARCHAR)) L FROM ALIAS GROUP BY tconst)
      SELECT sum(n.D::HUGEINT*n.B*ac.L+n.A::HUGEINT*n.B*dc.L+n.A::HUGEINT*n.D*bc.L+n.expectedRows::HUGEINT*(2*length(n.tconst)+15)) FROM MOVIE_COUNTS n JOIN ac USING(tconst) JOIN dc USING(tconst) JOIN bc USING(tconst)""")
    free=shutil.disk_usage(BASE).free
    # Deliberately conservative: Parquet+lineage plus 12GB temporary allowance and source-stage database.
    required=int(text_estimate)*2+12*(1<<30)
    mem={}
    for line in open('/proc/meminfo'):
        if line.startswith(('MemTotal:','MemAvailable:','SwapFree:')): k,v,*_=line.split();mem[k.rstrip(':')]=int(v)*1024
    pre=dict(started_at_utc=start,precheck_at_utc=now(),counts=totals,expected_moviecast=expected,
      uncompressed_tsv_payload_estimate_bytes=int(text_estimate),estimated_parquet_plus_lineage_upper_bytes=int(text_estimate)*2,
      temporary_space_allowance_bytes=12*(1<<30),conservative_additional_space_bytes=required,
      available_disk_bytes=free,resource_gap_bytes=max(0,required-free),memory=mem,duckdb_memory_limit='12GB',
      largest_movie=rows(c,'SELECT * FROM MOVIE_COUNTS ORDER BY expectedRows DESC,tconst LIMIT 1')[0],
      excluded_movies_by_reason=exclusions,invalid_source_associations=invalid,
      director_duplicate_list_entries_normalized=scalar(c,'SELECT coalesce(sum(len(directorPositions)-1),0) FROM DIRECTOR_RAW'),
      partitions=PARTITIONS,rule='all movie scope, all valid actor source rows x distinct valid crew directors x all valid aka source rows; no caps')
    save('checks/precheck.json',pre);print('PRECHECK',json.dumps(pre,ensure_ascii=False),flush=True)
    if free<required: raise RuntimeError(f'Insufficient space: gap {required-free} bytes; full materialization stopped, no sampling fallback')
    for table in ['MOVIE','PERSON']:
        copy(c,'SELECT * FROM '+table+' ORDER BY '+('tconst' if table=='MOVIE' else 'nconst'),f'data/{table}.parquet')
    for name,table in [('actor_source','ACTOR_RAW'),('alias_source','ALIAS_RAW'),('crew_source','CREW_RAW'),('director_source','DIRECTOR_RAW')]:
        copy(c,'SELECT * FROM '+table,f'provenance/{name}.parquet')
    # Materialize each movie partition separately; never hold the global product in Python memory.
    progress=[]
    for k in range(PARTITIONS):
        part_start=time.monotonic();n=scalar(c,f'SELECT sum(expectedRows) FROM MOVIE_COUNTS WHERE partitionId={k}')
        target=f'data/MOVIECAST/part-{k:02d}.parquet'
        query=f"SELECT {PROJECTION} {JOIN} WHERE substring(a.tconst,3)::BIGINT%{PARTITIONS}={k} ORDER BY a.tconst,a.actorOrdering,d.directorId,b.aliasOrdering"
        copy(c,query,target)
        actual=scalar(c,f'SELECT count(*) FROM read_parquet({lit(BASE/target)})')
        assert actual==n,(k,n,actual)
        copy(c,f"SELECT objectId,tconst,split_part(objectId,'|',3)::BIGINT actorOrdering,directorId,split_part(objectId,'|',5)::BIGINT aliasOrdering FROM read_parquet({lit(BASE/target)})",f'provenance/MOVIECAST_SOURCE/part-{k:02d}.parquet')
        progress.append(dict(partition=k,expected=n,actual=actual,bytes=(BASE/target).stat().st_size,seconds=time.monotonic()-part_start))
        save('checks/build_progress.json',dict(completed=progress,expected_total=expected,actual_so_far=sum(x['actual'] for x in progress)))
        print(now(),'PARTITION',k,'ROWS',actual,'SECONDS',round(progress[-1]['seconds'],2),flush=True)
    # Persistent reader database stores normalized raw-source extracts and business-only views.
    c.execute('ALTER TABLE MOVIE RENAME TO MOVIE_STAGE; ALTER TABLE PERSON RENAME TO PERSON_STAGE')
    c.execute(f'CREATE VIEW MOVIE AS SELECT * FROM read_parquet({lit(BASE/"data/MOVIE.parquet")})')
    c.execute(f'CREATE VIEW PERSON AS SELECT * FROM read_parquet({lit(BASE/"data/PERSON.parquet")})')
    c.execute(f'CREATE VIEW MOVIECAST_OBJECTS AS SELECT * FROM read_parquet({lit(BASE/"data/MOVIECAST/*.parquet")})')
    c.execute('CREATE VIEW MOVIECAST AS SELECT '+','.join(BUSINESS['MOVIECAST'])+' FROM MOVIECAST_OBJECTS')
    c.execute(f'CREATE VIEW MOVIECAST_SOURCE AS SELECT * FROM read_parquet({lit(BASE/"provenance/MOVIECAST_SOURCE/*.parquet")})')
    c.execute('DROP TABLE MOVIE_STAGE; DROP TABLE PERSON_STAGE; CHECKPOINT');c.close()
    save('checks/build_complete.json',dict(started_at_utc=start,completed_at_utc=now(),seconds=time.monotonic()-t0,expected=expected,actual=sum(x['actual'] for x in progress),partitions=progress,counts=totals))
    print('FULL_BUILD_COMPLETE',expected,flush=True)

if __name__=='__main__': main()
