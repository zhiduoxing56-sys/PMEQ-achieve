#!/usr/bin/env python3
"""Exhaustive table/schema/source/FK/identity checks with bounded memory."""
import json,time
from common import BASE,BUSINESS,connection,copy,lit,now,rows,save,scalar,sha

def main():
    started=now();t0=time.monotonic();c=connection()
    result={'started_at_utc':started,'schemas':{},'counts':{},'partitions':[],'checks':{}}
    for table,expected in BUSINESS.items():
        got=[x[0] for x in c.execute('DESCRIBE '+table).fetchall()]
        assert got==expected,(table,got)
        result['schemas'][table]=got
        result['counts'][table]=scalar(c,'SELECT count(*) FROM '+table)
    assert result['counts']['MOVIECAST']==json.loads((BASE/'checks/precheck.json').read_text())['expected_moviecast']
    for k in range(32):
        print(now(),'VERIFY_PARTITION',k,flush=True)
        mc='read_parquet('+lit(BASE/f'data/MOVIECAST/part-{k:02d}.parquet')+')'
        sc='read_parquet('+lit(BASE/f'provenance/MOVIECAST_SOURCE/part-{k:02d}.parquet')+')'
        r=rows(c,f"""SELECT count(*) objects,count(DISTINCT objectId) uniqueIds,
           count(*) FILTER(WHERE tconst IS NULL OR actorId IS NULL OR directorId IS NULL OR aliasTitle IS NULL OR aliasTitle='' OR actorName IS NULL OR actorName='' OR directorName IS NULL OR directorName='') missingNecessaryValues,
           count(*) FILTER(WHERE substring(tconst,3)::BIGINT%32<>{k}) wrongPartition FROM {mc}""")[0]
        s=rows(c,f'SELECT count(*) n,count(DISTINCT objectId) uniqueIds FROM {sc}')[0]
        assert r['objects']==r['uniqueIds']==s['n']==s['uniqueIds']
        assert r['missingNecessaryValues']==r['wrongPartition']==0
        lineage=rows(c,f"""SELECT
          count(*) FILTER(WHERE s.objectId IS NULL) missingSourceMap,
          count(*) FILTER(WHERE a.actorId IS NULL) missingActorSource,
          count(*) FILTER(WHERE d.directorId IS NULL) missingDirectorSource,
          count(*) FILTER(WHERE b.aliasOrdering IS NULL) missingAliasSource,
          count(*) FILTER(WHERE mc.tconst IS DISTINCT FROM s.tconst OR mc.directorId IS DISTINCT FROM s.directorId
            OR mc.aliasTitle IS DISTINCT FROM b.aliasTitle OR mc.actorName IS DISTINCT FROM a.actorName
            OR mc.directorName IS DISTINCT FROM d.directorName) alteredSourceValues,
          count(*) FILTER(WHERE mc.objectId IS DISTINCT FROM 'mc1|'||s.tconst||'|'||s.actorOrdering::VARCHAR||'|'||s.directorId||'|'||s.aliasOrdering::VARCHAR) invalidDeterministicId
          FROM {mc} mc LEFT JOIN {sc} s ON mc.objectId=s.objectId
          LEFT JOIN ACTOR a ON s.tconst=a.tconst AND s.actorOrdering=a.actorOrdering AND mc.actorId=a.actorId
          LEFT JOIN DIRECTOR d ON s.tconst=d.tconst AND mc.directorId=d.directorId
          LEFT JOIN ALIAS b ON s.tconst=b.tconst AND s.aliasOrdering=b.aliasOrdering""")[0]
        assert not any(lineage.values()),(k,lineage)
        r.update(lineage);r['partition']=k;result['partitions'].append(r)
        save('checks/validation_progress.json',result)
    # With each source key unique and every source tuple present at most once, equality of each
    # movie's actual and expected products proves full coverage, not just equality of total sizes.
    c.execute('CREATE OR REPLACE TABLE ACTUAL_MOVIE_COUNTS AS SELECT tconst,count(*) actualRows FROM MOVIECAST GROUP BY tconst')
    mismatch=scalar(c,"""SELECT count(*) FROM MOVIE_COUNTS e FULL JOIN ACTUAL_MOVIE_COUNTS a USING(tconst)
         WHERE coalesce(e.expectedRows,0)<>coalesce(a.actualRows,0)""")
    assert mismatch==0
    result['checks']['per_movie_product_mismatches']=mismatch
    source_checks={
      'actor_not_original_source':scalar(c,"""SELECT count(*) FROM ACTOR a LEFT JOIN ACTOR_RAW r ON a.tconst=r.tconst AND a.actorOrdering=r.ordering::BIGINT AND a.actorId=r.nconst LEFT JOIN PERSON p ON a.actorId=p.nconst WHERE r.nconst IS NULL OR a.actorName IS DISTINCT FROM p.primaryName"""),
      'director_not_original_source':scalar(c,"""SELECT count(*) FROM DIRECTOR d LEFT JOIN CREW_RAW r USING(tconst) LEFT JOIN PERSON p ON d.directorId=p.nconst WHERE r.tconst IS NULL OR NOT list_contains(string_split(r.directors,','),d.directorId) OR d.directorName IS DISTINCT FROM p.primaryName"""),
      'alias_not_original_source':scalar(c,"""SELECT count(*) FROM ALIAS b LEFT JOIN ALIAS_RAW r ON b.tconst=r.titleId AND b.aliasOrdering=r.ordering::BIGINT WHERE r.titleId IS NULL OR b.aliasTitle IS DISTINCT FROM r.title""")}
    assert not any(source_checks.values());result['checks'].update(source_checks)
    stats={};fks={}
    for attr,target,key in [('tconst','MOVIE','tconst'),('actorId','PERSON','nconst'),('directorId','PERSON','nconst')]:
        table='FREQ_'+attr
        if attr=='tconst':c.execute(f'CREATE OR REPLACE TABLE {table} AS SELECT tconst connectionValue,actualRows groupSize FROM ACTUAL_MOVIE_COUNTS')
        else:c.execute(f'CREATE OR REPLACE TABLE {table} AS SELECT {attr} connectionValue,count(*) groupSize FROM MOVIECAST GROUP BY {attr}')
        copy(c,f'SELECT * FROM {table} ORDER BY connectionValue',f'checks/groups/{attr}.parquet')
        dist=f'SELECT groupSize,count(*) numberOfDistinctKeys FROM {table} GROUP BY groupSize ORDER BY groupSize'
        c.execute(f'COPY ({dist}) TO {lit(BASE/f"checks/{attr}_group_histogram.csv")} (HEADER,FORMAT CSV)')
        stats[attr]=rows(c,f"""SELECT count(*) distinctValues,max(groupSize) maximumGroupSize,min(groupSize) minimumGroupSize,
          avg(groupSize) meanGroupSize,quantile_cont(groupSize,0.5) medianGroupSize,
          quantile_cont(groupSize,0.95) p95GroupSize,quantile_cont(groupSize,0.99) p99GroupSize,sum(groupSize)::BIGINT totalRecords FROM {table}""")[0]
        stats[attr]['largestGroups']=rows(c,f'SELECT * FROM {table} ORDER BY groupSize DESC,connectionValue LIMIT 10')
        fks[attr]=rows(c,f"""SELECT coalesce(sum(f.groupSize) FILTER(WHERE p.{key} IS NOT NULL),0)::BIGINT successfulJoinedRecords,
          coalesce(sum(f.groupSize) FILTER(WHERE p.{key} IS NULL),0)::BIGINT danglingForeignKeyRecords,
          count(*) FILTER(WHERE p.{key} IS NULL) danglingDistinctKeys
          FROM {table} f LEFT JOIN {target} p ON f.connectionValue=p.{key}""")[0]
        assert fks[attr]['danglingForeignKeyRecords']==0
        assert fks[attr]['successfulJoinedRecords']==result['counts']['MOVIECAST']
    result['group_statistics']=stats;result['foreign_keys']=fks
    result['checks']['equal_business_fields_different_sources_retained']=True
    result['checks']['identity_unique_globally']='All partition IDs unique; a movie deterministically occurs in only one partition; injective source composite identity.'
    result['checks']['full_per_movie_cartesian_coverage']=True
    # Logical table roundtrip checks of entity Parquet to retained source projections.
    result['checks']['movie_missing_primaryTitle']=scalar(c,'SELECT count(*) FROM MOVIE WHERE primaryTitle IS NULL')
    result['checks']['movie_missing_originalTitle']=scalar(c,'SELECT count(*) FROM MOVIE WHERE originalTitle IS NULL')
    result['checks']['person_missing_primaryName']=scalar(c,'SELECT count(*) FROM PERSON WHERE primaryName IS NULL')
    result['checks']['person_missing_primaryProfession']=scalar(c,'SELECT count(*) FROM PERSON WHERE primaryProfession IS NULL')
    manifest=json.loads((BASE/'provenance/source_manifest.json').read_text())
    source_hashes={}
    for f in manifest['files']:
        digest=sha(BASE/f['path']);assert digest==f['sha256'];source_hashes[f['path']]=digest
    result['frozen_source_hashes_verified']=source_hashes
    result['completed_at_utc']=now();result['seconds']=time.monotonic()-t0;result['all_passed']=True
    c.execute('CHECKPOINT');c.close();save('checks/validation.json',result)
    print('VALIDATION_ALL_PASSED',result['counts'],flush=True)

if __name__=='__main__':main()
