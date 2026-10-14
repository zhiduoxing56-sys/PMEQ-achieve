#!/usr/bin/env python3
"""Independent Python gzip+TSV pass: verify raw projections and reconstruct every per-movie product."""
import collections,gzip,hashlib,json,time
from common import BASE,connection,now,save

MOD=(1<<256)-1
class Fingerprint:
    def __init__(self):self.n=0;self.total=0;self.xor=0
    def add(self,fields):
        raw=('\t'.join('\\N' if x is None else str(x) for x in fields)+'\n').encode('utf-8')
        h=int.from_bytes(hashlib.sha256(raw).digest(),'big')
        self.n+=1;self.total=(self.total+h)&MOD;self.xor^=h
    def value(self):return {'rows':self.n,'sum_sha256_mod_2_256':f'{self.total:064x}','xor_sha256':f'{self.xor:064x}'}

def scan(name):
    with gzip.open(BASE/'raw'/f'{name}.tsv.gz','rt',encoding='utf-8',newline='') as f:
        header=f.readline().rstrip('\n').split('\t');n=0
        for line in f:
            n+=1;fields=line.rstrip('\n').split('\t')
            if len(fields)!=len(header):raise ValueError((name,n,'unexpected column count',len(fields)))
            yield fields

def main():
    start=now();t0=time.monotonic();c=connection(read_only=True)
    movie_ids=set();ac=collections.Counter();dc=collections.Counter();bc=collections.Counter()
    wanted={x[0] for x in c.execute('SELECT nconst FROM ACTOR_RAW UNION SELECT directorId FROM DIRECTOR_RAW').fetchall()}
    valid_names=set();fps={};raw_rows={}
    def fp(name):fps[name]=Fingerprint();return fps[name]
    f=fp('MOVIE');n=0
    print(now(),'RAW title.basics',flush=True)
    for x in scan('title.basics'):
        n+=1
        if x[1]=='movie':movie_ids.add(x[0]);f.add([x[0],x[2],x[3]])
    raw_rows['title.basics']=n
    f=fp('PERSON');n=0
    print(now(),'RAW name.basics',flush=True)
    for x in scan('name.basics'):
        n+=1;f.add([x[0],x[1],x[4]])
        if x[0] in wanted and x[1] not in ('\\N',''):valid_names.add(x[0])
    raw_rows['name.basics']=n
    f=fp('ACTOR_RAW');n=0;invalid_actor=0
    print(now(),'RAW title.principals',flush=True)
    for x in scan('title.principals'):
        n+=1
        if x[0] in movie_ids and x[3] in ('actor','actress'):
            f.add(x)
            if x[2] in valid_names:ac[x[0]]+=1
            else:invalid_actor+=1
    raw_rows['title.principals']=n
    f=fp('CREW_RAW');n=0;invalid_director=0;duplicates=0
    print(now(),'RAW title.crew',flush=True)
    for x in scan('title.crew'):
        n+=1
        if x[0] in movie_ids:
            f.add(x)
            ds=[] if x[1] in ('\\N','') else x[1].split(',')
            unique=set(ds);duplicates+=len(ds)-len(unique)
            dc[x[0]]=len(unique&valid_names);invalid_director+=len(unique-valid_names)
    raw_rows['title.crew']=n
    f=fp('ALIAS_RAW');n=0;invalid_alias=0
    print(now(),'RAW title.akas',flush=True)
    for x in scan('title.akas'):
        n+=1
        if x[0] in movie_ids:
            f.add(x)
            if x[2] not in ('\\N',''):bc[x[0]]+=1
            else:invalid_alias+=1
    raw_rows['title.akas']=n
    independent_expected=sum(ac[t]*dc[t]*bc[t] for t in movie_ids)
    mismatches=0
    for t,a,d,b,expected in c.execute('SELECT tconst,A,D,B,expectedRows FROM MOVIE_COUNTS').fetchall():
        if (a,d,b,expected)!=(ac[t],dc[t],bc[t],ac[t]*dc[t]*bc[t]):mismatches+=1
    assert mismatches==0
    assert independent_expected==json.loads((BASE/'checks/build_complete.json').read_text())['actual']
    projections={'MOVIE':'tconst,primaryTitle,originalTitle','PERSON':'nconst,primaryName,primaryProfession',
      'ACTOR_RAW':'tconst,ordering,nconst,category,job,characters',
      'ALIAS_RAW':'titleId,ordering,title,region,language,types,attributes,isOriginalTitle',
      'CREW_RAW':'tconst,directors,writers'}
    fingerprints={}
    for table,cols in projections.items():
        print(now(),'TABLE_FINGERPRINT',table,flush=True)
        f=Fingerprint();r=c.execute(f'SELECT {cols} FROM {table}')
        while True:
            chunk=r.fetchmany(50000)
            if not chunk:break
            for x in chunk:f.add(x)
        fingerprints[table]={'official_raw':fps[table].value(),'formal_table_or_frozen_extract':f.value()}
        assert fps[table].value()==f.value(),(table,fingerprints[table])
    c.close()
    save('checks/independent_raw_validation.json',dict(started_at_utc=start,completed_at_utc=now(),seconds=time.monotonic()-t0,
       raw_record_counts=raw_rows,projection_fingerprints=fingerprints,independent_expected_moviecast=independent_expected,
       per_movie_mismatches=mismatches,invalid_actor_associations=invalid_actor,invalid_directors=invalid_director,
       invalid_aliases=invalid_alias,normalized_director_duplicates=duplicates,all_passed=True,
       method='Independent standard-library gzip UTF-8 tab parser; no DuckDB CSV reader. Full per-movie counts, and order-independent SHA256 multiset fingerprints of exact raw projections.'))
    print('INDEPENDENT_RAW_VALIDATION_ALL_PASSED',independent_expected,flush=True)

if __name__=='__main__':main()
