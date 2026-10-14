#!/usr/bin/env python3
"""Read-only sample and exact two-predicate/one-join baseline, no PERSON/other strings read."""
import collections,datetime,hashlib,json,pathlib,re,shutil,time
import duckdb

ROOT=pathlib.Path(__file__).resolve().parents[2]
OUT=pathlib.Path(__file__).resolve().parents[1]
FULL=ROOT/'imdb_final_dataset'
SEED=20261014
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def lit(x):return "'"+str(x).replace("'","''")+"'"
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
def save(path,x):
 p=OUT/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def ed(a,b):
 if len(a)>len(b):a,b=b,a
 prev=list(range(len(a)+1))
 for j,cb in enumerate(b,1):
  cur=[j]
  for i,ca in enumerate(a,1):cur.append(min(cur[-1]+1,prev[i]+1,prev[i-1]+(ca!=cb)))
  prev=cur
 return prev[-1]
def ed_through3(a,b):
 # Exact for all distances <=3; 4 is the explicit sentinel for anything larger.
 if a==b:return 0
 if abs(len(a)-len(b))>3:return 4
 if len(a)>len(b):a,b=b,a
 prev={i:i for i in range(min(len(a),3)+1)}
 for j,cb in enumerate(b,1):
  cur={}
  if j<=3:cur[0]=j
  for i in range(max(1,j-3),min(len(a),j+3)+1):
   cur[i]=min(cur.get(i-1,4)+1,prev.get(i,4)+1,prev.get(i-1,4)+(a[i-1]!=cb),4)
  if min(cur.values(),default=4)>3:return 4
  prev=cur
 return prev.get(len(a),4)
def mutate(s,k,kind='substitute'):
 # Query perturbations only; source strings and sampled records are never changed.
 chars=list(s)
 if kind=='insert':return s+'~'*k
 if kind=='delete':return ''.join(chars[:-k]) if k else s
 for i in range(min(k,len(chars))):chars[i]='~' if chars[i]!='~' else '^'
 return ''.join(chars)
def profile(records,field):
 counts=collections.Counter();repeat=0
 for r in records:
  s=r[field];n=len(s);counts[n]+=1
  grams=collections.Counter(s[i:i+4] for i in range(max(0,n-3)))
  repeat=max(repeat,max(grams.values(),default=0))
 return dict(records=len(records),null_strings=sum(r[field] is None for r in records),
  min_codepoints=min(counts),max_codepoints=max(counts),shorter_than_q4=sum(v for k,v in counts.items() if k<4),
  fewer_than_16_codepoints=sum(v for k,v in counts.items() if k<16),
  max_utf8_bytes=max(len(r[field].encode()) for r in records),max_qgram_multiplicity_per_record=repeat,
  non_ascii_records=sum(any(ord(ch)>127 for ch in r[field]) for r in records),
  length_histogram=dict(sorted(counts.items())))

def make_queries(anchors,movies):
 by={r['tconst']:r for r in movies};families=[];used=set()
 def add(r,kind):
  key=(r['aliasTitle'],by[r['tconst']]['primaryTitle'],kind)
  if key in used:return
  used.add(key);families.append(dict(anchor=r,target=by[r['tconst']],kind=kind))
 # Real independent queries, including titles that are quite different on the two sides.
 ranked=sorted(anchors,key=lambda r:(-ed(r['aliasTitle'],by[r['tconst']]['primaryTitle']),r['objectId']))
 for r in ranked[:3]:add(r,'distinct_alias_and_primary')
 for r in anchors:
  if len(r['aliasTitle'])>=16 and len(by[r['tconst']]['primaryTitle'])>=16:
   add(r,'normal_q4_tau3_domain')
   if sum(f['kind']=='normal_q4_tau3_domain' for f in families)>=3:break
 for r in anchors:
  if any(ord(ch)>127 for ch in r['aliasTitle']):add(r,'unicode');break
 for r in anchors:
  if len(r['aliasTitle'])<4 or len(by[r['tconst']]['primaryTitle'])<4:add(r,'short_string_q4_boundary');break
 groups=collections.defaultdict(list)
 for r in anchors:groups[(r['tconst'],r['aliasTitle'])].append(r)
 repeated=sorted((g for g in groups.values() if len(g)>1),key=lambda g:(-len(g),g[0]['objectId']))
 if repeated:add(repeated[0][0],'distinct_source_duplicate_string')
 # A negative control retains each side's exact text but uses genuinely incompatible movies.
 if len(movies)>1:
  r=anchors[0];other=next(m for m in movies if m['tconst']!=r['tconst'] and m['primaryTitle']!=by[r['tconst']]['primaryTitle'])
  families.append(dict(anchor=r,target=other,kind='different_movie_join_control'))
 queries=[]
 for fi,f in enumerate(families):
  for mode in ['exact','substitute1','insert1','delete1','substitute2','substitute3']:
   ad=f['anchor']['aliasTitle'];gt=f['target']['primaryTitle']
   if mode!='exact':
    k=int(mode[-1]);kind=mode[:-1];ad=mutate(ad,k,kind);gt=mutate(gt,k,kind)
   for td in range(4):
    for tg in range(4):
     queries.append(dict(queryId=f'f{fi:02d}_{mode}_d{td}g{tg}',family=f['kind'],mode=mode,
       Qdelta=ad,Qgamma=gt,tauDelta=td,tauGamma=tg,
       sourceAnchorObjectId=f['anchor']['objectId'],sourceTargetObjectId=f['target']['objectId'],
       queryStringMutualEditDistance=ed(ad,gt)))
 return queries

def main():
 OUT.mkdir(exist_ok=True)
 for d in ['checks','logs','reports','bin','scripts','samples','runtime']: (OUT/d).mkdir(exist_ok=True)
 manifest=json.loads((FULL/'artifact_manifest.json').read_text())
 touched=['data/imdb_final.duckdb','data/MOVIE.parquet']+[r['path'] for r in manifest['files'] if r['path'].startswith('data/MOVIECAST/')]
 before={p:dict(bytes=(FULL/p).stat().st_size,sha256=sha(FULL/p)) for p in touched}
 save('checks/full_inputs_before.json',before)
 c=duckdb.connect(str(FULL/'data/imdb_final.duckdb'),read_only=True)
 c.execute("SET memory_limit='4GB'; SET threads=4")
 encoding_probes=[]
 for x,y in [('电影','电~'),('É','~'),('Б','~'),('abc','a~c')]:
  d=c.execute('SELECT levenshtein(?,?)',[x,y]).fetchone()[0]
  encoding_probes.append(dict(left=x,right=y,duckdb_builtin_distance=d,unicode_codepoint_distance=ed(x,y)))
 save('checks/edit_distance_encoding_probes.json',dict(duckdb_version=duckdb.__version__,probes=encoding_probes,
  finding='DuckDB builtin Levenshtein in this environment measures UTF-8 byte edits, unlike the codepoint q-gram index; use Unicode-codepoint baseline',
  minimum_fix='Use supplied Python/Go codepoint Levenshtein; do not directly use builtin levenshtein for multilingual correctness answers'))
 # Select only this query's data: two source fields plus anchor identity.
 sql=f"SELECT tconst,aliasTitle,objectId FROM MOVIECAST_OBJECTS ORDER BY sha256(objectId||'|{SEED}'),objectId LIMIT 10000"
 print(now(),'DRAW reproducible 10000-object nested pool',flush=True)
 t0=time.monotonic();pool=c.execute(sql).fetchall();again=c.execute(sql).fetchall()
 assert pool==again
 for r in pool:
  assert re.fullmatch(r'tt[0-9]+',r[0]) and r[1] is not None
  assert r[0]=='tt'+f'{int(r[0][2:]):07d}' and int(r[0][2:])<2**64
 global_ids={r[2]:i+1 for i,r in enumerate(pool)}
 checks=[]
 for n in [1000,5000,10000]:
  directory=OUT/'samples'/f'n{n}';directory.mkdir(exist_ok=True)
  anchors=[dict(objectId=oid,recordId=global_ids[oid],tconst=tc,joinId=int(tc[2:]),aliasTitle=s) for tc,s,oid in pool[:n]]
  tids=sorted({r['tconst'] for r in anchors})
  target_rows=c.execute('SELECT tconst,primaryTitle FROM MOVIE WHERE tconst IN ('+','.join(lit(x) for x in tids)+') ORDER BY tconst').fetchall()
  movies=[dict(objectId=tc,recordId=int(tc[2:]),tconst=tc,joinId=int(tc[2:]),primaryTitle=s) for tc,s in target_rows]
  assert len(movies)==len(tids) and {m['tconst'] for m in movies}==set(tids)
  assert len(set(r['objectId'] for r in anchors))==n
  assert len({m['recordId'] for m in movies})==len(movies)
  assert all(m['primaryTitle'] is not None for m in movies)
  for file,values in [('MOVIECAST.json',anchors),('MOVIE.json',movies)]:
   (directory/file).write_text(json.dumps(values,ensure_ascii=False,indent=2)+'\n')
  for f in [directory/'MOVIECAST.parquet',directory/'MOVIE.parquet']:
   if f.exists():f.unlink()
  # Compact official field projections are separately usable by external readers.
  c.execute(f"COPY (SELECT tconst,aliasTitle,objectId FROM MOVIECAST_OBJECTS WHERE objectId IN ({','.join(lit(r['objectId']) for r in anchors)}) ORDER BY objectId) TO {lit(directory/'MOVIECAST.parquet')} (FORMAT PARQUET,COMPRESSION ZSTD)")
  c.execute(f"COPY (SELECT tconst,primaryTitle FROM MOVIE WHERE tconst IN ({','.join(lit(x) for x in tids)}) ORDER BY tconst) TO {lit(directory/'MOVIE.parquet')} (FORMAT PARQUET,COMPRESSION ZSTD)")
  dup=collections.Counter((r['tconst'],r['aliasTitle']) for r in anchors)
  ap=profile(anchors,'aliasTitle');mp=profile(movies,'primaryTitle')
  check=dict(scale=n,anchor_objects=n,target_objects=len(movies),all_foreign_keys_preserved=True,
    tconst_encoding='Exact official tt ID -> numeric suffix uint64 -> 8-byte unsigned big-endian canonical join; roundtrip and collision checks passed',
    objectId_to_recordId='anchor: rank 1..10000 in frozen deterministic pool; target: numeric official tconst; source mapping retained',
    same_seed_second_draw_identical=True,no_legal_object_deduplication=True,
    duplicate_string_groups=sum(v>1 for v in dup.values()),objects_in_duplicate_string_groups=sum(v for v in dup.values() if v>1),
    aliasTitle=ap,primaryTitle=mp,all_passed=True)
  save(f'samples/n{n}/sample_manifest.json',dict(seed=SEED,selection='first N of smallest SHA256(objectId + | + decimal seed), stable objectId tie break',**check))
  print(now(),'PLAINTEXT',n,'anchor',len(movies),'target',flush=True)
  queries=make_queries(anchors,movies)
  target_lookup={m['tconst']:m for m in movies};dist_cache={};answers=[]
  for query in queries:
   ad=query['Qdelta'];gt=query['Qgamma'];td=query['tauDelta'];tg=query['tauGamma']
   cachekey=(ad,gt)
   if cachekey not in dist_cache:
    text_da={s:ed_through3(s,ad) for s in {r['aliasTitle'] for r in anchors}}
    text_dm={s:ed_through3(s,gt) for s in {r['primaryTitle'] for r in movies}}
    distances_a={r['objectId']:text_da[r['aliasTitle']] for r in anchors}
    distances_m={r['objectId']:text_dm[r['primaryTitle']] for r in movies}
    dist_cache[cachekey]=(distances_a,distances_m)
   da,dm=dist_cache[cachekey]
   # Method A: independently filter two tables, then hash join on actual tconst.
   amatch=[r for r in anchors if da[r['objectId']]<=td]
   mmatch={r['tconst']:r for r in movies if dm[r['objectId']]<=tg}
   pairs=sorted((r['objectId'],mmatch[r['tconst']]['objectId']) for r in amatch if r['tconst'] in mmatch)
   # Method B: enumerate the original preserved relation first, then apply both predicates.
   reference=sorted((r['objectId'],target_lookup[r['tconst']]['objectId']) for r in anchors
      if da[r['objectId']]<=td and dm[target_lookup[r['tconst']]['objectId']]<=tg)
   assert pairs==reference and len(pairs)==len(set(pairs))
   # Builtin DuckDB ED is checked only on ASCII. Non-ASCII uses codepoints;
   # every full result is independently recomputed using Go []rune DP later.
   ar=next(r for r in anchors if r['objectId']==query['sourceAnchorObjectId'])
   mr=next(r for r in movies if r['objectId']==query['sourceTargetObjectId'])
   db_a,db_m=c.execute('SELECT levenshtein(?,?),levenshtein(?,?)',[ar['aliasTitle'],ad,mr['primaryTitle'],gt]).fetchone()
   if ar['aliasTitle'].isascii() and ad.isascii():assert min(db_a,4)==da[ar['objectId']]
   if mr['primaryTitle'].isascii() and gt.isascii():assert min(db_m,4)==dm[mr['objectId']]
   query['anchorQueryChunks']=len(ad)//4;query['targetQueryChunks']=len(gt)//4
   query['currentProtocolQueryDomainSupported']=(1<=len(ad)//4<=14 and td<len(ad)//4 and 1<=len(gt)//4<=16 and tg<len(gt)//4)
   answers.append(dict(queryId=query['queryId'],anchorStringMatches=len(amatch),targetStringMatches=len(mmatch),
      pairCount=len(pairs),pairs=[dict(anchorObjectId=a,targetObjectId=m) for a,m in pairs]))
  (directory/'queries.json').write_text(json.dumps(queries,ensure_ascii=False,indent=2)+'\n')
  (directory/'plaintext_answers.json').write_text(json.dumps(answers,ensure_ascii=False,indent=2)+'\n')
  threshold_stats=[]
  for td in range(4):
   for tg in range(4):
    subset=[x for q,x in zip(queries,answers) if (q['tauDelta'],q['tauGamma'])==(td,tg)]
    threshold_stats.append(dict(tauDelta=td,tauGamma=tg,queries=len(subset),nonempty=sum(x['pairCount']>0 for x in subset),totalPairs=sum(x['pairCount'] for x in subset)))
  pairs=len(answers);nonempty=sum(x['pairCount']>0 for x in answers)
  # Monotonicity is checked within each identical text/mode/family, separately per threshold.
  grouped=collections.defaultdict(dict)
  for q,a in zip(queries,answers):grouped[(q['family'],q['mode'],q['Qdelta'],q['Qgamma'])][(q['tauDelta'],q['tauGamma'])]={tuple(x.values()) for x in a['pairs']}
  for group in grouped.values():
   for (td,tg),answer in group.items():
    if td<3:assert answer<=group[(td+1,tg)]
    if tg<3:assert answer<=group[(td,tg+1)]
  check['plaintext']=dict(queries=len(queries),nonempty_queries=nonempty,empty_queries=len(queries)-nonempty,
      threshold_grid=threshold_stats,full_answer_equivalence=True,threshold_monotonicity=True,
      current_protocol_supported_query_count=sum(q['currentProtocolQueryDomainSupported'] for q in queries),
      real_distinct_alias_primary_query_families=sum(q['family']=='distinct_alias_and_primary' and q['mode']=='exact' and q['tauDelta']==q['tauGamma']==0 for q in queries),
      all_passed=True)
  save(f'checks/n{n}_data_and_plaintext.json',check);checks.append(check)
  save(f'samples/n{n}/files.json',{f.name:dict(bytes=f.stat().st_size,sha256=sha(f)) for f in directory.iterdir() if f.is_file() and f.name!='files.json'})
 c.close();save('checks/data_plaintext_summary.json',dict(started_seed=SEED,completed_at_utc=now(),seconds=time.monotonic()-t0,scales=checks,all_passed=True))
 print('SAMPLE_AND_PLAINTEXT_COMPLETE',flush=True)

if __name__=='__main__':main()
