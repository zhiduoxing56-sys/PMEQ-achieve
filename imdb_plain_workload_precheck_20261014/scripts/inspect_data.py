#!/usr/bin/env python3
"""Read-only narrow full-table statistics; reuse and independently check saved plaintext samples."""
import collections,datetime,json,pathlib,shutil
import duckdb
from common import BASE,FULL,OLD,Q_VALUES,SCALES,SEED,csvsave,save,sha

def main():
 for d in ['checks','reports','results','plain_indexes','scripts','samples','logs','temporary']:(BASE/d).mkdir(parents=True,exist_ok=True)
 protected={}
 for root,label in [(FULL,'formal'),(OLD,'prior_plaintext')]:
  for p in root.rglob('*'):
   if p.is_file() and not p.is_symlink():protected[label+'/'+str(p.relative_to(root))]=dict(bytes=p.stat().st_size,sha256=sha(p))
 save('checks/protected_inputs_before.json',protected)
 c=duckdb.connect(str(FULL/'data/imdb_final.duckdb'),read_only=True)
 c.execute("SET memory_limit='6GB'; SET threads=4")
 c.execute('SET temp_directory=?',[str(BASE/'temporary')])
 joins=c.execute('''WITH a AS (SELECT tconst,count(*) n FROM MOVIECAST GROUP BY tconst)
   SELECT sum(a.n)::BIGINT,count(*)::BIGINT,
    coalesce(sum(a.n) FILTER(WHERE m.tconst IS NOT NULL),0)::BIGINT,
    coalesce(sum(a.n) FILTER(WHERE m.tconst IS NULL),0)::BIGINT,
    coalesce(sum(a.n) FILTER(WHERE m.primaryTitle IS NOT NULL AND m.primaryTitle<>''),0)::BIGINT,
    max(a.n)::BIGINT FROM a LEFT JOIN MOVIE m USING(tconst)''').fetchone()
 full_stats={'MOVIECAST_objects':joins[0],'distinct_anchor_tconst':joins[1],'matched_join_records':joins[2],
   'dangling_join_records':joins[3],'objects_with_usable_target_string':joins[4],'maximum_objects_per_movie':joins[5],
   'MOVIE_objects':c.execute('SELECT count(*) FROM MOVIE').fetchone()[0],
   'distinct_target_tconst':c.execute('SELECT count(DISTINCT tconst) FROM MOVIE').fetchone()[0]}
 length_rows=[];length_profiles={}
 for table,field in [('MOVIECAST','aliasTitle'),('MOVIE','primaryTitle')]:
  hist=c.execute(f'SELECT length({field}) codepoints,count(*) records FROM {table} GROUP BY 1 ORDER BY 1').fetchall()
  for length,n in hist:length_rows.append(dict(scope='full_database',table=table,field=field,codepoints=length,records=n))
  valid={l:n for l,n in hist if l is not None and l>0};total=sum(valid.values())
  def quantile(p):
   remaining=int(max(0,total-1)*p)
   for l,n in valid.items():
    if remaining<n:return l
    remaining-=n
  length_profiles[table]=dict(total_records=sum(n for _,n in hist),null_records=sum(n for l,n in hist if l is None),
    empty_records=sum(n for l,n in hist if l==0),valid_nonempty_records=total,min=min(valid),max=max(valid),
    p05=quantile(.05),p50=quantile(.5),p95=quantile(.95),p99=quantile(.99),
    mean=sum(l*n for l,n in valid.items())/total,mathematical_q_interval=[1,max(valid)])
 c.close();save('checks/full_database_narrow_stats.json',dict(joins=full_stats,strings=length_profiles,
  selected_business_fields=['MOVIECAST.tconst','MOVIECAST.aliasTitle','MOVIE.tconst','MOVIE.primaryTitle'],
  distance_unit='Unicode codepoints',source_collection_unchanged=True))
 legality=[];pair_legality=[];sample_stats=[]
 for n in SCALES:
  src=OLD/'samples'/f'n{n}';dst=BASE/'samples'/f'n{n}';dst.mkdir(exist_ok=True)
  for name in ['MOVIECAST.json','MOVIE.json']:shutil.copy2(src/name,dst/name)
  a=json.loads((dst/'MOVIECAST.json').read_text());m=json.loads((dst/'MOVIE.json').read_text());by={r['tconst']:r for r in m}
  assert len(a)==n and len({r['objectId'] for r in a})==n
  assert all(r['tconst'] in by for r in a)
  profiles={}
  for role,rs,field in [('anchor',a,'aliasTitle'),('target',m,'primaryTitle')]:
   hist=collections.Counter(len(r[field]) for r in rs)
   for l,num in sorted(hist.items()):length_rows.append(dict(scope=f'n{n}',table='MOVIECAST' if role=='anchor' else 'MOVIE',field=field,codepoints=l,records=num))
   profiles[role]={'min':min(hist),'max':max(hist),'length_histogram':dict(sorted(hist.items()))}
   texts=set(r[field] for r in rs)
   for q in Q_VALUES:
    weights=collections.Counter(len(r[field])//q for r in rs)
    distinct=collections.Counter(len(s)//q for s in texts)
    for r,num in sorted(weights.items()):legality.append(dict(scale=n,q=q,role=role,r=r,
      source_objects=num,distinct_real_query_strings=distinct[r],mathematically_legal=r>0,
      legal_tau_min=0 if r else None,legal_tau_max=r-1 if r else None,
      existing_code_q_and_r_supported=(q==4 and 1<=r<=(14 if role=='anchor' else 16))))
  for q in Q_VALUES:
   pair_groups=collections.defaultdict(lambda:[0,set()])
   for r in a:
    d,g=r['aliasTitle'],by[r['tconst']]['primaryTitle'];rd,rg=len(d)//q,len(g)//q
    group=pair_groups[(rd,rg)];group[0]+=1;group[1].add((d,g))
   for (rd,rg),(count,pairs) in sorted(pair_groups.items()):pair_legality.append(dict(scale=n,q=q,r_delta=rd,r_gamma=rg,
    source_objects=count,distinct_real_query_pairs=len(pairs),mathematically_legal=rd>0 and rg>0,
    legal_threshold_pair_count_per_query=rd*rg,
    threshold_pairs_in_0_to_3=min(rd,4)*min(rg,4),
    existing_code_q_and_r_supported=q==4 and 1<=rd<=14 and 1<=rg<=16))
  dup=collections.Counter((r['tconst'],r['aliasTitle']) for r in a)
  sample_stats.append(dict(anchor_objects=n,target_objects=len(m),matching_records=n,distinct_connection_keys=len(m),
    unique_anchor_identifiers=True,unique_target_identifiers=len({r['objectId'] for r in m})==len(m),
    preserved_repeated_source_objects=sum(v for v in dup.values() if v>1),strings=profiles))
 csvsave('reports/string_length_histograms.csv',length_rows)
 csvsave('reports/legal_queries_by_r.csv',legality)
 csvsave('reports/legal_real_query_pairs.csv',pair_legality)
 save('checks/samples_and_legality.json',dict(seed=SEED,scales=sample_stats,
  sampling='Reuse unchanged verified nested samples; no copying of data records within a sample',
  q_values=Q_VALUES,mathematical_query_rule='r=floor(Unicode length/q), r>=1, 0<=tau<r',
  query_count_convention='Source objects and distinct string queries both reported; distinct two-string query pairs separately reported'))
 print('DATA_STATISTICS_COMPLETE',json.dumps(full_stats),flush=True)

if __name__=='__main__':main()
