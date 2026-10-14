#!/usr/bin/env python3
"""Fixed real objects and previously verified queries; public workload only."""
import collections,gzip,json,pathlib,shutil
from common import BASE,ROOT,OLD,SEED,save,csvsave,sha,bit_ids,threshold_mask,bounded_ed,distribution
from plain_index import PlainIndex

Q_VALUES=[3,4,5,6];R=4;B=65536

def independent_ed(a,b,tau):
 if abs(len(a)-len(b))>tau:return tau+1
 row=list(range(len(b)+1))
 for i,x in enumerate(a,1):
  nxt=[i]
  for j,y in enumerate(b,1):nxt.append(min(nxt[-1]+1,row[j]+1,row[j-1]+(x!=y)))
  row=nxt
 return row[-1]

def main():
 pool=OLD/'samples/n10000';a=json.loads((pool/'MOVIECAST.json').read_text());m=json.loads((pool/'MOVIE.json').read_text());by={r['tconst']:r for r in m}
 eligible=[r for r in a if len(r['aliasTitle'])>=6 and len(by[r['tconst']]['primaryTitle'])>=6]
 a=eligible[:1000];keys={r['tconst'] for r in a};m=[r for r in m if r['tconst'] in keys];aid={r['objectId']:i for i,r in enumerate(a)};mid={r['objectId']:i for i,r in enumerate(m)};movie={r['tconst']:i for i,r in enumerate(m)}
 assert len(a)==1000 and len(aid)==1000 and len(mid)==len(m)
 frozen=OLD/'samples/n1000';oldqueries=json.loads((frozen/'queries.json').read_text());oldanswers={x['queryId']:x for x in json.loads((frozen/'plaintext_answers.json').read_text())}
 queries=[x for x in oldqueries if min(len(x['Qdelta']),len(x['Qgamma']))>=6*R and x['sourceAnchorObjectId'] in aid]
 assert len(queries)>0 and all(0<=x['tauDelta']<R and 0<=x['tauGamma']<R for x in queries)
 save('samples/n1000/MOVIECAST.json',a);save('samples/n1000/MOVIE.json',m);save('samples/fixed_queries.json',queries)
 duplicate=collections.Counter((r['tconst'],r['aliasTitle']) for r in a)
 save('checks/fair_configuration.json',dict(seed=SEED,q_values=Q_VALUES,N=1000,targetN=len(m),B=B,signature_count_both_sides=R,
  tau_delta=[0,1,2,3],tau_gamma=[0,1,2,3],public_Upos=270,position_Bin=10,comparison_Bout=1,
  fixed_records_across_q=True,fixed_queries_across_q=True,eligible_in_original_pool=len(eligible),
  source_pool='unchanged prior verified nested n10000 hash-order pool',sampling_rule='Filter both full source strings >=6 Unicode codepoints then first 1000; no K-based selection and no truncation',
  query_rule='Reuse all previous n1000 queries whose seed is in the common sample and both full query lengths >=24; first 4 disjoint q-chunks only, full strings retained for exact verification',
  queries=len(queries),distinct_source_query_seeds=len({x['sourceAnchorObjectId'] for x in queries}),
  preserved_objects_in_duplicate_title_groups=sum(n for n in duplicate.values() if n>1),
  source_hashes={str(p.relative_to(ROOT)):sha(p) for p in [pool/'MOVIECAST.json',pool/'MOVIE.json',frozen/'queries.json',frozen/'plaintext_answers.json']},
  crypto_outsourcing_status='BLOCKED: current target chain still uses retired matrix; no real crypto index constructed',
  scale5000_status='NOT RUN: new-operator integrated correctness prerequisite not met',
  safety_scope='Position backend uses fresh crypto randomness. Public plaintext bucket profiling keys are fixed across q, not production secrets.'))
 # Project prior answers and independently validate the common sample exact baseline.
 cacheA={};cacheM={};truths={};prior_projection=[]
 for query in queries:
  d,g,td,tg=query['Qdelta'],query['Qgamma'],query['tauDelta'],query['tauGamma']
  for role,rs,text,key,cache in [('a',a,'aliasTitle',(d,td),cacheA),('m',m,'primaryTitle',(g,tg),cacheM)]:
   if key not in cache:
    hits=set()
    for i,row in enumerate(rs):
     x=bounded_ed(row[text],key[0],key[1]);y=independent_ed(row[text],key[0],key[1])
     assert (x<=key[1])==(y<=key[1]),('independent ED disagreement',role,i,key)
     if x<=key[1]:hits.add(i)
    cache[key]=hits
  truth={(i,movie[a[i]['tconst']]) for i in cacheA[(d,td)] if movie[a[i]['tconst']] in cacheM[(g,tg)]}
  old={(aid[p['anchorObjectId']],mid[p['targetObjectId']]) for p in oldanswers[query['queryId']]['pairs'] if p['anchorObjectId'] in aid and p['targetObjectId'] in mid}
  assert old<=truth
  prior_projection.append(dict(queryId=query['queryId'],projected_old_pairs=len(old),current_common_sample_pairs=len(truth),newly_included_real_sample_pairs=len(truth-old),old_pairs_preserved=True))
  truths[query['queryId']]=truth
 csvsave('checks/prior_answer_projection.csv',prior_projection)
 save('samples/exact_answers.json',[dict(queryId=x['queryId'],pairs=[dict(anchorObjectId=a[i]['objectId'],targetObjectId=m[j]['objectId']) for i,j in sorted(truths[x['queryId']])]) for x in queries])
 print('FIXED_COMMON_SAMPLE',len(a),len(m),'queries',len(queries),flush=True)
 metrics=[];checks=[]
 with gzip.open(BASE/'results/query_details.jsonl.gz','wt',encoding='utf-8') as details:
  for q in Q_VALUES:
   occ=sum(max(0,len(r['aliasTitle'])-q+1) for r in a)+sum(max(0,len(r['primaryTitle'])-q+1) for r in m)
   free=shutil.disk_usage(BASE).free;available=int(next(x for x in open('/proc/meminfo') if x.startswith('MemAvailable:')).split()[1])*1024
   assert free>512*(1<<20) and available>512*(1<<20)
   save(f'checks/resources_q{q}.json',dict(plaintext_occurrences=occ,available_memory_bytes=available,available_disk_bytes=free,scope='1000-object public plaintext only; not a crypto resource estimate'))
   index=PlainIndex(a,m,q,B,1000)
   qrows=[]
   for query in queries:
    fd=[(query['Qdelta'][h*q:(h+1)*q],h*q) for h in range(R)];fg=[(query['Qgamma'][h*q:(h+1)*q],h*q) for h in range(R)]
    td,tg=query['tauDelta'],query['tauGamma'];af=[index.anchor_feature(w,p,td) for w,p in fd]
    ids=list(bit_ids(threshold_mask([x['mask'] for x in af],R-td,len(a))))
    counts=collections.Counter(i for x in af for i in bit_ids(x['mask']));assert set(ids)=={i for i,n in counts.items() if n>=R-td}
    matched=0
    for w,p in fd:
     group=index.groups['anchor'].get(w)
     if group:matched+=sum(ri>=0 and abs(pos-p)<=td for ri,pos in zip(group['rows'],group['positions']))
    SP=targetMatched=0;pairs=[];routes=0;evalP=0
    for i in ids:
     tc=a[i]['tconst'];hits=0
     for w,p in fg:
      f=index.target_feature(tc,w,p,tg);hits+=f['hit'];SP+=f['S'];evalP+=f['evaluation'];routes+=1
      group=index.groups['target'].get((tc,w))
      if group:targetMatched+=sum(ri>=0 and abs(pos-p)<=tg for ri,pos in zip(group['rows'],group['positions']))
     if hits>=R-tg:pairs.append((i,movie[tc]))
    assert len(pairs)==len(set(pairs)) and routes==len(ids)*R
    truth=truths[query['queryId']];final={(i,j) for i,j in pairs if i in cacheA[(query['Qdelta'],td)] and j in cacheM[(query['Qgamma'],tg)]}
    assert final==truth
    exactA=cacheA[(query['Qdelta'],td)];assert exactA<=set(ids)
    fpAnchor=len(set(ids)-exactA);fpPairs=len(set(pairs)-truth)
    row=dict(q=q,N_anchor=len(a),N_target=len(m),B=B,r_delta=R,r_gamma=R,queryId=query['queryId'],tau_delta=td,tau_gamma=tg,
     anchorMatchedPostingItems=matched,S_B=sum(f['S'] for f in af),K=len(ids),candidateRetentionRate=len(ids)/len(a),
     anchorFalsePositiveCandidates=fpAnchor,anchorFalsePositiveRate=fpAnchor/len(ids) if ids else 0,
     routes=routes,targetMatchedPostingItems=targetMatched,S_P=SP,
     signatureCandidatePairs=len(pairs),signatureFalsePositivePairs=fpPairs,signatureFalsePositivePairRate=fpPairs/len(pairs) if pairs else 0,
     exactResultPairs=len(final),falseNegatives=0,wrongResults=0,duplicateResults=0,labelOutOfRange=0,
     anchorEvaluationDomain=sum(f['evaluation'] for f in af),targetEvaluationDomain=evalP,
     scope='PUBLIC PLAINTEXT WORKLOAD; NOT CRYPTO QUERY PERFORMANCE')
    metrics.append(row);qrows.append(row)
    details.write(json.dumps(dict(query=query,**row,anchorCandidateObjectIds=[a[i]['objectId'] for i in ids],
     exactPairs=[dict(anchorObjectId=a[i]['objectId'],targetObjectId=m[j]['objectId']) for i,j in sorted(final)]),ensure_ascii=False)+'\n')
   index.save_scope='public_plaintext_only'
   checks.append(dict(q=q,queries=len(qrows),all_exact_answers_equal_saved_baseline=True,all_anchor_exact_hits_retained=True,
    OR_and_Keep_semantics_checked=True,label_out_of_range=0,wrong_join=0,duplicate_results=0,source_objects_preserved=True))
   print('PUBLIC_Q_COMPLETE',q,'meanK',sum(x['K'] for x in qrows)/len(qrows),'meanSB',sum(x['S_B'] for x in qrows)/len(qrows),'meanSP',sum(x['S_P'] for x in qrows)/len(qrows),flush=True)
 csvsave('results/plain_query_metrics.csv',metrics);save('checks/plain_correctness.json',checks)
 summary=[]
 for q in Q_VALUES:
  rs=[x for x in metrics if x['q']==q];s=dict(q=q,query_executions=len(rs),distinct_queries=len({x['queryId'] for x in rs}))
  for name in ['anchorMatchedPostingItems','S_B','K','routes','S_P','signatureCandidatePairs','exactResultPairs']:
   for k,v in distribution([x[name] for x in rs]).items():
    if k!='count':s[name+'_'+k]=v
  s['anchor_false_positive_ratio']=sum(x['anchorFalsePositiveCandidates'] for x in rs)/sum(x['K'] for x in rs)
  s['signature_false_positive_pair_ratio']=sum(x['signatureFalsePositivePairs'] for x in rs)/sum(x['signatureCandidatePairs'] for x in rs)
  summary.append(s)
 csvsave('reports/plain_q_summary.csv',summary)
 csvsave('results/crypto_outsourcing_status.csv',[dict(q=q,N_anchor=1000,status='BLOCKED_TARGET_MATRIX_PATH',successful_repetitions=0,
  crypto_build_seconds=None,secret_sharing_seconds=None,total_outsource_seconds=None,save_seconds=None,validation_seconds=None,
  actual_outsource_communication_bytes=None,actual_crypto_index_storage_bytes=None,peak_memory_bytes=None,
  reason='No current new-operator complete DO build/target path; retired builder and target auxiliary matrix not invoked') for q in Q_VALUES])
 save('checks/fair_plain_complete.json',dict(contexts=4,queries_per_q=len(queries),query_executions=len(metrics),
  independent_edit_distance_matches=True,all_four_q_exact_answers_identical=True,
  password_index_built=False,scale5000_run=False,scale5000_reason='Integrated new-operator prerequisite not met'))

if __name__=='__main__':main()
