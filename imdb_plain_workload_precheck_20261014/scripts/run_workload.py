#!/usr/bin/env python3
"""Four public parameter axes, real source strings and joins, semantic OR audits and access counts."""
import collections,gc,gzip,json,pathlib,shutil
from common import BASE,Q_VALUES,SCALES,BUCKET_VALUES,SEED,chunks,csvsave,save,sha,bit_ids,threshold_mask,bounded_ed,distribution
from plain_index import PlainIndex

def variants(seed):
 for mode in ['exact','one_substitution']:
  d,g=seed['Qdelta'],seed['Qgamma']
  if mode=='one_substitution':
   d=('~' if d[0]!='~' else '^')+d[1:];g=('~' if g[0]!='~' else '^')+g[1:]
  for td in range(4):
   for tg in range(4):
    query=dict(seedId=seed['seedId'],seedAnchorObjectId=seed['seedAnchorObjectId'],seedTargetObjectId=seed['seedTargetObjectId'],
      mode=mode,Qdelta=d,Qgamma=g,tauDelta=td,tauGamma=tg)
    raw=json.dumps([d,g,td,tg],ensure_ascii=False,separators=(',',':')).encode()
    import hashlib
    query['queryId']=hashlib.sha256(raw).hexdigest()[:24]
    yield query

def seed_pool(a,m):
 by={r['tconst']:r for r in m};seen=set();out=[]
 for r in a:
  d,g=r['aliasTitle'],by[r['tconst']]['primaryTitle']
  if (d,g) in seen:continue
  seen.add((d,g));out.append(dict(seedId=r['objectId'],seedAnchorObjectId=r['objectId'],seedTargetObjectId=r['tconst'],Qdelta=d,Qgamma=g))
 return out

def run_query(index,query):
 q=index.q;fd=chunks(query['Qdelta'],q);fg=chunks(query['Qgamma'],q);rd,rg=len(fd),len(fg)
 td,tg=query['tauDelta'],query['tauGamma'];assert rd>td>=0 and rg>tg>=0
 af=[index.anchor_feature(w,p,td) for w,p in fd]
 candidate_mask=threshold_mask([f['mask'] for f in af],rd-td,index.n)
 # Independent public count array verifies bit-sliced per-object OR accumulation and Keep.
 naive_counts=collections.Counter()
 for w,p in fd:naive_counts.update(bit_ids(index.refcache[(w,p,td)]))
 reference_candidates={i for i,count in naive_counts.items() if count>=rd-td}
 ids=list(bit_ids(candidate_mask));assert set(ids)==reference_candidates
 join_candidates=collections.defaultdict(list)
 for i in ids:join_candidates[index.a[i]['tconst']].append(i)
 SP=realP=GP=evalP=nonemptyP=routes=target_checks=0;pbuckets=collections.Counter();candidate_pairs=[]
 for tc,anchor_ids in join_candidates.items():
  hits=0
  for w,p in fg:
   f=index.target_feature(tc,w,p,tg);multiplicity=len(anchor_ids)
   hits+=f['hit'];SP+=multiplicity*f['S'];realP+=multiplicity*f['real'];GP+=multiplicity*f['groups']
   evalP+=multiplicity*f['evaluation'];nonemptyP+=multiplicity*(f['S']>0);routes+=multiplicity
   target_checks+=multiplicity*f['boolean_outputs_checked'];pbuckets[f['bucket']]+=multiplicity
  # Independently compute the target object's feature matches from the original string.
  text=index.m_text[index.movie_by_tc[tc]];direct=0
  for w,p in fg:
   lo=max(0,p-tg);hi=min(len(text)-q,p+tg)
   direct+=hi>=lo and text.find(w,lo,hi+q)>=0
  assert hits==direct
  if hits>=rg-tg:candidate_pairs.extend((i,index.movie_by_tc[tc]) for i in anchor_ids)
 assert routes==len(ids)*rg
 # Exact answers use separate full-object edit predicates and preserved joins.
 delta_key=(query['Qdelta'],td);gamma_key=(query['Qgamma'],tg)
 if not hasattr(index,'ed_cache'):index.ed_cache={'anchor':{},'target':{}}
 if delta_key not in index.ed_cache['anchor']:
  index.ed_cache['anchor'][delta_key]={i for i,s in enumerate(index.a_text) if bounded_ed(s,delta_key[0],td)<=td}
 if gamma_key not in index.ed_cache['target']:
  index.ed_cache['target'][gamma_key]={i for i,s in enumerate(index.m_text) if bounded_ed(s,gamma_key[0],tg)<=tg}
 ed_a=index.ed_cache['anchor'][delta_key];ed_m=index.ed_cache['target'][gamma_key]
 truth={(i,index.movie_by_tc[index.a[i]['tconst']]) for i in ed_a if index.movie_by_tc[index.a[i]['tconst']] in ed_m}
 final={(i,j) for i,j in candidate_pairs if i in ed_a and j in ed_m}
 assert final==truth,('exact edit-distance answer omission',index.name,query['queryId'],len(final),len(truth))
 assert len(candidate_pairs)==len(set(candidate_pairs)), 'different source objects merged or identical object pair duplicated'
 SB=sum(f['S'] for f in af);realB=sum(f['real'] for f in af)
 unfiltered=index.unfiltered_target_slots(fg)
 fullscan=rg*index.summary['sides']['target']['paddedPostings']
 activeA=[f for f in af if f['S']];activeP=[index.bucket_meta['target'][b] for b in pbuckets if b in index.bucket_meta['target']]
 flags=[]
 if q!=4:flags.append('current_code_q_fixed_4')
 if rd>14:flags.append('anchor_r_above_14')
 if rg>16:flags.append('target_r_above_16')
 if not(14<=index.bits<=17):flags.append('bucket_width_outside_current_manifest')
 if max((f['D'] for f in af),default=0)>index.n:flags.append('visited_anchor_local_D_above_N')
 if max((f['D'] for f in af),default=0)>32768:flags.append('visited_anchor_D_above_32768')
 if max((f['S'] for f in af),default=0)>65536:flags.append('visited_anchor_T_above_65536')
 if max((x['paddedSlots'] for x in activeP),default=0)>65536:flags.append('visited_target_T_above_65536')
 position_max=max(max(len(s)-q for s in index.a_text if len(s)>=q),max(len(s)-q for s in index.m_text if len(s)>=q))
 if position_max>62:flags.append('indexed_positions_exceed_current_Upos_62')
 metric=dict(context=index.name,q=q,B=index.B,N_anchor=index.n,N_target=len(index.m),queryId=query['queryId'],
  r_delta=rd,r_gamma=rg,tau_delta=td,tau_gamma=tg,K=len(ids),candidateRetentionRate=len(ids)/index.n,
  exactAnchorStringMatches=len(ed_a),distinctCandidateJoinKeys=len(join_candidates),
  S_B=SB,anchorRealItemsVisited=realB,anchorDummyItemsVisited=SB-realB,
  anchorGroupComparisons=sum(f['groups'] for f in af),anchorBucketInvocations=rd,uniqueAnchorBuckets=len({f['bucket'] for f in af}),
  S_P=SP,targetRealItemsVisited=realP,targetDummyItemsVisited=SP-realP,targetGroupComparisons=GP,
  routes=routes,nonemptyTargetRoutes=nonemptyP,uniqueTargetBuckets=len(pbuckets),
  anchorEvaluationDomainTotal=sum(f['evaluation'] for f in af),anchorEvaluationDomainMax=max((f['evaluation'] for f in af),default=0),
  anchorObjectCapacityMax=max((f['D'] for f in af),default=0),targetEvaluationDomainTotal=evalP,
  targetEvaluationDomainMax=64 if nonemptyP else 0,targetEvaluationDomainTotalIfD16=32*nonemptyP,
  targetPublicObjectCapacity=26,targetObjectsPerJoin=1,
  aggregationBooleanOutputsChecked=sum(f['boolean_outputs_checked'] for f in af)+target_checks,
  aggregationCorrect=True,labelOutOfRange=0,signatureCandidatePairCount=len(candidate_pairs),exactResultPairCount=len(final),
  exactFalseNegatives=0,signatureFalsePositivePairs=len(candidate_pairs)-len(final),
  targetSlotsWithoutAnchorFiltering=unfiltered,targetSlotsFullTablePerChunk=fullscan,
  targetWorkloadRatioToUnfilteredRouting=SP/unfiltered if unfiltered else 0,
  targetWorkloadRatioToFullTargetScan=SP/fullscan if fullscan else 0,
  currentCodeLimitFlags=';'.join(flags),currentCodeAllListedLimitsSatisfied=not flags)
 detail=dict(query=query,**metric,
  anchorCandidateObjectIds=[index.a[i]['objectId'] for i in ids],
  signatureCandidatePairs=[dict(anchorObjectId=index.a[i]['objectId'],targetObjectId=index.m[j]['objectId']) for i,j in candidate_pairs],
  exactAnswerPairs=[dict(anchorObjectId=index.a[i]['objectId'],targetObjectId=index.m[j]['objectId']) for i,j in sorted(final)],
  anchorAccesses=[dict(occurrence=h,word=w,position=p,bucket=f['bucket'],paddedItems=f['S'],objectCapacity=f['D'],evaluationDomain=f['evaluation']) for h,((w,p),f) in enumerate(zip(fd,af))],
  targetBucketInvocations=[dict(bucket=b,invocations=times,paddedItemsPerInvocation=index.bucket_meta['target'].get(b,{}).get('paddedSlots',0),
    evaluationDomainPerInvocation=64 if b in index.bucket_meta['target'] else 0) for b,times in sorted(pbuckets.items())])
 return metric,detail

def main():
 datasets={}
 for n in SCALES:
  sd=BASE/'samples'/f'n{n}';datasets[n]=(json.loads((sd/'MOVIECAST.json').read_text()),json.loads((sd/'MOVIE.json').read_text()))
 pools={n:seed_pool(*datasets[n]) for n in SCALES}
 shared=pools[1000][:24]
 save('checks/query_seed_selection.json',dict(seed=SEED,shared_seeds=shared,
  rule='First 24 distinct real two-string query pairs in the previously frozen source-object hash order; no candidate-based selection',
  mutations='Queries only: exact and one codepoint substitution on each side. Data strings unchanged.',
  thresholds=[0,1,2,3],r_rule='All complete nonoverlapping chunks of the whole real query; no artificial truncation'))
 configurations=sorted({(n,4,65536) for n in SCALES}|{(10000,q,65536) for q in Q_VALUES}|{(10000,4,b) for b in BUCKET_VALUES})
 all_metrics=[];all_illegal=[];layout_summaries=[];bucket_invariance={};paired_q=collections.defaultdict(dict)
 with gzip.open(BASE/'results/query_details.jsonl.gz','wt',encoding='utf-8') as details:
  for n,q,b in configurations:
   a,m=datasets[n];occ=sum(max(0,len(r['aliasTitle'])-q+1) for r in a)+sum(max(0,len(r['primaryTitle'])-q+1) for r in m)
   mem={}
   for line in open('/proc/meminfo'):
    if line.startswith('MemAvailable:'):mem['available_bytes']=int(line.split()[1])*1024
   needed_memory=max(256*(1<<20),occ*500);needed_disk=max(128*(1<<20),occ*300)
   free=shutil.disk_usage(BASE).free
   save(f'checks/resources/n{n}_q{q}_B{b}.json',dict(plaintext_occurrences_before_padding=occ,
     working_memory_conservative_bytes=needed_memory,temporary_disk_conservative_bytes=needed_disk,
     available_memory_bytes=mem['available_bytes'],available_disk_bytes=free,
     sufficient=mem['available_bytes']>needed_memory+256*(1<<20) and free>needed_disk+256*(1<<20),
     scope='Only this requested plaintext subset, no full cipher-scale projection'))
   assert mem['available_bytes']>needed_memory+256*(1<<20) and free>needed_disk+256*(1<<20)
   print('BUILD_PLAINTEXT_POSTINGS',n,q,b,flush=True)
   index=PlainIndex(a,m,q,b,n);layout_summaries.append(index.summary)
   suite=[('shared_real_queries',s,None) for s in shared]
   if (n,q,b)==(10000,4,65536):
    for role in ['delta','gamma']:
     bins=collections.defaultdict(list)
     for s in pools[n]:
      rd,rg=len(s['Qdelta'])//q,len(s['Qgamma'])//q
      if rd and rg:bins[rd if role=='delta' else rg].append(s)
     for r,ss in sorted(bins.items()):
      for s in ss[:3]:suite.append((f'r_{role}_axis',s,r))
   suite_metrics=[];seen=set();attempts=0;invalid=0
   for family,seed,horizontal_r in suite:
    for query in variants(seed):
     query['family']=family;query['horizontal_r']=horizontal_r
     identity=(family,query['queryId'])
     if identity in seen:continue
     seen.add(identity);attempts+=1
     rd,rg=len(query['Qdelta'])//q,len(query['Qgamma'])//q
     if rd<1 or rg<1 or query['tauDelta']>=rd or query['tauGamma']>=rg:
      all_illegal.append(dict(context=index.name,family=family,queryId=query['queryId'],r_delta=rd,r_gamma=rg,
       tau_delta=query['tauDelta'],tau_gamma=query['tauGamma'],reason='no_complete_query_chunk' if not rd or not rg else 'tau_must_be_smaller_than_r'))
      invalid+=1;continue
     metric,detail=run_query(index,query);metric['family']=family;metric['horizontal_r']=horizontal_r
     detail['family']=family;detail['horizontal_r']=horizontal_r
     details.write(json.dumps(detail,ensure_ascii=False,separators=(',',':'))+'\n');all_metrics.append(metric);suite_metrics.append(metric)
     if family=='shared_real_queries' and n==10000 and q==4:
      digest=(tuple(detail['anchorCandidateObjectIds']),tuple((p['anchorObjectId'],p['targetObjectId']) for p in detail['exactAnswerPairs']))
      if query['queryId'] in bucket_invariance:assert bucket_invariance[query['queryId']]==digest,'Bucket variation changed logical answers'
      else:bucket_invariance[query['queryId']]=digest
     if family=='shared_real_queries' and n==10000 and b==65536:paired_q[query['queryId']][q]=metric
   csvsave(f'results/{index.name}_metrics.csv',suite_metrics)
   save(f'checks/{index.name}_correctness.json',dict(queries_attempted=attempts,mathematically_legal_queries=len(suite_metrics),
    invalid_queries_recorded=invalid,aggregation_semantic_correct_queries=len(suite_metrics),
    labels_out_of_range=0,exact_result_omissions=0,bucket_invariance_checked=(n==10000 and q==4),
    implementation_limit_flagged_queries=sum(bool(x['currentCodeLimitFlags']) for x in suite_metrics),
    flags_are_diagnostics_not_candidate_rate_gates=True))
   print('PLAIN_QUERY_COMPLETE',index.name,'legal',len(suite_metrics),'invalid',invalid,
    'K',distribution([x['K'] for x in suite_metrics]),flush=True)
   del index;gc.collect()
 csvsave('results/all_query_metrics.csv',all_metrics)
 csvsave('reports/invalid_query_configurations.csv',all_illegal)
 save('checks/plain_layouts.json',layout_summaries)
 common_ids=[qid for qid,d in paired_q.items() if len(d)==len(Q_VALUES)]
 common_metrics=[dict(paired_q[qid][q]) for qid in common_ids for q in Q_VALUES]
 csvsave('results/q_axis_common_legal_queries.csv',common_metrics,list(all_metrics[0]))
 save('checks/run_complete.json',dict(contexts=len(configurations),total_mathematically_legal_query_executions=len(all_metrics),
  invalid_query_configurations=len(all_illegal),all_plain_aggregation_checks_passed=True,all_exact_answer_checks_passed=True,
  bucket_changes_preserve_logical_answers=True,q_axis_queries_legal_under_every_tested_q=len(common_ids),
  no_secret_sharing_or_multiplication_or_product_tree_or_fft_run=True,
  no_candidate_count_or_rate_pass_threshold=True))
 print('ALL_PLAINTEXT_AXES_COMPLETE',len(all_metrics),flush=True)

if __name__=='__main__':main()
