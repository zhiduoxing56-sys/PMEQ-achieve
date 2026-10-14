"""Materialized plaintext postings, dummy slots and local labels. No protocol modules imported."""
import array,collections,csv,json,pathlib,shutil
import duckdb
from common import BASE,TIERS,anchor_hash,join_hash,target_word_hash,prefix,power2,width,csvsave,save,distribution

class PlainIndex:
 def __init__(self,anchors,movies,q,buckets,scale):
  self.a=anchors;self.m=movies;self.q=q;self.B=buckets;self.bits=buckets.bit_length()-1;self.n=scale
  self.name=f'n{scale}_q{q}_B{buckets}';self.path=BASE/'plain_indexes'/self.name
  self.path.mkdir(parents=True,exist_ok=True)
  self.a_text=[r['aliasTitle'] for r in anchors];self.m_text=[r['primaryTitle'] for r in movies]
  self.movie_by_tc={r['tconst']:i for i,r in enumerate(movies)}
  self.anchor_join_counts=collections.Counter(r['tconst'] for r in anchors)
  self.target_join_digest={r['tconst']:join_hash(r['tconst']) for r in movies}
  self.word_digest={};self.acache={};self.refcache={};self.tcache={};self.trefcache={}
  self.groups={};self.bucket_groups={};self.bucket_meta={};self.capacity=[];self.label_checks=0
  for role,records,field in [('anchor',anchors,'aliasTitle'),('target',movies,'primaryTitle')]:
   groups={}
   for ri,r in enumerate(records):
    text=r[field]
    for p in range(max(0,len(text)-q+1)):
     word=text[p:p+q];key=word if role=='anchor' else (r['tconst'],word)
     if key not in groups:
      if role=='anchor':bucket=prefix(anchor_hash(word),self.bits)
      else:
       if word not in self.word_digest:self.word_digest[word]=target_word_hash(word)
       bucket=prefix(self.target_join_digest[r['tconst']],self.bits)^prefix(self.word_digest[word],self.bits)
      groups[key]={'word':word,'join':None if role=='anchor' else r['tconst'],'bucket':bucket,'rows':[],'positions':[]}
     groups[key]['rows'].append(ri);groups[key]['positions'].append(p)
   bybucket=collections.defaultdict(list)
   for key,g in groups.items():
    w=width(len(g['rows']))
    if w is None:raise ValueError(f'{self.name} {role}: group {key!r} exceeds current padding ladder ({len(g["rows"])} real slots); no truncation')
    g['real']=len(g['rows']);g['width']=w;bybucket[g['bucket']].append(key)
   metadata={}
   for bucket,keys in sorted(bybucket.items()):
    ids=sorted({i for key in keys for i in groups[key]['rows']})
    local={ri:j+1 for j,ri in enumerate(ids)} if role=='anchor' else {ri:1 for ri in ids}
    D=power2(len(ids)) if role=='anchor' else 26
    eval_domain=power2(D+1) if role=='anchor' else power2(power2(D)+1)
    T=sum(groups[key]['width'] for key in keys)
    metadata[bucket]=dict(role=role,bucket=bucket,groups=len(keys),realSlots=sum(groups[key]['real'] for key in keys),
       paddedSlots=T,dummySlots=sum(groups[key]['width']-groups[key]['real'] for key in keys),
       distinctGlobalObjects=len(ids),publicObjectCapacity=D,evaluationDomain=eval_domain,
       targetEvaluationDomainD16=32 if role=='target' else 0,targetEvaluationDomainD26=64 if role=='target' else 0)
    if role=='anchor':metadata[bucket]['sourceRowsByLabel']=ids
    flags=[]
    if T>65536:flags.append('posting_T_above_65536')
    if role=='anchor' and D>32768:flags.append('label_D_above_32768')
    if role=='anchor' and D>scale:flags.append('public_local_D_above_global_N')
    if flags:self.capacity.append(dict(role=role,bucket=bucket,T=T,D=D,flags=';'.join(flags)))
    for key in keys:
     g=groups[key];g['rows']=array.array('i',g['rows']+[-1]*(g['width']-g['real']))
     g['positions']=array.array('i',g['positions']+[0]*(g['width']-g['real']))
     g['labels']=array.array('I',[local[ri] for ri in g['rows'][:g['real']]]+[0]*(g['width']-g['real']))
     assert len(g['rows'])==len(g['positions'])==len(g['labels'])==g['width']
     for row,position,label in zip(g['rows'],g['positions'],g['labels']):
      if row<0:assert label==0 and position==0
      else:
       assert 1<=label<=D and records[row][field][position:position+q]==g['word']
       if role=='anchor':assert ids[label-1]==row
       else:assert records[row]['tconst']==g['join'] and label==1
      self.label_checks+=1
   self.groups[role]=groups;self.bucket_groups[role]=bybucket;self.bucket_meta[role]=metadata
  self.persist()

 def persist(self):
  group_rows=[];bucket_rows=[];summaries={}
  c=duckdb.connect(':memory:');c.execute("SET memory_limit='2GB'")
  for role in ['anchor','target']:
   groups=self.groups[role];metas=self.bucket_meta[role];sorted_keys=sorted(groups,key=lambda k:(groups[k]['bucket'],repr(k)))
   temporary=self.path/f'{role}_postings.csv'
   with temporary.open('w',encoding='utf-8',newline='') as f:
    w=csv.writer(f);w.writerow(['groupOrdinal','slotOrdinal','objectRow','codepointPosition','localLabel','isReal'])
    for gi,key in enumerate(sorted_keys):
     g=groups[key];g['ordinal']=gi
     group_rows.append(dict(role=role,groupOrdinal=gi,qgram=g['word'],joinTconst=g['join'],bucket=g['bucket'],
       realSlots=g['real'],padWidth=g['width'],dummySlots=g['width']-g['real']))
     for si,(row,pos,label) in enumerate(zip(g['rows'],g['positions'],g['labels'])):w.writerow([gi,si,row,pos,label,row>=0])
   dest=self.path/f'{role}_postings.parquet'
   src_literal="'"+str(temporary).replace("'","''")+"'"
   dst_literal="'"+str(dest).replace("'","''")+"'"
   c.execute(f"COPY (SELECT groupOrdinal::INTEGER groupOrdinal,slotOrdinal::INTEGER slotOrdinal,objectRow::INTEGER objectRow,codepointPosition::INTEGER codepointPosition,localLabel::INTEGER localLabel,isReal::BOOLEAN isReal FROM read_csv({src_literal},header=true)) TO {dst_literal} (FORMAT PARQUET,COMPRESSION ZSTD)")
   actual=c.execute('SELECT count(*),count(*) FILTER(WHERE isReal),count(*) FILTER(WHERE NOT isReal) FROM read_parquet(?)',[str(dest)]).fetchone()
   expected=(sum(g['width'] for g in groups.values()),sum(g['real'] for g in groups.values()),sum(g['width']-g['real'] for g in groups.values()))
   assert actual==expected
   temporary.unlink()
   summaries[role]=dict(sourceObjects=len(self.a if role=='anchor' else self.m),indexedObjects=len({i for g in groups.values() for i in g['rows'] if i>=0}),
    logicalGroups=len(groups),nonemptyBuckets=len(metas),realPostings=actual[1],paddedPostings=actual[0],dummyPostings=actual[2],
    largestGroupRealSlots=max(g['real'] for g in groups.values()),largestGroupPadWidth=max(g['width'] for g in groups.values()),
    bucketPaddedCapacity=distribution([m['paddedSlots'] for m in metas.values()]),
    objectCapacity=distribution([m['publicObjectCapacity'] for m in metas.values()]),
    evaluationDomain=distribution([m['evaluationDomain'] for m in metas.values()]))
   for meta in metas.values():bucket_rows.append({k:v for k,v in meta.items() if k!='sourceRowsByLabel'})
  c.close()
  csvsave(f'plain_indexes/{self.name}/groups.csv',group_rows)
  csvsave(f'plain_indexes/{self.name}/buckets.csv',bucket_rows)
  self.summary=dict(context=self.name,scale=self.n,q=self.q,buckets=self.B,sides=summaries,
   plaintext_labels_checked=self.label_checks,label_out_of_range=0,capacity_violating_buckets=self.capacity,
   current_code_q_supported=self.q==4,current_manifest_bucket_bits_supported=14<=self.bits<=17,
   hash_key_status='Fixed PUBLIC plaintext profiling keys; not production secrets or outsourced indexes',
   target_semantic_objects_per_join=1,target_public_capacity_reference=26,
   target_domain_reference='Experimental zeroCapacity(D)=nextPow2(D); kernel n=nextPow2(zeroCapacity(D)+1); D26 gives 64, D16 gives 32')
  save(f'plain_indexes/{self.name}/summary.json',self.summary)

 def anchor_feature(self,word,p,tau):
  key=(word,p,tau)
  if key in self.acache:return self.acache[key]
  bucket=prefix(anchor_hash(word),self.bits);meta=self.bucket_meta['anchor'].get(bucket)
  if word not in self.groups['anchor']:mask=0;checks=0
  else:
   g=self.groups['anchor'][word];labels=set()
   for row,pos,label in zip(g['rows'],g['positions'],g['labels']):
    if row>=0 and abs(pos-p)<=tau:labels.add(label)
   ids=meta['sourceRowsByLabel'];mask=0
   for label in labels:mask|=1<<ids[label-1]
   checks=meta['publicObjectCapacity']
  if key not in self.refcache:
   reference=0
   for i,text in enumerate(self.a_text):
    lo=max(0,p-tau);hi=min(len(text)-self.q,p+tau)
    if hi>=lo and text.find(word,lo,hi+self.q)>=0:reference|=1<<i
   self.refcache[key]=reference
  assert mask==self.refcache[key],('anchor OR disagrees with direct source-string matches',key)
  result=dict(mask=mask,bucket=bucket,S=meta['paddedSlots'] if meta else 0,real=meta['realSlots'] if meta else 0,
    groups=meta['groups'] if meta else 0,D=meta['publicObjectCapacity'] if meta else 0,
    evaluation=meta['evaluationDomain'] if meta else 0,boolean_outputs_checked=meta['publicObjectCapacity'] if meta else 0)
  self.acache[key]=result;return result

 def target_feature(self,tc,word,p,tau):
  key=(tc,word,p,tau)
  if key in self.tcache:return self.tcache[key]
  if word not in self.word_digest:self.word_digest[word]=target_word_hash(word)
  bucket=prefix(self.target_join_digest[tc],self.bits)^prefix(self.word_digest[word],self.bits)
  meta=self.bucket_meta['target'].get(bucket);g=self.groups['target'].get((tc,word));labels=set()
  if g:
   for row,pos,label in zip(g['rows'],g['positions'],g['labels']):
    if row>=0 and self.m[row]['tconst']==tc and abs(pos-p)<=tau:labels.add(label)
  hit=bool(labels)
  assert labels<={1},'local target label outside source join namespace'
  text=self.m_text[self.movie_by_tc[tc]];lo=max(0,p-tau);hi=min(len(text)-self.q,p+tau)
  reference=hi>=lo and text.find(word,lo,hi+self.q)>=0
  assert hit==reference,('target OR disagrees with joined object',key)
  result=dict(hit=hit,bucket=bucket,S=meta['paddedSlots'] if meta else 0,real=meta['realSlots'] if meta else 0,
    groups=meta['groups'] if meta else 0,D=26 if meta else 0,evaluation=64 if meta else 0,
    boolean_outputs_checked=26 if meta else 0)
  self.tcache[key]=result;return result

 def unfiltered_target_slots(self,features):
  total=0
  for word,_ in features:
   if word not in self.word_digest:self.word_digest[word]=target_word_hash(word)
   w=prefix(self.word_digest[word],self.bits)
   for tc,number in self.anchor_join_counts.items():
    bucket=prefix(self.target_join_digest[tc],self.bits)^w
    meta=self.bucket_meta['target'].get(bucket)
    if meta:total+=number*meta['paddedSlots']
  return total
