#!/usr/bin/env python3
"""Summarize public workload counters and audit provenance; no protocol execution."""
import collections,csv,gzip,html,json,pathlib
from common import BASE,FULL,OLD,Q_VALUES,SEED,csvsave,save,sha,distribution

def readcsv(p):
 return list(csv.DictReader((BASE/p).open(encoding='utf-8-sig')))

def summarize(rows,axis,setting):
 out=dict(axis=axis,setting=setting,legal_query_executions=len(rows),nonempty_exact_queries=sum(int(x['exactResultPairCount'])>0 for x in rows))
 for field in ['K','S_B','S_P','routes','exactResultPairCount','signatureCandidatePairCount','anchorEvaluationDomainTotal','targetEvaluationDomainTotal']:
  for k,v in distribution([int(x[field]) for x in rows]).items():
   if k!='count':out[field+'_'+k]=v
 out['candidate_retention_mean']=sum(float(x['candidateRetentionRate']) for x in rows)/len(rows)
 out['S_P_ratio_to_all_anchor_routing']=sum(int(x['S_P']) for x in rows)/sum(int(x['targetSlotsWithoutAnchorFiltering']) for x in rows)
 out['S_P_ratio_to_full_target_per_chunk']=sum(int(x['S_P']) for x in rows)/sum(int(x['targetSlotsFullTablePerChunk']) for x in rows)
 return out

def table(headers,rows):
 return '\n'.join([' | '.join(map(str,headers))]+[' | '.join(map(str,row)) for row in rows])

def main():
 complete=json.loads((BASE/'checks/run_complete.json').read_text());metrics=readcsv('results/all_query_metrics.csv')
 assert len(metrics)==complete['total_mathematically_legal_query_executions']
 shared=[x for x in metrics if x['family']=='shared_real_queries']
 axes=[]
 for n in [1000,5000,10000]:axes.append(summarize([x for x in shared if int(x['N_anchor'])==n and int(x['q'])==4 and int(x['B'])==65536],'N',n))
 for q in Q_VALUES:axes.append(summarize([x for x in shared if int(x['N_anchor'])==10000 and int(x['q'])==q and int(x['B'])==65536],'q',q))
 for b in [1024,4096,16384,65536,131072]:axes.append(summarize([x for x in shared if int(x['N_anchor'])==10000 and int(x['q'])==4 and int(x['B'])==b],'B',b))
 for family,axis in [('r_delta_axis','r_delta'),('r_gamma_axis','r_gamma')]:
  subset=[x for x in metrics if x['family']==family]
  for r in sorted({int(x['horizontal_r']) for x in subset}):axes.append(summarize([x for x in subset if int(x['horizontal_r'])==r],axis,r))
 csvsave('reports/four_axes_summary.csv',axes)
 common=readcsv('results/q_axis_common_legal_queries.csv')
 common_summary=[summarize([x for x in common if int(x['q'])==q],'q_common_queries',q) for q in Q_VALUES]
 csvsave('reports/q_axis_same_queries_summary.csv',common_summary)
 layouts=json.loads((BASE/'checks/plain_layouts.json').read_text());index_rows=[]
 for layout in layouts:
  for role,s in layout['sides'].items():
   index_rows.append(dict(context=layout['context'],role=role,sourceObjects=s['sourceObjects'],indexedObjects=s['indexedObjects'],
    noCompleteQgramObjects=s['sourceObjects']-s['indexedObjects'],logicalGroups=s['logicalGroups'],realPostings=s['realPostings'],
    dummyPostings=s['dummyPostings'],paddedPostings=s['paddedPostings'],nonemptyBuckets=s['nonemptyBuckets'],
    largestGroupPadWidth=s['largestGroupPadWidth'],maxBucketPaddedCapacity=s['bucketPaddedCapacity']['max'],
    p95BucketPaddedCapacity=s['bucketPaddedCapacity']['p95'],maxObjectCapacity=s['objectCapacity']['max'],
    maxEvaluationDomain=s['evaluationDomain']['max'],labelsOutOfRange=layout['label_out_of_range']))
 csvsave('reports/plain_index_capacity_summary.csv',index_rows)
 flags=collections.Counter(f for x in metrics for f in x['currentCodeLimitFlags'].split(';') if f)
 save('checks/current_limit_counts.json',dict(query_level_diagnostic_counts=dict(flags),all_queries=len(metrics),
  all_queries_have_long_source_position_flag=True,scope='Static limits only. No native or crypto test and no performance verdict.'))

 # Verify saved access records against actual materialized bucket capacities and source namespaces.
 buckets={}
 for layout in layouts:
  bs=list(csv.DictReader((BASE/'plain_indexes'/layout['context']/'buckets.csv').open(encoding='utf-8-sig')))
  buckets[layout['context']]={(r['role'],int(r['bucket'])):r for r in bs}
 sources={}
 for n in [1000,5000,10000]:
  a=json.loads((BASE/f'samples/n{n}/MOVIECAST.json').read_text());m=json.loads((BASE/f'samples/n{n}/MOVIE.json').read_text())
  sources[n]=({r['objectId']:r for r in a},{r['objectId']:r for r in m})
 audited=nonempty=0
 with gzip.open(BASE/'results/query_details.jsonl.gz','rt',encoding='utf-8') as f:
  for line in f:
   x=json.loads(line);a,m=sources[x['N_anchor']];bs=buckets[x['context']]
   assert x['K']==len(x['anchorCandidateObjectIds'])==len(set(x['anchorCandidateObjectIds']))
   assert all(i in a for i in x['anchorCandidateObjectIds'])
   assert x['routes']==x['K']*x['r_gamma']
   SB=SP=EA=EP=routes=0
   for access in x['anchorAccesses']:
    actual=bs.get(('anchor',access['bucket']));T=int(actual['paddedSlots']) if actual else 0
    domain=int(actual['evaluationDomain']) if actual else 0
    assert access['paddedItems']==T and access['evaluationDomain']==domain
    SB+=T;EA+=domain
   for access in x['targetBucketInvocations']:
    actual=bs.get(('target',access['bucket']));T=int(actual['paddedSlots']) if actual else 0
    domain=int(actual['evaluationDomain']) if actual else 0
    assert access['paddedItemsPerInvocation']==T and access['evaluationDomainPerInvocation']==domain
    SP+=T*access['invocations'];EP+=domain*access['invocations'];routes+=access['invocations']
   assert (SB,SP,EA,EP,routes)==(x['S_B'],x['S_P'],x['anchorEvaluationDomainTotal'],x['targetEvaluationDomainTotal'],x['routes'])
   for name,count in [('signatureCandidatePairs','signatureCandidatePairCount'),('exactAnswerPairs','exactResultPairCount')]:
    pairs=x[name];assert len(pairs)==x[count]
    assert len({(p['anchorObjectId'],p['targetObjectId']) for p in pairs})==len(pairs)
    for pair in pairs:
     assert pair['anchorObjectId'] in a and pair['targetObjectId'] in m
     assert a[pair['anchorObjectId']]['tconst']==m[pair['targetObjectId']]['tconst']
   audited+=1;nonempty+=bool(x['exactAnswerPairs'])
 assert audited==len(metrics)
 save('checks/saved_trace_audit.json',dict(query_traces_audited=audited,nonempty_exact_queries=nonempty,
  materialized_bucket_capacity_counters_consistent=True,object_identifiers_and_join_namespaces_consistent=True,
  source_objects_not_merged=True,access_count_unit='Whole materialized padded bucket per occurrence and candidate route; repeated visits charged repeatedly'))
 print('TRACE_AUDIT_COMPLETE',audited,flush=True)

 # All official files and prior verified plaintext deliverables must be byte-identical.
 before=json.loads((BASE/'checks/protected_inputs_before.json').read_text());after={}
 for root,label in [(FULL,'formal'),(OLD,'prior_plaintext')]:
  for p in root.rglob('*'):
   if p.is_file() and not p.is_symlink():after[label+'/'+str(p.relative_to(root))]=dict(bytes=p.stat().st_size,sha256=sha(p))
 save('checks/protected_inputs_after.json',after)
 changed=[p for p in before.keys()&after.keys() if before[p]!=after[p]]
 added=sorted(after.keys()-before.keys());removed=sorted(before.keys()-after.keys())
 assert not changed and not added and not removed,(changed,added,removed)
 save('checks/protected_input_integrity.json',dict(protected_files=len(before),protected_bytes=sum(x['bytes'] for x in before.values()),
  all_sha256_identical=True,changed_paths=changed,added_paths=added,removed_paths=removed,
  formal_database_and_prior_plaintext_materials_unchanged=True))
 print('PROTECTED_INPUT_HASHES_UNCHANGED',len(before),flush=True)

 full=json.loads((BASE/'checks/full_database_narrow_stats.json').read_text());samples=json.loads((BASE/'checks/samples_and_legality.json').read_text())
 baseline=next(x for x in layouts if x['context']=='n10000_q4_B65536')
 source_files=['internal/indexbuild/builder.go','internal/anchorfilter/filter.go','internal/aggregation/compare.go',
  'internal/discovery/types.go','internal/indexbuild/target_artifact.go','internal/scmpnative/native.go',
  'internal/zeroagg/labels.go','internal/zeroagg/kernel.go','internal/targetaggregation/sidecar.go',
  '../clean_pmeq-target-zero-poly-agg/internal/targetaggregation/zero_labels.go']
 save('checks/readonly_capacity_source_snapshot.json',{p:dict(bytes=(BASE.parent/p).stat().st_size,sha256=sha(BASE.parent/p)) for p in source_files})
 def axis_table(axis,rows=axes):
  return table(['设置','合法执行数','非空查询数','K均值','K中位数','K最大值','S_B均值','S_P均值','路由均值'],
    [[x['setting'],x['legal_query_executions'],x['nonempty_exact_queries'],f"{x['K_mean']:.3f}",x['K_p50'],x['K_max'],f"{x['S_B_mean']:.3f}",f"{x['S_P_mean']:.3f}",f"{x['routes_mean']:.3f}"] for x in rows if x['axis']==axis])
 lengthtable=table(['字段','记录数','长度最小/最大','P05/P50/P95/P99','均长'],
  [[t+'.'+('aliasTitle' if t=='MOVIECAST' else 'primaryTitle'),s['total_records'],f"{s['min']}/{s['max']}",f"{s['p05']}/{s['p50']}/{s['p95']}/{s['p99']}",f"{s['mean']:.3f}"] for t,s in full['strings'].items()])
 indextable=table(['侧','真实项','填充占位项','含填充总项','逻辑组','非空桶','最大桶T','最大D','最大求值域'],
  [[role,s['realPostings'],s['dummyPostings'],s['paddedPostings'],s['logicalGroups'],s['nonemptyBuckets'],s['bucketPaddedCapacity']['max'],s['objectCapacity']['max'],s['evaluationDomain']['max']] for role,s in baseline['sides'].items()])
 sampletable=table(['锚对象数','目标对象数/连接键数','匹配对象数','重复键和标题组内保留对象数'],
  [[x['anchor_objects'],x['target_objects'],x['matching_records'],x['preserved_repeated_source_objects']] for x in samples['scales']])
 rsets={fam:sorted({int(x['horizontal_r']) for x in metrics if x['family']==fam}) for fam in ['r_delta_axis','r_gamma_axis']}
 flagtable=table(['容量诊断','影响执行数（可以重叠）'],sorted(flags.items()))
 report=f'''IMDb 主连接查询明文工作量预检报告
日期：2026-10-14；随机种子：{SEED}
正式库：{FULL}/data/imdb_final.duckdb（只读）

一、结论与验收范围
本轮指定查询的数据库支持性、明文倒排分桶、候选路由及聚合语义正确性通过。
实际完成13个参数配置、{len(metrics):,}次数学合法查询；{nonempty:,}次查询得到非空精确答案。
聚合对象命中集合与独立的源字符串特征判断一致，正确率100%；局部标签越界0；精确答案遗漏0。
这一结论针对数据库和明文工作量预检。当前实现的固定q/r/位置等边界另列，不意味着任意参数均能直接进入密码实验。
没有运行秘密共享、密码索引外包、辅助矩阵、秘密乘法、乘积树或FFT，没有开展新的密码性能测试。
正式数据与原有明文预检共{len(before):,}个文件逐文件SHA-256一致，没有修改论文或协议源码。

固定查询：
ED(MOVIECAST.aliasTitle,Qδ) ≤ τδ；ED(MOVIE.primaryTitle,Qγ) ≤ τγ；MOVIECAST.tconst = MOVIE.tconst。
两个字符串查询分别作用于各自属性，没有要求aliasTitle与primaryTitle相互相似。

二、八项最低要求及输出
1. 两表连接：锚表41,286,264个对象；目标表759,363条。锚表525,080个不同tconst均在目标表中存在；匹配41,286,264条，悬空0。一个电影最多15,456个合法锚对象。
2. 字符串：两侧无NULL和空串，Unicode码点长度完整直方图见reports/string_length_histograms.csv。没有改变大小写、规范化或截短源字符串。
{lengthtable}
3. 查询特征：完整查询的非重叠q块，r=floor(码点长度/q)，r≥1且0≤τ<r。对一对查询，q≤min(|Qδ|,|Qγ|)，τδ<rδ且τγ<rγ。全表单侧最长字符串给出的上界分别273和242，这并不表示所有字符串或连接对均支持这些q。q=1时所有非空字符串均有特征。本轮q=1,2,3,4,5,6,8，按实际长度逐项判断合法性。源对象数、不同查询字符串数、不同双侧查询对数分别统计；见legal_queries_by_r.csv与legal_real_query_pairs.csv，包含r=0的不可行情况。
4. 数据规模：复用冻结的嵌套哈希样本，三档真实等值连接全部保留；目标侧规模自然独立于锚侧，没有强制相等。
{sampletable}
5. 索引构造：全部13个配置实际物化了公开明文倒排项、填充占位项、逻辑组和桶，逐条校验来源位置与标签；没有调用正式密码构建器。详细逐桶数据及两侧parquet在plain_indexes/。q=4、B=65,536、N=10,000时：
{indextable}
6. 锚侧过滤：每个查询块在位置±τ内查找，按局部标签OR，再按全局源对象累计块命中，命中块数≥rδ-τδ才保留。K是这个特征过滤候选数，K/N是候选保留率，K不是精确编辑距离答案数。K可以是0，也可以很大，没有设强制通过阈值。详细分位数见four_axes_summary.csv。
7. 目标检索：逐候选对象按其真实tconst路由每个目标查询块，路由次数=K×rγ；同一电影的多个合法锚对象分别计费、分别输出对象对。重复路由不会合并成一条结果。S_P、路由次数、真实/占位项、非空/不同访问桶和求值域均已保存。
8. 聚合正确性：标签OR得到的源对象集合与直接在源字符串中搜索块的参考实现一致；Keep另以普通逐对象计数复核。目标侧按tconst命名空间检查，局部标签1不会合并不同电影。精确答案在双侧特征候选之后再应用双侧完整编辑距离谓词，并与直接明文全对象谓词及连接形成的答案对比。签名过滤可能有误报，见signatureFalsePositivePairs；不能将签名候选直接当作精确答案。{len(metrics):,}次查询全部通过上述检查。正确答案保留原始anchorObjectId、targetObjectId。

三、四个横轴的实际设置与结果
共有13个唯一配置，基线配置在横轴之间复用。每次配置前都检查可用内存/磁盘，见checks/resources/，没有资源不足或截断。
共享查询来自1,000档按冻结源对象顺序最前24组不同真实双侧标题，无任何K筛选。每组有原查询及两侧各替换首个码点的查询版本，各自遍历τδ、τγ=0,1,2,3。源数据不改动，查询只保留满足τ<r的组合，非法组合显式记录。
以下合法数为执行次数，含阈值和查询版本。4,574个不合法设置已记录，其原因是无完整q块或τ≥r；它们不是失败答案，也没有计入正确率。r分层在共享查询之外增加真实查询。

N轴：q=4，B=65,536，三档使用相同446组合法查询。
{axis_table('N')}

q轴：N=10,000，B=65,536。不同q的合法查询数量不同，因此此表展示可行域及工作量，不能直接拿各行均值判断q的因果效果。
{axis_table('q')}
另有144组查询在全部7种q下均合法，提供同查询对照：
{axis_table('q_common_queries',common_summary)}
共同查询明细见results/q_axis_common_legal_queries.csv，汇总见reports/q_axis_same_queries_summary.csv。

B轴：固定N=10,000，q=4，相同446组合法查询。每个查询的候选对象ID和精确答案在5种桶数下完全一致。
{axis_table('B')}

r轴：固定N=10,000，q=4，B=65,536；完整真实查询按自然块数分层，每档最多选取哈希顺序最前3个不同真实查询对，没有截短查询，也没有为了达到特定K而选种子。
锚r实际档次：{rsets['r_delta_axis']}；完成1,628次合法执行。
目标r实际档次：{rsets['r_gamma_axis']}；完成1,596次合法执行。
每档不同r对应多少源对象/不同查询以及全部合法τ范围见legal_queries_by_r.csv；试跑数量与K/S_B/S_P见four_axes_summary.csv。
另一侧r随真实配对字符串记录；此探索分层用于确认可行性，不是已经固定论文中的r控制变量实验。

四、K、S_B、S_P及求值域的计量规则
所有倒排项来自实际源字符串的重叠q-gram，保存原码点位置。锚逻辑组按word，目标按(tconst,word)，填充到当前公开阶梯[4,16,64,256,1024,4096,8192,16384,32768]，占位项label=0，real=false。
S_B = 每个锚查询块访问的整个实际桶含填充容量之和。
S_P = 每个保留源候选×每个目标查询块路由到的整个实际桶含填充容量之和。
重复块、重复桶、同电影的不同候选均重复累计。空桶为0；真实项与占位项分别记录。没有只统计命中q-gram的组而漏计碰撞组。
公开明文执行使用字典/缓存定位匹配组以快速检查语义；S_B/S_P按保存的真实桶容量逐访问累计，不是Python实际触碰的内存次数或实测密码指令数。独立保存轨迹审计逐项对照物化桶容量、来源和连接，全部一致。这里的工作量可以用于后续算子输入容量规划，不能解释为已测得执行时间。
分桶以已知公开固定HMAC键确定，与实现的锚侧域分离和目标join XOR word路由形式一致，详见scripts/common.py。这些键用于公开可复现布局，不是生产秘密；不同生产密钥可能改变具体碰撞容量。
锚桶标签对真实源对象从1开始，D=nextPow2(桶中不同对象数)，标签0留给占位项；所访问求值域容量按nextPow2(D+1)逐次累计。
目标表每个tconst只有一个对象，按连接命名空间标签1，公开目标容量参考D_target=26。实验零点实现先nextPow2(D)，再nextPow2(D+1)，因此D_target=26对应求值域64；D_target=16的替代容量32也单列。这只是公开容量记录，没有运行多项式构造、求值或FFT；采用哪种公开容量尚未替论文定案。
results/all_query_metrics.csv记录每次访问的域总量及最大值；query_details.jsonl.gz保存具体访问桶、调用次数、候选源ID及精确答案，支持重算。

五、是否有性能优势：当前能判断什么
N=10,000、q=4、B=65,536共享查询中，平均K=28.706，中位数1，最大1,144；平均保留率0.2871%。总体平均S_P相对“相同查询块、不做锚过滤、对全部锚对象路由”的访问容量比例为0.23185%；相对“每个目标查询块扫一次目标全部填充项”的比例为0.03561%。这些是同一公开布局下的容量比较，完整结果及逐查询比率都保留，不以低候选率为通过条件。
固定同样的查询时，B从1,024升至131,072，平均S_B从2,406.511降至908.126，平均S_P从44,046.197降至440.188，K与精确答案完全不变，说明碰撞容量会影响路由工作量。
这提供候选驱动检索和增加桶数减少碰撞访问的机会；不能由此声称有多少倍实际加速。真实优势还取决于锚侧开销、路由代价、空桶处理、每桶求值域、通信和算子实现。后续正式性能实验应保持同查询与明确基线，报告总耗时及通信；本轮没有运行这些实验。

六、当前实现的边界与最小修复方向（只读诊断）
{flagtable}
全部配置没有单组填充超阶梯，也没有T>65,536、D>32,768或桶内局部标签越界；详见plain_index_capacity_summary.csv、plain_layouts.json。
当前构建器q固定4；锚Threshold限制r≤14；目标旧接口查询次数上限16。q探索和r长查询可在明文执行，但当前接口需参数化或明确声明可行查询域后才能采用。没有使用旧辅助矩阵作为此次容量或正确性判据。
B=1,024/4,096低于当前正式artifact的14..17位桶参数约束；B=16,384/65,536/131,072在该约束内。低B探索保留为工作量对照，不能直接交给该artifact编码器。
当前位置比较native Bin=7、Upos≤62；三档样本在q=4的最大索引位置分别75、80、89，超过62。全库最长aliasTitle=273，若q=4则位置最高269；primaryTitle=242则最高238。必须支持相应位置域或制定明确且不丢弃合法源对象的处理规则。仅修改Upos常量不能证明修复，因为native的Bin支持也必须对齐。应单独修复位置范围并以长字符串验证，不删除长标题、不截短、不改变全量库。
锚侧语义OR和目标侧语义OR均经明文验证；这是零点聚合预期的对象命中语义检查，不是当前秘密算子的测试。正式接口完成位置与参数边界对齐后，再安排受控的小规模密码正确性验证。

七、保存与复现
新增文件全部位于{BASE}，原有三档各960组查询/答案、16阈值组合及独立编辑距离一致性材料均原样保留在旧目录。
直接读取倒排项：DuckDB read_parquet('plain_indexes/<配置>/anchor_postings.parquet')；目标对应target_postings.parquet。objectRow是同配置samples/n*/JSON数组的0基序号，groupOrdinal连接groups.csv，bucket连接buckets.csv，正式源objectId从JSON映射，dummy对象序号=-1。
真实查询与答案：results/query_details.jsonl.gz逐行JSON；K、路由和容量：results/all_query_metrics.csv。
复现命令（在项目根目录；只写本次独立预检目录）：
env PYTHONDONTWRITEBYTECODE=1 imdb_final_dataset/.venv/bin/python imdb_plain_workload_precheck_20261014/scripts/inspect_data.py
env PYTHONDONTWRITEBYTECODE=1 imdb_final_dataset/.venv/bin/python imdb_plain_workload_precheck_20261014/scripts/run_workload.py
env PYTHONDONTWRITEBYTECODE=1 imdb_final_dataset/.venv/bin/python imdb_plain_workload_precheck_20261014/scripts/finalize_report.py
报告不包含秘密操作时间或旧版性能数字，没有估算十万条密码索引开销。
'''
 (BASE/'reports/主连接查询明文工作量预检报告.txt').write_text(report)
 html_doc='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>IMDb 主连接查询明文工作量预检</title><style>body{max-width:1150px;margin:36px auto;padding:0 20px;font-family:system-ui,"Microsoft YaHei",sans-serif;color:#172b3a;background:#f9fbfd}pre{white-space:pre-wrap;line-height:1.7;font-family:inherit;font-size:15px}a{color:#1260a0}</style><body><pre>'+html.escape(report)+'</pre></body></html>'
 (BASE/'reports/主连接查询明文工作量预检报告.html').write_text(html_doc)
 (BASE/'README.txt').write_text('本目录是公开明文工作量预检，未构建密码索引或辅助矩阵。\n先读 reports/主连接查询明文工作量预检报告.html。\n逐查询指标 results/all_query_metrics.csv；查询与正确答案 results/query_details.jsonl.gz；四轴汇总 reports/four_axes_summary.csv。\n物化的公开明文倒排项与桶在plain_indexes/；输入来源ID映射在samples/；固定种子20261014。\n正式全量数据库与旧明文材料均未修改，见checks/protected_input_integrity.json。\n数据和明文语义通过，当前位置上限及q/r参数仍需在正式密码实验前对齐。\n')
 save('artifact_manifest.json',{str(p.relative_to(BASE)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(BASE.rglob('*')) if p.is_file() and p.name!='artifact_manifest.json'})
 print('REPORT_COMPLETE',json.dumps(dict(contexts=13,legal_queries=len(metrics),nonempty_queries=nonempty,files_preserved=len(before)),ensure_ascii=False),flush=True)

if __name__=='__main__':main()
