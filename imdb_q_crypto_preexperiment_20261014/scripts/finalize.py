#!/usr/bin/env python3
import csv,difflib,hashlib,html,json,pathlib,platform,subprocess
from common import BASE,ROOT,FULL,OLD,sha,save,csvsave

def readcsv(path):return list(csv.DictReader((BASE/path).open(encoding='utf-8-sig')))
def fmt_table(head,rows):return '\n'.join([' | '.join(head)]+[' | '.join(map(str,x)) for x in rows])

def main():
 config=json.loads((BASE/'checks/fair_configuration.json').read_text());summary=readcsv('reports/plain_q_summary.csv')
 complete=json.loads((BASE/'checks/fair_plain_complete.json').read_text())
 before=json.loads((BASE/'checks/protected_before.json').read_text());after={}
 for label,d in [('formal',FULL),('prior_plaintext',OLD),('workload_plaintext',ROOT/'imdb_plain_workload_precheck_20261014')]:
  for p in d.rglob('*'):
   if p.is_file() and not p.is_symlink():after[label+'/'+str(p.relative_to(d))]=dict(bytes=p.stat().st_size,sha256=sha(p))
 assert before==after,'Protected official data or plaintext baseline changed'
 save('checks/protected_after.json',after);save('checks/protection.json',dict(files=len(before),all_sha256_identical=True,official_data_unchanged=True,previous_plaintext_baselines_unchanged=True))
 old_sources=json.loads((BASE/'checks/adaptation_source_before.json').read_text());diff=[];changes=[]
 for name,b in old_sources.items():
  p=ROOT/name;original=BASE/'checks/source_before'/name
  assert sha(original)==b['sha256']
  diff.extend(difflib.unified_diff(original.read_text().splitlines(True),p.read_text().splitlines(True),fromfile='before/'+name,tofile='after/'+name))
  changes.append(dict(path=name,kind='modified',before_sha256=b['sha256'],after_sha256=sha(p)))
 new_sources=['internal/qgram/qgram.go','internal/qgram/qgram_test.go','internal/scmpnative/imdb_capacity_test.go','internal/zeroagg/imdb_parameter_test.go']
 for name in new_sources:
  p=ROOT/name;diff.extend(difflib.unified_diff([],p.read_text().splitlines(True),fromfile='/dev/null',tofile='after/'+name))
  changes.append(dict(path=name,kind='added',before_sha256=None,after_sha256=sha(p)))
 (BASE/'checks/minimal_source_changes.patch').write_text(''.join(diff))
 save('checks/source_changes.json',changes)
 # Frozen read-only evidence for blocked current chain, not an executable compatibility path.
 capacity_sources=['internal/anchorindex/logical_key.go','internal/targetcrypto/canonical.go',
  'internal/indexbuild/builder.go','internal/indexbuild/target_artifact.go','internal/discovery/types.go',
  'internal/discovery/offline.go','internal/discovery/cloud.go','internal/targetquery/query.go',
  'internal/targetposition/position.go','internal/targetaggregation/sidecar.go',
  'internal/targetaggregation/gen/sidecar.go','internal/targetaggregation/protocol.go',
  'third_party/ezpc_fss/pubdiv.cpp','third_party/ezpc_fss/dcf.cpp']
 save('checks/current_sources.json',{n:dict(bytes=(ROOT/n).stat().st_size,sha256=sha(ROOT/n)) for n in capacity_sources})
 caps=[]
 for q in [3,4,5,6]:
  a,t=273-q,242-q
  width=lambda p:next(b for b in range(2,33) if p+1 < 1<<(b-1))
  caps.append(dict(q=q,anchor_max_index_position=a,target_max_index_position=t,anchor_min_Bin=width(a),target_min_Bin=width(t),
    uniform_test_Bin=10,uniform_test_Upos=270,masked_input_ring_size=1024,Bout=1,per_party_native_key_bytes=368))
 csvsave('reports/position_parameters.csv',caps)
 input_a=json.loads((BASE/'samples/n1000/MOVIECAST.json').read_text());input_m=json.loads((BASE/'samples/n1000/MOVIE.json').read_text());movie={r['tconst']:r for r in input_m}
 eligibility=[];index_rows=[]
 for q in [3,4,5,6]:
  natural={(r['aliasTitle'],movie[r['tconst']]['primaryTitle']) for r in input_a if min(len(r['aliasTitle']),len(movie[r['tconst']]['primaryTitle']))>=4*q}
  eligibility.append(dict(q=q,fixed_r=4,min_query_codepoints_both_sides=4*q,distinct_natural_real_pairs=len(natural)))
  lay=json.loads((BASE/f'plain_indexes/n1000_q{q}_B65536/summary.json').read_text())
  s=lay['sides'];index_rows.append(dict(q=q,anchor_real=s['anchor']['realPostings'],target_real=s['target']['realPostings'],
   anchor_padded=s['anchor']['paddedPostings'],target_padded=s['target']['paddedPostings'],
   total_real=sum(x['realPostings'] for x in s.values()),total_padded=sum(x['paddedPostings'] for x in s.values()),
   total_dummy=sum(x['dummyPostings'] for x in s.values()),anchor_groups=s['anchor']['logicalGroups'],target_groups=s['target']['logicalGroups'],
   max_anchor_bucket_T=s['anchor']['bucketPaddedCapacity']['max'],max_target_bucket_T=s['target']['bucketPaddedCapacity']['max'],
   labels_checked=lay['plaintext_labels_checked'],labels_out_of_range=lay['label_out_of_range'],
   scope='ACTUAL PUBLIC PLAINTEXT LAYOUT; NOT A CRYPTO INDEX OR CRYPTO STORAGE MEASUREMENT'))
 csvsave('reports/query_eligibility.csv',eligibility);csvsave('reports/plain_layout_counts.csv',index_rows)
 env=dict(platform=platform.platform(),processor_model=next((x.split(':',1)[1].strip() for x in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),''),
  go_version=subprocess.check_output([str(ROOT/'artifacts/n-domain-regression-pilot-runtime/go/bin/go'),'version'],text=True).strip(),
  native_build='Pinned in-project third_party/ezpc_fss, O3; new experiment native/libphase6scmp.a',GOMAXPROCS=2,GOMEMLIMIT='4GiB',
  purpose='Parameter correctness and public workload; not timing the full protocol')
 save('checks/environment.json',env)
 status=dict(parameter_adaptation='PARTIAL: native Bin10 and explicit q signatures tested; full main-query configuration not wired',
  new_zero_operator_unit_tests='PASS',unicode_q_unit_tests='PASS',native_Bin7_regression='PASS',native_Bin10_domain='PASS',
  production_package_build_after='PASS',production_test_package_compile='BLOCKED: stale matrix diagnostics tests',
  q_plain_exact_correctness={str(q):'PASS' for q in [3,4,5,6]},
  q_current_new_crypto_end_to_end={str(q):'NOT RUN / BLOCKED' for q in [3,4,5,6]},
  true_crypto_outsourcing_measurements='NONE',successful_crypto_repetitions=0,
  scale1000_plain_runs=True,scale1000_crypto_runs=False,scale5000_runs=False,
  default_q=4,default_status='PROVISIONAL based on limited public workload and query-length coverage; not proved optimal',
  default_supported_by_real_crypto_query_performance=False,formal_full_index_build_ready=False,
  gate='Target active pipeline still calls retired matrix; latest independent target experiment is not adopted into this workspace',
  no_old_index_builder_or_auxiliary_matrix_executed=True,no_formal_database_build_started=True)
 save('checks/final_status.json',status)
 pos=fmt_table(['q','锚最大位置','目标最大位置','锚最小Bin','目标最小Bin','本轮统一Bin/Upos'],[[r['q'],r['anchor_max_index_position'],r['target_max_index_position'],r['anchor_min_Bin'],r['target_min_Bin'],'10/270'] for r in caps])
 idx=fmt_table(['q','锚真实项','目标真实项','锚含填充项','目标含填充项','占位项总数'],[[r['q'],r['anchor_real'],r['target_real'],r['anchor_padded'],r['target_padded'],r['total_dummy']] for r in index_rows])
 workload=fmt_table(['q','查询执行数','平均匹配锚项','平均K','K最大值','平均S_B','平均路由','平均S_P','锚候选假阳性率','连接候选假阳性率'],
  [[r['q'],r['query_executions'],f"{float(r['anchorMatchedPostingItems_mean']):.3f}",f"{float(r['K_mean']):.3f}",r['K_max'],f"{float(r['S_B_mean']):.3f}",f"{float(r['routes_mean']):.3f}",f"{float(r['S_P_mean']):.3f}",f"{float(r['anchor_false_positive_ratio'])*100:.2f}%",f"{float(r['signature_false_positive_pair_ratio'])*100:.2f}%"] for r in summary])
 elig=fmt_table(['q','固定r=4时两侧查询最短长度','公共样本可用不同真实查询对数'],[[r['q'],r['min_query_codepoints_both_sides'],r['distinct_natural_real_pairs']] for r in eligibility])
 source_list='\n'.join(c['kind']+' '+c['path'] for c in changes)
 report=f'''IMDb 密码参数适配与 q 小规模预实验报告
日期：2026-10-14；独立目录：{BASE}
结论：底层位置比较适配和四种q的公平明文工作量检查已完成；完整新密码链路尚未完成适配，真实外包对比被阻塞。没有使用旧矩阵路径，没有5000条或正式全量密码构建。

第一部分：当前密码参数和有效源码检查
权威工作区：{ROOT}，HEAD 49cc443a33d11e2ea3466dd39f1797b5de2a287e；保留原有未提交修改，没有切换分支、合并、重置或改论文。
当前协议入口是internal/discovery.RunLocal、Provision、NewStatic，没有可用的完整新IMDb数据所有者构建入口。锚cloud.go实际调用ap.zero.Aggregate(x,as.Labels)，GF16零点聚合已经在当前目录；目标protocol.go仍调用incidence.NewAggregator(...side.buckets[route.BucketID].matrix...)，其sidecar.go仍保存*incidence.PartyMatrix，gen/sidecar.go仍生成矩阵。
独立目录/home/tenggn/projects/clean_pmeq-target-zero-poly-agg包含目标零点实验，但它的报告明确声明没有替换正式默认路径。它不是本轮已采用的主工作区版本，不能擅自作为已迁移生产链路，也没有使用它的旧性能数据。本轮没有合并或重新改写目标核心算子。
当前包build通过，只证明源码可编译，不代表新链路能运行；主查询测试包仍因旧HitB2A、Incidence、DenseProducts诊断字段未迁移而编译失败。保存完整编译日志，没有删除这些测试以获得通过。
q=4绑定仍存在于anchorindex/logical_key.go、targetcrypto/canonical.go、indexbuild/builder.go及TargetManifest.Validate，targetquery/query.go仍按4切片。锚域仍area/name/id，目标域仍area_alias/name/area；必须迁移到MOVIECAST/aliasTitle/tconst和MOVIE/primaryTitle/tconst并统一绑定q，不能仅换输入文件。
发现的7位/62上限也不限于原生后端：discovery/offline.go、targetposition/position.go、targetquery/query.go及封包验证还有固定7、127、62和4*h，尚未同步到本次新参数。因此四种q的当前正式密码入口都不能列为成功配置。

第二部分：准确位置域及实际最小适配
重叠索引片段的0基码点位置为0..L-q；L<q无完整片段。真实最大L为锚273、目标242。
{pos}
SCMP判断有符号差值是否非负，必须保证Upos+1<2^(Bin-1)，因为上界过滤输入R+1，而不仅是存储位置Upos。锚最大情况Upos=270，R+1≤271；Bin=9的正半域只有256，不能覆盖；Bin=10的正半域512可覆盖，故准确最小锚容量是10位。目标单独最小9位；为公平本轮统一位置Bin=10、公开Upos=270。
明文位置差值范围落在[-271,270]，处于10位有符号域[-512,511]。随机位置掩码独立均匀来自完整Z1024，不是只取明文半域；全部输入先取低10位，加掩码再模1024。Ring32加性份额到Z1024的约减合法，因为1024整除2^32。掩码后的输入可能超过255，原来的uint8 C ABI会截断，所以桥和Go声明均改成uint32。
输入位宽改变不改变FSS安全密钥长度：仍128位AES/DCF种子，Bout仍1，输出仍F2，输出随机掩码去除一次。跨块计数Z128及其7位SCMP、GF16零点聚合都保持原域，不能把所有127常量机械替换成1023。核心LLAMA/DCF数学实现未修改。
原生后端只新增所需Bin10，继续支持Bin7；没有开放未验证的所有位宽。DCF树深度从6增加到9，单方SCMP序列化密钥从284增到368字节。解析器检查Bin、Bout、DCF深度、长度及输出环，禁止异宽/越界键。新的本轮原生库单独生成在native/，后续使用新桥必须重新编译库。
用户预处理增加实际Bin绑定，ConsumeBounds拒绝与预处理位宽不同的查询位置域，避免把7位掩码用于10位令牌。
新增显式Unicode片段工具internal/qgram和anchorfilter.QueryChunksWithQ；它们支持q和固定签名数，默认入口仍保持原q4。没有偷偷更改全局Q常量或旧索引格式。签名工具的可配置不等于正式索引/令牌已完成q绑定。
修改和新增源码清单：
{source_list}
精确修改差异及逐文件前后SHA-256在checks/minimal_source_changes.patch、source_changes.json。四个被修改文件原文在checks/source_before/，不覆盖原先未提交修改。
本轮固定r=4，查询片段位置最多3q≤18，所以Upos270同时覆盖本次索引和查询。未来若使用整串的全部片段，应同时检查查询位置：例如允许比最长源串多3码点，锚q=3的末块位置可能273；此时公开Upos应至少273，Bin仍10。这一未来入口检查没有在本轮冒称已接入。

第三部分：正确性测试与公平数据
原生Bin10穷举0..271所有73,984对明文输入，每对使用独立真实密钥、完整Z1024随机掩码，且覆盖两种输出掩码；另测30对极端/环绕掩码及保守半域边界。全部通过。
四种q对应位置域的72个区间批次测试通过：含0、1、62、127、239、最大位置和τ=0、1、3；强制Ring32份额先溢出再约减，验证上下界、输出掩码和一次性消费。越界掩码1024、C输入截断风险及7/10混用拒绝测试通过。原Bin7的4096对穷举、并发/新鲜性/一次性测试仍通过。
q=3,4,5,6片段单元测试通过，含中文、emoji、组合/非ASCII码点、273码点末位置、固定r和非法UTF-8/短查询拒绝。
当前新zeroagg算子实际执行256组秘密共享OR测试，覆盖重复根、空命中、多命中、填充标签0和越界标签拒绝，结果与对象OR一致，真实一次性GF材料用量一致。这不是整条新目标密码链路验收。
正式库只读，未派生或改动。复用原n10000冻结哈希顺序池：过滤两侧真实源字符串均≥6码点，按原顺序取前1000条，目标提取对应电影，得到1000/992条。池中符合条件9373条。没有按q成功与否换数据，没有截短或伪造字符串。
四种q完全相同的记录和查询。查询全部来自旧n1000已经验证的明文基准：保留源种子在公共样本内且两侧完整查询长度≥24的288组，来自3个真实原始查询种子，含exact、substitute1、insert1、delete1、substitute2、substitute3各48组，τδ/τγ独立遍历0..3。
使用完整查询的前4个非重叠片段，不截短完整查询；所有q均有4个合法块。选取任意4个不重叠块并按至少4-τ命中进行候选判断，保留原过滤语义；完整编辑距离仍对原完整查询字符串计算。
原明文答案投影到公共样本，与本次答案完全一致（新加入样本对象带来的额外答案0）。另用独立完整动态规划逐字符串检查带阈值实现的命中判定。四种q共1152次执行，精确答案全部相同，各q总144对答案，漏报0、错误结果0、重复结果0。4个来自相同电影和标题组的不同源对象均保留；所有物化明文槽位的来源和局部标签检查通过。
重要区分：片段/原生算子/明文结果通过，正式索引与查询令牌绑定未完成；不能把后者标成通过。

第四部分：真实密码外包成本
q | 1000条完整密码外包 | 成功重复次数 | 构建/共享/保存/校验/总时间 | 通信/存储/峰值内存
3 | 未执行：当前新目标路径缺失 | 0 | N/A | N/A
4 | 未执行：当前新目标路径缺失 | 0 | N/A | N/A
5 | 未执行：当前新目标路径缺失 | 0 | N/A | N/A
6 | 未执行：当前新目标路径缺失 | 0 | N/A | N/A
未调用旧构建器、目标矩阵生成器或旧完整查询runner进行测量。不存在可重复三次的完整成功密码配置，不能输出中位数、估计时间或用明文构造时间冒充密码外包成本。缺失值是N/A而不是0。原始状态表在results/crypto_outsourcing_status.csv。
1000条的新整链前置验收未满足，因此5000条构建与对比没有开始。没有任何100000条或全量密码索引生成、规模资源推算或旧性能数据引用。
下表仅为真实源字符串生成的公开明文布局项数，用于结构分析，既不是密码索引存储字节，也不是正式外包测量：
{idx}
固定填充阶梯4/16/64/256/1024/4096/8192/16384/32768；四种q采用同一已知公开布局键、B=65536。填充前重叠项、填充占位项及实际桶均物化到plain_indexes/，与密码索引严格区分。

第五部分：相同查询下的主连接工作量
{workload}
K来自锚块命中局部标签OR，再按源对象累积≥rδ-τδ的Keep语义；它不是最终编辑距离答案数。锚匹配项按真实物理重复出现位置累计；S_B是每个锚块访问整个实际桶的含填充槽数之和，S_P是每个候选×目标块路由到的整个实际桶含填充槽数之和，重复访问重复累计，逻辑路由=4K。
公开明文实现用字典/缓存定位组以核对语义；槽数是根据实际物化桶按访问请求累计的协议输入容量，不是Python实测内存访问数。命中组之外的碰撞组和填充项也计入槽数。本轮没有宣称执行了相应密码访问或测得在线时间。
锚候选假阳性率为(总K-总锚编辑距离命中数)/总K；连接签名候选假阳性率为(总签名候选对-总精确答案对)/总签名候选对，是汇总加权比例，而非逐查询百分比简单平均。四种q连接签名候选总数均225对，最终144对，签名误报81对（36%）；经过完整编辑距离检查后误报0。
小候选不是验收门槛，全部0候选及较大候选查询保留。逐查询指标、候选对象标识和答案在results/plain_query_metrics.csv、query_details.jsonl.gz；旧明文基准完整保留。

第六部分：完整对比表及展示
reports/plain_q_summary.csv有各q的最小值、中位数、P90/P95/P99、最大值和均值；plain_layout_counts.csv保存布局结构规模；position_parameters.csv保存准确位宽；HTML报告提供K、S_B、S_P的可切换公开工作量图。
密码外包/通信/存储/查询性能均未测；公开结构和明文槽工作量是此轮唯一可用于q趋势比较的数据。测量环境和源码哈希保留，不能把诊断结果标为正式论文性能实验。
四种q样本与查询的SHA固定。此次查询仅来自3个原始种子，不能当作IMDb总体查询分布，后续应扩大代表性。

第七部分：暂定默认q建议
建议暂定q=4，保留q=3、5、6继续比较；这不是已证明整体最优，也不是正式冻结。
q3平均K=1.708、S_B=24.667、S_P=20.556，比q4的1.042/14.889/15.556高；在此公共查询集上q4明显减轻锚过滤和目标访问。
q5、q6分别将目标S_P减至14.333、14.167，但锚S_B升到15.556、15.778。只按等权槽数相加，q4=30.444、q5=29.889、q6=29.944，不能从这个很小且不能反映算子差异的间距推断速度优劣。q6公开布局总填充项较少，但真实密态存储/共享/通信成本仍未知。
固定r=4时，较大q还收缩真实查询可行域：
{elig}
本轮公平比较使用共同≥24码点查询，没有因q失败换样本。对于后续更多短标题查询，q4比q5/6在固定r下保留更宽的可用范围；若后续改变r，必须重新分析。综合较低锚访问量、相对q3的过滤收益、查询长度覆盖及缺失的真实成本，q4适合作为下一轮验证起点，不能据此声称比q5/6快。
该默认建议没有任何真实密码查询性能支持；完整外包与查询对比后可以修订。

第八部分：正式建库前阻塞与下一步最小接入范围
1. 当前目标侧仍旧矩阵路径。必须先正式接入已经独立验证的新目标零点标签、生成/读取/预处理/聚合接口，并禁止matrix fallback；这属于算子迁移，不能在本轮用旧实现凑成本数据。
2. 当前缺少完整新IMDb DO构建入口。需形成可生成锚/目标密态索引、源对象标签、全局对齐/载荷及完整性校验的统一路径，逐阶段计时和实际字节计量。
3. 引入不可变参数绑定，使q、两侧字段域、Upos、Bin同时贯穿字符签名、键派生、索引manifest、预处理、令牌、位置封包和校验；不能只改Q或后端。
4. 原生Bin10已经通过，但当前整链仍使用7/62/127固定接口；须对齐新的位置域，同时保持计数7位/F2输出/GF16算术域，勿机械全局替换。
5. 旧诊断测试需迁移到新对象命中语义，并保留有效回归；当前主查询测试包不能编译，尚无新链路小规模正确性证据。
完成这些接入后，先1000条新链路验收，再在固定数据/查询/r/阈值/桶/填充/安全参数和环境下，对每q至少三次真实构建、保存、校验分别计量；通过资源和正确性门槛后才执行5000条。本报告没有自动开始这些后续工作。

最终六问：
1. 新算子密码参数是否适配完成？部分完成：底层10位SCMP和显式片段工具已验证，整链未完成。
2. 四种q是否全部正确运行？片段与明文流程全部通过；完整新密码流程均未验收，不能答全部通过。
3. 四种q真实外包成本？均N/A，未完成，不能估计充当实测。
4. 哪个q适合主体实验？暂定q4作为验证起点，真实成本和更广查询集补齐后再确认。
5. 默认q有真实密码查询性能支持吗？没有。
6. 具备正式数据库索引构建条件吗？不具备；目标算子接入和整链参数绑定仍阻塞。

保护与复现：正式库、原明文预检和上一轮公开工作量材料共{len(before)}个文件，前后SHA-256全部一致。未改论文、未删正确性基准、未生成矩阵，没有大规模建库。源码仅修改/增加上列8个文件。
复现（项目根目录；新目录内输出）：
env PMEQ_SCMP_BUILD={BASE}/native bash tools/build_phase6_native.sh
bash imdb_q_crypto_preexperiment_20261014/scripts/run_go.sh test -tags phase6native ./internal/scmpnative ./internal/qgram ./internal/zeroagg -count=1 -v
env PYTHONDONTWRITEBYTECODE=1 imdb_final_dataset/.venv/bin/python imdb_q_crypto_preexperiment_20261014/scripts/fair_plain_q.py
env PYTHONDONTWRITEBYTECODE=1 imdb_final_dataset/.venv/bin/python imdb_q_crypto_preexperiment_20261014/scripts/finalize.py
主查询旧测试编译阻塞复现：bash imdb_q_crypto_preexperiment_20261014/scripts/run_go.sh test -tags phase6native ./internal/discovery -run '^$'
本轮结束，不自动启动正式构建。
'''
 (BASE/'reports/IMDb密码参数适配与q预实验报告.txt').write_text(report)
 chart=[dict(q=int(r['q']),K=float(r['K_mean']),S_B=float(r['S_B_mean']),S_P=float(r['S_P_mean'])) for r in summary]
 document='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>IMDb q参数预实验</title><style>body{max-width:1100px;margin:35px auto;padding:0 20px;font:15px system-ui,sans-serif;color:#173145;background:#f8fafc}pre{white-space:pre-wrap;line-height:1.7;font:inherit}.chart{background:white;border:1px solid #ccd7e0;padding:20px;border-radius:8px}.row{display:flex;align-items:center;gap:12px;margin:15px 0}.label{width:40px}.track{flex:1;background:#e8eef3;height:22px}.bar{height:100%;background:#187aa0}.value{width:90px}select{padding:8px}small{color:#526474}</style><body><h1>IMDb q参数预实验</h1><div class="chart"><strong>公开明文工作量：相同1000/992条记录、288组查询、r=4、B=65536</strong><p><select id="metric"><option value="K">K：平均锚候选对象数</option><option value="S_B">S_B：平均锚访问填充槽数</option><option value="S_P">S_P：平均目标访问填充槽数</option></select></p><div id="bars"></div><small>这是物化桶容量的逻辑累计，非密码查询时间。完整密码外包未完成；3个原始查询种子不足以代表总体查询分布。</small></div><pre>'''+html.escape(report)+'''</pre><script>const data='''+json.dumps(chart)+''';const sel=document.getElementById('metric');function render(){const metric=sel.value,max=Math.max(...data.map(x=>x[metric]));document.getElementById('bars').innerHTML=data.map(x=>'<div class="row"><span class="label">q='+x.q+'</span><div class="track"><div class="bar" style="width:'+(100*x[metric]/max)+'%"></div></div><span class="value">'+x[metric].toFixed(3)+'</span></div>').join('');}sel.onchange=render;render();</script></body></html>'''
 (BASE/'reports/IMDb密码参数适配与q预实验报告.html').write_text(document)
 (BASE/'README.txt').write_text('结果：底层Bin10适配和公平明文q对比通过；完整新密码链路未接入，外包成本未测。\n报告 reports/IMDb密码参数适配与q预实验报告.html\n源码差异 checks/minimal_source_changes.patch；测试 logs/parameter_tests.log\n公开逐查询工作量 results/plain_query_metrics.csv；真实外包状态 results/crypto_outsourcing_status.csv\n暂定q4，未得到密码查询性能支持；未开始5000条或正式全量密码构建。\n')
 save('artifact_manifest.json',{str(p.relative_to(BASE)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(BASE.rglob('*')) if p.is_file() and p.name!='artifact_manifest.json' and 'cache' not in p.relative_to(BASE).parts and 'tmp' not in p.relative_to(BASE).parts})
 print('FINAL_REPORT_COMPLETE protected_files',len(before),'plain_queries',complete['query_executions'],'crypto_costs','N/A','recommendation','provisional q4')

if __name__=='__main__':main()
