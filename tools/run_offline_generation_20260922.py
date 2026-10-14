#!/usr/bin/env python3
"""Only the three authorized generation microbenchmarks. Never overwrites results."""
import csv,hashlib,json,os,platform,shutil,statistics as st,subprocess,time,math
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/paper-evaluation-20260922/offline-generation'
OLD=ROOT/'artifacts/n-domain-regression-pilot-runtime'
MIB=1024**2

def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def put(name,v):
 with (OUT/name).open('x') as f:f.write(v if isinstance(v,str) else json.dumps(v,ensure_ascii=False,indent=2)+'\n')
def quant(v,p):
 v=sorted(v);a=(len(v)-1)*p;i=int(a);return v[i]+(v[min(i+1,len(v)-1)]-v[i])*(a-i)
def stat(v):return dict(mean=st.mean(v),median=quant(v,.5),P95=quant(v,.95),P99=quant(v,.99),min=min(v),max=max(v))
def csvout(name,rows):
 with (OUT/name).open('x',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
def rows(name):return [json.loads(x) for x in (OUT/name).read_text().splitlines()]
def table(rows,fields):
 def f(x):return f'{x:.6f}' if isinstance(x,float) else str(x)
 return '| '+' | '.join(fields)+' |\n|'+'|'.join(['---']*len(fields))+'|\n'+'\n'.join('| '+' | '.join(f(r[k]) for k in fields)+' |' for r in rows)
def main():
 if OUT.exists():raise SystemExit('Refuse existing output directory')
 OUT.mkdir();(OUT/'runtime').mkdir()
 sources=[p for p in (ROOT/'internal').rglob('*') if p.is_file()]+[ROOT/'go.mod',ROOT/'go.sum',Path(__file__)]
 protected={str(p.relative_to(ROOT)):digest(p) for p in sources}
 for d in ['results/paper-evaluation-20260922','results/database-scalability-analysis-20260922','results/timing-calibration-20260920']:
  for p in (ROOT/d).rglob('*'):
   if p.is_file() and OUT not in p.parents:protected[str(p.relative_to(ROOT))]=digest(p)
 put('preservation-before.json',protected)
 for name,args in [('git-head.txt',['rev-parse','HEAD']),('git-status.txt',['status','--short']),('git-diff-stat.txt',['diff','--stat'])]:put(name,subprocess.check_output(['git',*args],cwd=ROOT,text=True))
 runtime=OUT/'runtime'
 for n in ['cache','tmp','modcache','gopath']:(runtime/n).mkdir()
 for mod,ver in [('github.com/gtank/ristretto255','v0.2.0'),('filippo.io/edwards25519','v1.1.0')]:
  dest=runtime/'modcache'/f'{mod}@{ver}';dest.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(OLD/'modcache'/f'{mod}@{ver}',dest)
  dest=runtime/'modcache/cache/download'/mod;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(OLD/'modcache/cache/download'/mod,dest)
 env={k:v for k,v in os.environ.items() if not k.startswith(('PMEQ_','GO','CGO_'))}
 env.update(GOROOT=str(OLD/'go'),GOPATH=str(runtime/'gopath'),GOMODCACHE=str(runtime/'modcache'),GOCACHE=str(runtime/'cache'),GOTMPDIR=str(runtime/'tmp'),TMPDIR=str(runtime/'tmp'),GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',GOENV='off',GOMAXPROCS='32',GOGC='100',GOMEMLIMIT='off',GODEBUG='',CGO_ENABLED='1',GOAMD64='v1',CGO_LDFLAGS=f'-L{OLD / "native"} -lphase6scmp -lcrypto -pthread',PMEQ_OFFLINE_ROOT=str(ROOT),PMEQ_OFFLINE_OUTPUT=str(OUT),PMEQ_OFFLINE_AREA='/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area')
 go=str(OLD/'go/bin/go');binary=runtime/'offline-generation.test'
 cpu=Path('/proc/cpuinfo').read_text();memory=Path('/proc/meminfo').read_text();native=OLD/'native/libphase6scmp.a'
 calibration=json.loads((ROOT/'results/timing-calibration-20260920/environment.json').read_text())
 assert digest(Path(env['PMEQ_OFFLINE_AREA']))==calibration['raw_sha256']['area']
 assert digest(native)==json.loads((ROOT/'results/global-scale-environment.json').read_text())['native_library_sha256']
 params=json.loads((ROOT/'results/paper-evaluation-20260922/provenance/frozen-parameters.json').read_text())
 assert [params[k] for k in ['q','AnchorBucketBits','TargetBucketBits','SCMPBin','SCMPBout','TargetRecordDomain']]==[4,16,16,7,1,26]
 metadata=dict(started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),os=platform.platform(),uname=list(platform.uname()),cpu=next(x for x in cpu.splitlines() if x.startswith('model name')),cpu_count=os.cpu_count(),affinity=sorted(os.sched_getaffinity(0)),memory=memory,go=subprocess.check_output([go,'version'],env=env,text=True).strip(),environment={k:v for k,v in env.items() if k.startswith(('GO','CGO','PMEQ_'))},parameters=params,native_sha256=digest(native),source_sha256={str(p.relative_to(ROOT)):digest(p) for p in sources},calibration_os=calibration['uname'],calibration_cpu=calibration['cpu_model'],calibration_runtime=calibration['runtime_env'],differences='New isolated test binary/package and cache/tmp paths; same retained Go1.27.1, native library, GOMAXPROCS32/GOGC100/GOMEMLIMIT off. Pre-timer GC for batch/Exact-K; no resident database. Single dealer generation, not concurrent online clouds. Historical memory availability cannot be equated to current.',stop_policy='stop if generation>60s, MemAvailable<2GiB, swap-in/out increase, correctness error, nonzero exit; no automatic retries or reduced repeats')
 put('environment.json',metadata)
 with (OUT/'build.log').open('x') as f:subprocess.run([go,'test','-tags','phase6native','-c','-o',str(binary),'./internal/offlinegeneration'],cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 put('binary.json',{'path':str(binary),'sha256':digest(binary),'native_sha256':digest(native),'build_info':subprocess.check_output([go,'version','-m',str(binary)],env=env,text=True)})
 def swap():return {l.split()[0]:int(l.split()[1]) for l in Path('/proc/vmstat').read_text().splitlines() if l.split()[0] in ['pswpin','pswpout']}
 executions=[]
 def run(name,test,**extra):
  print('RUN',name,flush=True);e=dict(env,**extra);before=swap();start=time.time()
  with (OUT/(name+'.log')).open('x') as f:
   result=subprocess.run([str(binary),f'-test.run=^{test}$','-test.v','-test.count=1','-test.timeout=90m'],cwd=ROOT,env=e,stdout=f,stderr=subprocess.STDOUT)
  after=swap();record={'name':name,'exit':result.returncode,'wall_seconds':time.time()-start,'swap_before':before,'swap_after':after,'extra_env':extra};executions.append(record);put(name+'-execution.json',record)
  if result.returncode or after!=before:raise RuntimeError('STOP; failure or paging evidence in '+name)
  print('PASS',name,f'{time.time()-start:.2f}s',flush=True)
 run('shape-census','TestOfflineGenerationShapes')
 run('dpf-single','TestOfflineDPFGeneration')
 run('scmp-single','TestOfflineSCMPGeneration',PMEQ_OFFLINE_LEVEL='single')
 for n in [120071,250000,500000,1000000]:run(f'exact-{n}-pilot','TestOfflineExactPreprocessing',PMEQ_OFFLINE_N=str(n),PMEQ_OFFLINE_PILOT='1')
 put('pilot-gate.json',{'status':'passed','all_four_exact_pilots_before_formal':True,'pilots':[rows(f'exact-{n}-pilot-raw.jsonl')[0] for n in [120071,250000,500000,1000000]]})
 for level in ['median','p95','max']:run('scmp-'+level,'TestOfflineSCMPGeneration',PMEQ_OFFLINE_LEVEL=level)
 for n in [120071,250000,500000,1000000]:run(f'exact-{n}','TestOfflineExactPreprocessing',PMEQ_OFFLINE_N=str(n))
 summarize()
 changed=[p for p,h in protected.items() if not (ROOT/p).exists() or digest(ROOT/p)!=h]
 put('preservation-after.json',{'checked':len(protected),'changed':changed});assert not changed
 put('completed.json',{'status':'passed','executions':executions,'experiments':'DPF generation, SCMP generation, Exact-K preprocessing only','finished_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})
 put('result-sha256.json',{str(p.relative_to(OUT)):digest(p) for p in OUT.iterdir() if p.is_file()})
 print('ALL COMPLETE',OUT,flush=True)

def summarize():
 paper=[]
 for kind in ['dpf','scmp']:
  raw=rows(f'{kind}-single-raw.jsonl');meas=[r for r in raw if r['Phase']=='measured'];assert len(meas)==1000 and len(raw)==1100
  assert all(r['Nanoseconds']>0 for r in meas)
  summary={'samples':len(meas),'warmup':100,**{k+'_us':v for k,v in stat([r['Nanoseconds']/1e3 for r in meas]).items()},'CS0_key_bytes' if kind=='dpf' else 'CS0_material_bytes':meas[0]['CS0Bytes'],'CS1_key_bytes' if kind=='dpf' else 'CS1_material_bytes':meas[0]['CS1Bytes'],'User_material_bytes':meas[0]['UserBytes'],'total_key_bytes' if kind=='dpf' else 'total_material_bytes':meas[0]['MaterialBytes']}
  assert len({r['MaterialBytes'] for r in meas})==1
  csvout('dpf-gen-samples.csv' if kind=='dpf' else 'scmp-single-samples.csv',raw)
  csvout('dpf-gen-summary.csv' if kind=='dpf' else 'scmp-single-summary.csv',[summary])
  paper.append({'category':'DPF single key pair' if kind=='dpf' else 'SCMP single complete comparison','scale':1,'time_unit':'us','mean':summary['mean_us'],'median':summary['median_us'],'P95':summary['P95_us'],'P99':summary['P99_us'],'material_bytes':meas[0]['MaterialBytes'],'material_MiB':meas[0]['MaterialBytes']/MIB})
 shapes=json.loads((OUT/'scmp-query-shapes.json').read_text());selected=json.loads((OUT/'scmp-representatives.json').read_text())
 counts=[]
 for s in shapes:
  counts.append({'QueryID':s['Query'],'AnchorPositionComparisons':2*sum(s['AnchorT']),'AnchorRecordComparisons':sum(s['AnchorD'])+s['N'],'TargetPositionComparisons':2*sum(s['TargetCapacity']),'TargetRecordComparisons':26*s['K']*(s['R']+1),'TotalSCMPInstances':s['Count']})
 csvout('scmp-query-material-counts.csv',counts)
 put('scmp-count-selection.json',{'count_distribution':stat([s['Count'] for s in shapes]),'selection':'linear quantile at (n-1)p; choose nearest actual rank, half rank ties lower, sort ties by QueryID','selected':selected})
 batch=[];rawbatch=[]
 for level in ['median','p95','max']:
  raw=rows(f'scmp-{level}-raw.jsonl');rawbatch+=raw;meas=[r for r in raw if r['Phase']=='measured'];assert len(meas)==30 and len(raw)==35
  assert len({(r['Count'],r['MaterialBytes'],r['MetadataBytes']) for r in meas})==1
  v=meas[0];ss=stat([r['Nanoseconds']/1e6 for r in meas]);row={'level':level,'material_count':v['Count'],'warmup':5,'measured':30,**{k+'_ms':x for k,x in ss.items()},'total_material_bytes':v['MaterialBytes'],'MiB':v['MaterialBytes']/MIB,'binding_metadata_bytes':v['MetadataBytes'],'material_plus_binding_bytes':v['MaterialBytes']+v['MetadataBytes'],'CS0_material_bytes':v['CS0Bytes'],'CS1_material_bytes':v['CS1Bytes'],'User_material_bytes':v['UserBytes'],'max_after_generation_heap_bytes':max(r['HeapAfterBytes'] for r in meas),'max_after_generation_RSS_bytes':max(r['RSSAfterBytes'] for r in meas),'mean_us_per_instance':ss['mean']*1000/v['Count']};batch.append(row)
  paper.append({'category':'SCMP batch '+level,'scale':v['Count'],'time_unit':'ms','mean':ss['mean'],'median':ss['median'],'P95':ss['P95'],'P99':ss['P99'],'material_bytes':v['MaterialBytes'],'material_MiB':v['MaterialBytes']/MIB})
 csvout('scmp-batch-samples.csv',rawbatch);csvout('scmp-batch-summary.csv',batch)
 exact=[];rawexact=[]
 for n in [120071,250000,500000,1000000]:
  raw=rows(f'exact-{n}-raw.jsonl');rawexact+=raw;meas=[r for r in raw if r['Phase']=='measured'];warm=5 if n<500000 else 3;measured=30 if n<500000 else 20;assert len(meas)==measured and len(raw)==warm+measured
  ss=stat([r['Nanoseconds']/1e6 for r in meas]);assert all(r['MaterialBytes']==266*n for r in raw)
  row={'N':n,'warmup':warm,'measured':measured,**{k+'_ms':v for k,v in ss.items()},'preprocessing_bytes':266*n,'preprocessing_MiB':266*n/MIB,'max_after_generation_heap_bytes':max(r['HeapAfterBytes'] for r in meas),'max_after_generation_RSS_bytes':max(r['RSSAfterBytes'] for r in meas),'mean_ms_per_100k':ss['mean']*100000/n};exact.append(row)
  paper.append({'category':'Exact-K preprocessing','scale':n,'time_unit':'ms','mean':ss['mean'],'median':ss['median'],'P95':ss['P95'],'P99':ss['P99'],'material_bytes':266*n,'material_MiB':266*n/MIB})
 csvout('exact-k-preprocess-samples.csv',rawexact);csvout('exact-k-preprocess-summary.csv',exact);csvout('offline-generation-paper-table.csv',paper)
 # Simple descriptive regression over three actual batch means, no extrapolation.
 x=[r['material_count'] for r in batch];y=[r['mean_ms'] for r in batch];mx,my=st.mean(x),st.mean(y);slope=sum((a-mx)*(b-my) for a,b in zip(x,y))/sum((a-mx)**2 for a in x);intercept=my-slope*mx;r2=1-sum((b-(intercept+slope*a))**2 for a,b in zip(x,y))/sum((b-my)**2 for b in y)
 put('scmp-linearity.json',{'points':3,'fit_on_actual_means':True,'slope_ms_per_instance':slope,'intercept_ms':intercept,'R_squared':r2,'us_per_instance':[r['mean_us_per_instance'] for r in batch],'no_extrapolation':True})
 existing=ROOT/'results/paper-evaluation-20260922'
 tok=list(csv.DictReader((existing/'token-offline-existing/token-summary.csv').open()));vol=list(csv.DictReader((existing/'token-offline-existing/offline-volume-summary.csv').open()))
 total=sum(float(r['mean']) for r in vol if r['unit']=='MiB')
 env=json.loads((OUT/'environment.json').read_text())
 report=f'''# 查询令牌与离线材料独立生成实验

本轮仅调用当前真实生成API。所有旧结果保留；未修改协议、参数，未构造数据库/静态索引，未执行854完整查询、规模实验或Exact-K在线微基准。在线压缩仅四档pilot和每档随机一份正式生成材料做计时外正确性抽查。

## 结果

{table(paper,['category','scale','time_unit','mean','median','P95','P99','material_bytes','material_MiB'])}

DPF每次两份key由真实codec.EncodeKey在计时外测量，CS0/CS1各{paper[0]['material_bytes']//2} bytes。SCMP单次是aggregation.PreprocessComparison(1)，原生opaque key每云284B、cached rb1B、输入掩码share1B，每云286B；用户eta1B，共573B。实际长度由当前生成对象逐项读取核验，不用unsafe.Sizeof冒充wire。
SCMP批量材料crypto字段分别在batch-summary中计两云与用户；另列位置packet绑定PID在三方对象的48B/occurrence复制，不与raw Offline统计混淆。公开角色/shape计数、Go slice headers、guards、allocator不计cryptographic body，因此材料体积不是完整序列化wire/进程RSS。

## 调用路径与计时边界

DPF：anchorquery.MakeOccurrence调用gen.Gen，实验恰在gen.Gen(alpha)前后取wall时间，含生成过程crypto/rand与两份真实key，排除alpha输入准备、qchunk、HMAC、bucket、token其他字段、codec及求值。128位域。100预热+1000正式；每次耗时独立记录，汇总只用measured。少量随机生成试次的两份密钥经真实codec解码后，在目标/非目标点求值重构，计时外检查。

SCMP：实际Provision的两个生成封装为anchorfilter.Preprocess(t,7,Backend)（每slot下界和上界各一实例，rho_L/R及eta_L/R，随机omega和keys、PID），aggregation.PreprocessComparison(n,Backend)（输入mask两shares、user eta、omega、两方keys、cached rb）。omega作为KeyGen随机参数被相关密钥吸收，不额外伪造一份用户输出掩码。Bout1由native bridge真实调用keyGenSCMP(bin,1,...)固定。单实例用后者n=1；批量按代表query的真实调用分组调用前者与后者，保留完整两方材料直至计时结束；不生成Beaver或非SCMP材料、不进行在线求值/传输/落盘。计时包含真实随机性和native必要key编码，因为KeyGen返回当前opaque格式；排除额外文件序列化。100+1000单次，批量各5+30，未降低max次数。

Exact-K：aggregation.PreprocessCompactionWithBucketBits(layout,N,16)入口至返回。真实state字段为perm、c、t、r及layout/query/n/bucketBits、mutex/phase控制；CS0持perm=p、c=c0、t=t1、r=r1，CS1持perm=q、c=c1、t=t0、r=r0。随机生成p/q两置换、t0/r0/t1/r1四组tuple，计算c0[p[i]]=t0[i]-r0[p[i]]与c1[q[i]]=t1[i]-r1[q[i]]，包含fresh query ID。对应两轮(pi,A,B,C)相关状态；没有接口K参数，预处理不依赖K。
计时不含Keep、payload/fixture、在线shuffle、开Keep、统计K/Extract、文件I/O。材料体积由返回对象perm和6个tuple数组实际长度/字段宽度计算：2*4N+6*(1+8+32+2)N=266N，未把struct对齐填充当字段体积；公开绑定和生命周期元数据另在结构说明，不作为266N主体。
四档先各1次pilot确认资源和7个随机支持位置的完整在线压缩正确性，再按5+30、5+30、3+20、3+20正式执行。正式每档随机一份生成状态额外完整压缩并检查ID/scalar/bucket及集合，无性能计时，不构成重复在线微基准；所有材料fresh且ID去重验证。DPF与SCMP抽查失败会t.Fatal立刻停止，无协议修复重试。

## SCMP真实查询实例数量来源

每Query C = 2*sum_h(TAnchor_h) + sum_h(DAnchor_h) + N + 2*sum_h(TargetCapacity_h) + 26*K*R + 26*K。
逐项来自discovery/offline.go:Provision、anchorfilter/filter.go:Preprocess、targetposition/position.go:Preprocess、targetaggregation/packet.go:Preprocess的真实KeyGen循环。
三轮校准固定工作量已核对。本轮读取既有原始area做只读形状census：调用生产LoadArea/VisitQGrams/Encode/AnchorBucket/TierWidth/RecordCapacity，仅读取并累计被查询桶的T/D，无Build、分享、数据库重建。Target容量使用既有final bits16公开layout metadata和同样JoinBucket/WordBucket真实函数，所有非16历史layout均丢弃。
全部854查询的AnchorPosition=1168*sumT、AnchorAggregation=8sumT+4sum(DT)+578sumD+6*N*rAnchor+572*N，与既有Offline逐条精确相等；Target容量合计、group合计、K和TargetPosition同样与既有实际记录相等。counts.csv保存每查询四类比较数，scmp-query-shapes.json保存实际各调用长度。中位/P95从(n-1)p的rank选最近实际query，半rank选低者；非整数分位数不取整伪造不存在的工作量，选择依据另存scmp-count-selection.json。

## 增长趋势与主要开销

{table(batch,['level','material_count','mean_ms','mean_us_per_instance','total_material_bytes','MiB'])}

三个批量点均值拟合 C→时间 R²={r2:.6f}；每实例均值范围{min(r['mean_us_per_instance'] for r in batch):.6f}～{max(r['mean_us_per_instance'] for r in batch):.6f}us。只描述这三个实测shape的近似线性趋势，不外推未测规模或保证严格线性。不同位置/聚合封装的随机采样和分组开销保留在实测内。

{table(exact,['N','mean_ms','mean_ms_per_100k','preprocessing_bytes','preprocessing_MiB'])}

Exact-K的N增大{1000000/120071:.6f}倍，均值增大{exact[-1]['mean_ms']/exact[0]['mean_ms']:.6f}倍；单位100k耗时见表。与SCMP查询规模批量相比，单次DPF key pair生成很小。SCMP批量与Exact-K N120071的比较是同一真实查询规模下的分项对照；三类不包含全部Beaver/辅助静态准备，不能据此宣称完整Provision所有成本归因已完成。最大查询的SCMP批量与DPF单次不可当同工作量相比较。

已有{total:.6f} MiB/query表示六类一次性离线字段体积的平均，非时间、不是完整落盘/传输量；本轮测真实生成wall-clock，不通过bytes除吞吐估算。新SCMP体积只覆盖比较相关材料且包含用户bound masks，原六类体积按阶段还含Beaver等，所以不可直接相加，也不可把本轮三项时间之和当总Provision。

## 在线边界与实验5闭合

**DPF Gen实际属于在线Token生成，已包含在现有Token和LocalE2E；它不是当前系统计时外的离线准备。**本轮单独拆解测量，不把Token里DPF时间再重复加到离线总计。SCMP与Exact-K真实Provision调用在RunLocal之前，均在当前LocalE2E外。
已有Token总时间/通信、六类离线材料体积/总Provision记录，加上本轮三个缺失生成分项，满足本轮冻结的实验5范围。未增加完整离线pool落盘wire、所有Beaver独立生成或数据库外包指标；这些不是本次闭合条件。

【实验5已闭合，可直接写论文】

## 环境、资源与复现

OS={env['os']}；{env['cpu']}；Go={env['go']}；GOMAXPROCS32、GOGC100、GOMEMLIMIT=off；q4/Anchor16/Target16/Bin7/Bout1/DTarget26。实际内存/affinity、源码/HEAD/status、二进制/native哈希见environment.json与binary.json。同一保留Go工具链/native库与校准一致；新测试二进制/构建cache/tmp路径不同，无驻留DB；batch/Exact-K每次计时前显式GC，GC发生于生成区间内的部分仍计入时间。这不是校准E2E执行模型，不与其时间作直接归因。历史内存空闲/进程负载无法确认完全一致。
仅在生成结束边界读取HeapAlloc/RSS，无采样线程；max_after_generation_*是各测量结束点的最大值，**不是PeakHeap/PeakRSS**，不是单云内存。每次前后vmstat记录分页，所有成功执行必须无pswpin/pswpout增长；若可用内存<2GiB或单次生成>60s停止，不擅自减少次数。全部四档pilot通过，未触发资源中止；正确性抽查通过。输入/旧结果/协议源码前后哈希见preservation，排除本轮新增结果。
分位数一律(n-1)p线性插值；us=ns/1000，ms=ns/10^6，MiB=bytes/1024²。raw JSONL/样本CSV保留warmup与measured标记；pilot另存，不混入正式汇总。执行入口tools/run_offline_generation_20260922.py，当前目录存在时拒绝覆盖。
'''
 put('offline-generation-report.md',report)
 put('experiment5-final-summary.md',f'''# 实验5最终论文汇总

## A. 查询令牌开销（引用既有正式数据）

来源results/paper-evaluation-20260922/token-offline-existing/token-summary.csv；每Query三轮中位数，再对854合法查询统计。

{table(tok,['metric','unit','mean','median','P95','P99'])}

Token mean约0.387ms，单云平均约4875.862bytes。两云通信计总发送一次；DPF Gen在Token内，本轮单独测量是分解性辅助，不重复计入。

## B. 离线预处理开销

六类字段体积引用既有offline-volume-summary.csv：

{table([r for r in vol if r['unit']=='MiB'],['material','unit','mean','median','P95','P99','max'])}

六类平均体积合计{total:.6f}MiB/query；不是RSS或完整wire编码。生成时间本轮真实调用结果：

{table(paper,['category','scale','time_unit','mean','median','P95','P99','material_bytes'])}

SCMP/Exact-K生成在在线LocalE2E外，DPF Gen在Token内。SCMP实例数按真实Provision调用循环及逐查询体积交叉核验；Exact-K仅N驱动，材料266N字节，排除fixture/Keep/payload/online。详见offline-generation-report.md。已有总Provision仍按原口径引用，不用这里三项相加冒充完整总量。

Token生成开销、Token通信量、六类离线字段体积、所缺三个独立生成时间均有正式数据及可追溯原始样本。正确性抽查通过；所有旧结果未覆盖。闭合指本轮冻结实验5范围，不包含完整落盘offline pool或完整OutSource通信。

【实验5已闭合，可直接写论文】
''')
 print(table(paper,['category','scale','time_unit','mean','material_bytes']),flush=True)

if __name__=='__main__': main()
