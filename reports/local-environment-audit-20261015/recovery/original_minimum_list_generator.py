import pathlib,json,hashlib,html
P=pathlib.Path('/tmp/pmeq-local-environment-audit-20261015');R=pathlib.Path('/home/tenggn/projects/clean_pmeq');T=R.parent/'clean_pmeq-target-zero-poly-agg'
remote={x['path']:x for x in json.loads((P/'github_local_comparison.json').read_text())['files']}
items=[]
def entry(path,role,required=True):
 p=pathlib.Path(path)
 exists=p.is_file();row={'path':str(p),'role':role,'required':required,'exists':exists}
 if exists:
  row.update(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
  if p.is_relative_to(R):row['github_snapshot_status']=remote.get(str(p.relative_to(R)),{}).get('status','not_in_snapshot')
  else:row['github_snapshot_status']='local_only_or_target_branch'
 items.append(row)
for n in ['PMEQ本地工程环境与迁移前置审计报告.txt','core_version_comparison.csv','github_local_comparison.json','source_stability.json']:
 entry(P/n,'审计与版本边界')
for rel in ['internal/zeroagg/kernel.go','internal/targetaggregation/zero_labels.go','internal/targetaggregation/packet.go','internal/targetaggregation/protocol.go','internal/targetaggregation/sidecar.go','internal/discovery/offline.go','internal/discovery/types.go','internal/discovery/cloud.go','internal/discovery/local.go','internal/discovery/target_process_default.go','internal/discovery/target_process_experiment.go','internal/targetaggregation/experiment_process.go','internal/targetaggregation/experiment_operator.go','internal/targetaggregation/zero_native_test.go','internal/discovery/target_zero_native_test.go']:
 entry(T/rel,'目标零点新实现供体；与当前主目录比较，不能直接覆盖')
for rel in ['experiments/target-zero-poly/REPORT.zh-CN.md','experiments/target-zero-poly/summary/acceptance.json','experiments/target-zero-poly/cloud-worker/main.go','experiments/target-zero-poly/operator/main.go','experiments/target-zero-poly/user_ed.py']:
 entry(T/rel,'目标历史实现/验收边界及实验精确ED接口参考',False)
for rel in ['imdb_final_dataset/README.txt','imdb_final_dataset/reports/中文字段说明.txt','imdb_final_dataset/provenance/source_manifest.json','imdb_final_dataset/checks/delivery_acceptance.json','imdb_final_dataset/checks/validation.json','imdb_main_join_precheck_20261014/samples/n1000/MOVIECAST.json','imdb_main_join_precheck_20261014/samples/n1000/MOVIE.json','imdb_main_join_precheck_20261014/samples/n1000/sample_manifest.json','imdb_main_join_precheck_20261014/samples/n1000/queries.json','imdb_main_join_precheck_20261014/samples/n1000/plaintext_answers.json','imdb_q_crypto_preexperiment_20261014/checks/final_status.json','imdb_q_crypto_preexperiment_20261014/checks/minimal_source_changes.patch','imdb_q_crypto_preexperiment_20261014/reports/position_parameters.csv','imdb_q_crypto_preexperiment_20261014/logs/current_chain_test_compile.log']:
 entry(R/rel,'真实schema/小样本基准/现有参数适配证据')
for rel in ['docs/paper/latest.json','docs/paper/PMEQ_latest_20261011.tex']:
 entry(R/rel,'磁盘论文版本对照，尚需确认是否为导师批准的最终数学定义',False)
(P/'minimum_files_manifest.json').write_text(json.dumps(items,ensure_ascii=False,indent=2))
lines=['需要提供给 ChatGPT 的最小文件清单','日期：2026-10-15','',
'本轮只生成清单，没有复制、打包或上传源码/数据。列表 SHA-256 只针对这些小型源码、公开样本和报告；没有读取秘密载荷。',
'', 'A. 优先提供已有 GitHub 源码链接并固定提交',
'https://github.com/zhiduoxing56-sys/PMEQ-achieve/tree/5241fc1ab9cb58674736ae8bbc8866a84abacff0',
'这是当前主目录源码快照，345个文件与本地一致；无需重复上传整个主库。原主目录master HEAD并不是实际新版。',
'ChatGPT应重点读取：go.mod/go.sum；CURRENT_SPEC.md、PRODUCTION_CHAIN.md、SECURITY_INVARIANTS.md；internal/zeroagg、material、discovery、anchorindex、anchorfilter、indexbuild、targetcrypto、targetquery、targetposition、targetaggregation、candidatequery、qgram、scmpnative；tools/build_phase6_native.sh、phase6_scmp_bridge.cpp、scmp_key_codec.h。依赖的其他internal文件应从同一提交读取，不混用旧版本。',
'如果ChatGPT无法直接读取仓库，以上源码包应由用户提供源码文本；不附 native二进制、缓存、数据和密钥。',
'', 'B. 本地补充文件（必需及可选逐项标记）']
for i,x in enumerate(items,1):
 lines.extend([f"{i}. [{'必需' if x['required'] else '可选参考'}] {x['path']}",f"   用途：{x['role']}；存在={x['exists']}；GitHub={x.get('github_snapshot_status','—')}；字节={x.get('bytes','—')}"])
lines.extend(['','C. 必须补充的人工版本信息','导师当前批准的新算子数学定义和精确查询结果恢复规则。磁盘10月11日论文只是待核实的对照，不能自动认定最终数学版本。','',
'D. 按问题再提供，不在第一批最小清单中',str(P/'legacy_dependencies.csv')+'：需要逐项消除旧字段/固定参数时提供。',str(P/'repositories.json')+'：需要逐文件处理Git dirty/ignored时提供，文件较大含大量路径。',str(P/'data_locations.json')+'：需要讨论磁盘/运行态时提供，通常无需全部逐文件metadata。',
'锚侧供体磁盘已删的 internal/tpchdb/build.go 可以只读 git show 3d9689ab6a8ff23a3d293bab172fc49b4ed80b9a:internal/tpchdb/build.go 作为 ShareCoordinates/布局逻辑参考；它不是新电影数据适配器，本轮未恢复。','',
'E. 不提供给ChatGPT的运行秘密或大型载荷','不提供master keys、secret shares、private/里的party packets、Beaver材料、密钥种子、bank/ticket/consumed内容、HE secret keys、mp-spdz秘密运行状态或用户凭证。','无需提供全量raw.gz、DuckDB、全部Parquet分片、GoSDK/.venv/缓存、旧密码索引和大型TPC-H状态；本地保留，供未来获得授权的实际执行。','不要将旧索引性能、旧TPCH报告视为当前IMDb新算子性能；可选历史报告只证明当时供体实现的边界。','',
'唯一正式工作目录建议：/home/tenggn/projects/clean_pmeq','正式IMDb仍保留在其 imdb_final_dataset/；三个工作树仅作为明确版本的逻辑供体/历史证据。此建议未触发任何迁移、合并、删除或推送。'])
text='\n'.join(lines)+'\n';(P/'需要提供给ChatGPT的最小文件清单.txt').write_text(text)
print('Files',len(items),'required',sum(x['required'] for x in items),'missing',[x['path'] for x in items if not x['exists']])
