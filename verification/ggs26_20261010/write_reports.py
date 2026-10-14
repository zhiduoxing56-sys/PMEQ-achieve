"""Report tables derive only from completed recorded runs, never estimated time."""
import csv,json,hashlib,platform,subprocess
from pathlib import Path
P=Path(__file__).resolve().parent
def read(name):return list(csv.DictReader((P/name).open()))
def num(r,k):return float(r[k])
def table(rows,cols):
    out=['| '+' | '.join(title for title,fn in cols)+' |','| '+' | '.join('---' for _ in cols)+' |']
    for r in rows:out.append('| '+' | '.join(fn(r) for _,fn in cols)+' |')
    return '\n'.join(out)
def main():
    audit=json.loads((P/'benchmark-audit.json').read_text());assert not audit['missing_jobs'] and not audit['failed'] and not audit['remaining_unmeasured_original_shuffles']
    assert audit['large_shuffle_measured_records']==40 and audit['offline_bank_measured_records']==20 and audit['larger_measured_records']==10 and audit['grouped_matched_measured_records']==55
    main=read('performance-medians.csv');large=read('performance-large-shuffle-medians.csv');match=read('performance-matched-medians.csv');extra=read('performance-larger-medians.csv');banks=read('performance-offline-bank-medians.csv')
    names={'full-secure':'A：安全全量','shuffle':'B：秘密置换','linear-B':'C：通用 GF129 掩蔽 + 编码/参考解码','linear-hybrid':'C：目标离线掩码 + GF64 锚掩蔽','linear-grouped':'D：共享加权 Keep 分组乘法 + 参考解码','grouped-sum1':'D-sum：M=1 直接求和','ring-sum1':'M=1 通用 Ring64 求和'}
    cols=[('方案',lambda r:names[r['method']]),('L / M',lambda r:f"{int(r['L']):,} / {r['M']}"),('云本地累计 s',lambda r:f"{num(r,'cloud_local_s'):.3f}"),('在线阶段小计 s',lambda r:f"{num(r,'online_s'):.3f}"),('离线生成 s',lambda r:f"{num(r,'offline_s'):.3f}"),('含离线阶段小计 s',lambda r:f"{num(r,'end_to_end_with_measured_offline_s'):.3f}"),('云间 MB',lambda r:f"{num(r,'cloud_bytes')/1e6:.3f}"),('材料 MB',lambda r:f"{num(r,'material_bytes')/1e6:.3f}"),('用户 B',lambda r:str(int(num(r,'user_bytes')))),('用户恢复 s',lambda r:f"{num(r,'decode_s'):.6f}"),('峰值 MiB',lambda r:f"{num(r,'peak_rss_bytes')/2**20:.1f}")]
    selected=[]
    for L in [100000,1000000,6001215,60012150]:
        for method in ['full-secure','shuffle','linear-B','linear-hybrid','linear-grouped']:
            pool=large if method=='shuffle' and L==60012150 else main
            selected.append(next(r for r in pool if r['method']==method and int(r['L'])==L and r['M']=='10'))
    paired=[r for r in match if r['experiment_version']=='v5-grouped-matched' and r['M']=='1']
    dense=[r for r in main if r['method'] in ['full-secure','linear-grouped'] and r['M']=='1000' and r['L'] in ['1000000','60012150']]+[r for r in main+large if r['method']=='shuffle' and r['M']=='1000' and r['L'] in ['1000000','60012150']]
    workload=[next(r for r in pool if r['method']==method and r['L']=='35238024' and r['M']=='667') for method,pool in [('shuffle',large),('linear-grouped',main)]]
    bankcols=[('L',lambda r:f"{int(r['L']):,}"),('K / T_max',lambda r:f"{r['K']} / {r['T']}"),('五次生成+fsync中位数 s',lambda r:f"{num(r,'offline_s'):.3f}"),('双方实际材料 B',lambda r:str(int(num(r,'material_bytes')))),('实际文件 B（含头）',lambda r:str(int(num(r,'file_bytes_with_headers')))),('峰值 MiB',lambda r:f"{num(r,'peak_rss_bytes')/2**20:.1f}")]
    report='''# 可行性结论：CONDITIONAL

尚未完成“原论文完整快速算法 + 正式 PMEQ 接口 + 目标规模两方部署”的全面验证。已经找到实测明显更省通信和内存的独立候选 D；尤其 M=1 的 D-sum 不依赖复杂多项式解码，在指定全域共享输入契约下，计算、材料和通信都有优势。它需要静态目标返回侧表，当前生产 26K 动态目标出口不能直接接入，不能宣布 PASS。

论文快速编码已严格按 Definition 19 / Lemma 23 实现，129 位非零打包与正确共享转换通过。Theorem 25 快速解码缺少 LCH 快速多项式运算、扩展 GCD 和快速根查找实现；所有通用 C/D 时间使用明确标识的慢参考解码器。`linear-C-paper-fast` 全部留空，不以普通 BM/多项式求解的性能冒称已复现原方案。

## 实测范围和计量边界

所有产物位于独立 `verification/ggs26_20261010/`；原仓库 266 个已跟踪文件哈希及完整 porcelain 工作树状态未变，见 `preservation-check.json`。没有改正式代码、论文、数据或原实验结果。论文准确版本、公开实现检索和许可证证据见 `paper-review.md`。

所需四个 L 的 M=0/1/2/10/100/1000，以及 MusicBrainz K=46/M=1、K=519/M=667 和 TPC-H K=1/M=1、K=2/M=2，均完成五次独立 seed 的各主要基线。40 个原先因 4 GiB 预算跳过的置换后来全部补齐；原跳过记录仍保留，不能从旧行误判最终未测试。五次取各 trial 首条记录，不把同 seed 额外重跑混进中位数。

K/M/N 来自仓库已有统计及本地既有 TPC-H 负载，保存原文件来源和 SHA-256。测试重新生成秘密份额、合成编号/命中位置，未重跑实际 PSMJ 群匹配到 Keep 的全查询链。用户恢复的是候选对及重数；没有运行最终编辑距离验证。

大规模 C++ 是可信 harness 内的两个角色内核，应用数据实际通过 AF_UNIX write/read；所有转换、乘法、随机材料生成和序列化计量，不给云运算明文 Keep 捷径。小规模另有真实隔离的 spawn 云进程，DO 先离线、各云只得本方状态，最后各自 Pipe 到用户；还补充 30 次秘密 256 位 AES 随机性实例。C++ 公开 64 位 seed 仅用于可复现性能，不能作为生产保密实现。

`online_s` 是计数/输入适配/全部编码/云间传输/用户传输/恢复的测量阶段小计，`offline_s` 是实际生成、序列化和消耗材料的时间，双方 CPU 累计由 `cloud_local_s` 记录。`end_to_end_with_measured_offline_s` 是同次内核阶段小计之和；另给实际进程钟 `process_wall_s` 和扣除输入夹具生成的 `harness_wall_minus_fixture_s`，后者还含启动/配置/校验/清理，可检查未在阶段计时内的开销。**没有测生产跨云网络、材料交付和并行两云部署端到端时间，相关 CSV 单元留空。**

材料字节是实际生成的序列化份额大小；云间/用户字节是实际应用 write 的大小，含实验帧头，不含 IP/TLS。C++ 最终传输由用户 harness 读取，不能把其复用 socketpair 当作可部署的 peer-return API。最终 share 必须各发用户保密通道，用户消息边界/M/模式和生产绑定仍需接入。

v2 主矩阵固定四个物理 CPU 0/2/4/6，存在共享缓存/内存竞争；大置换先单线程试跑，再两个 CPU 8/10、每个 VM 18 GiB、联合最多 36 GiB、至少 8 GiB 主机保留及监控。v4 的历史版本名含 serial，但每行记录实际单/双进程及背景负载。v5 配对试验在 CPU12 轮换方法顺序、输入/seed 对齐，受同一后台大置换影响；v3 无后台的串行对照单独保留。不同版本中位数不混池，不能凭微小跨批差异宣布速度优势。峰值是整个 harness 进程 RSS，不是单云内存。下表 MB=10^6 字节，MiB=2^20 字节。

## M=10 的完整新增阶段比较

以下全部为五次实测中位数；C/D 均使用参考解码。最大 L 的置换来自 v4，其余为 v2，输入边界相同，执行并发不同。

'''+table(selected,cols)+'''

通用 GF129 每槽 Beaver 掩蔽产生约 68.25L 云间字节，输入准备比置换更贵。目标相关掩码 C 将它降到约 32.5L；D 通过在共享加权 Keep 上分组乘锚，降到约 `0.5L+136KM`，并保持准确 `H(bP)`。这是真实协议成本改善，不仅是快速编码的计时。

D 用约两次快速本地变换，较 C 的单次编码增加计算。M=10 百万槽配对试验的 D 在线阶段仍比置换慢，但含材料生成的小计更低；数据不支持“线性码在全部计算指标上都更快”。最大 L=60,012,150 的 D 云间约 32.2 MB，置换约 2.163 GB；用户 D 收 754 B，置换 394 B，两者都是短结果。

当前置换协议投影沿用 1 字节布尔序列化。若其所有 Keep 位也压到 bit，云间理论载荷可从 36L 降到 32.5L，材料从 110L 降到 104.75L；这些是**未执行的字节公式**。所以 C 的约 10% 通信优势不是本质优势，D 的数量级差异仍存在。安全全量 baseline A 的 Keep 位也可从实测 34L 用户载荷压到理论 32.25L；不得把这些公式当成真实新测量。

## M=1 的明确优势和适用限制

下表为 v5 同一串行配对输入、每格五次。D-sum 各云求和并只对 K 个秘密加权值安全乘锚，用户一个 GF129 元素即可恢复唯一完整编号对；包括 `(0,0)`。不输出槽号，不调用普通 BM，更不依赖未完成的 Theorem 25。

'''+table(paired,cols)+'''

约 600 万槽：D-sum 在线 0.111 秒、含实际生成小计 1.070 秒、云间 3,231,164 B、用户 108 B；置换对应 1.271 秒、6.286 秒、216,260,708 B、106 B。两者扣输入夹具的实际 harness 时钟也单独保留。这个量级差异有配对数据支持，而不是对 WAN 的性能外推。

另有通用 `ring-sum1`，不要求静态目标、可处理当前私有路由动态产生的两类 Ring64 ID。它安全计数、两次 Ring64 ID 掩蔽后求和，用户 106 B；已在四个指定 L 各跑五次。其云间约 64.25L，比置换更多，不能根据本机计算更快就宣布网络更优。若接在已掩蔽的生产出口后，只有计数和求和是新增，但那是另一个输入边界，未把上游 ID 掩蔽成本悄悄移出本报告的比较。

M=0 只安全计数并返回空编码，适用于任何返回方案；不能把它写成论文相对置换的专属优势。DO 离线不知道 M，未用材料的容量预留仍要计算。

## M=1000 和实际非空负载：剩余瓶颈

'''+table(dense,cols)+'''

60M/M1000 的 D 参考解码约 6.18 秒，编码约 30.09 秒；在线总 37.43 秒高于置换 17.58 秒，即使包含实测材料生成小计低于置换，也不能满足“原论文快速解码已验证”的要求。只接收 68,074 B 不等于客户端 CPU 已足够轻量；其恢复甚至可能比本机全量流式扫描慢。主要瓶颈已经从每槽安全乘法转移到两次编码及缺少快速解码。

MusicBrainz K=519、M=667、N=67,896 的负载形状：

'''+table(workload,cols)+'''

D 云间约 66.0 MB，置换约 1.270 GB；D 在线较慢、离线生成较快，用户参考解码约 2.21 秒。这个案例同样不支持无条件替换所有查询的结论。

## 完整离线池与更大 L

为避免只计消耗材料，另实际生成 T_max=1000、公开 K 容量下全部 D 票据，包括目标状态、全 L 计数 daBits、全 L 目标相关掩码、动态锚转换 AND 材料及 2KT_max GF129 triples。各 L 五次，真正写入双方文件、fsync、保存全文件哈希和相关性样本校验；未向云交付、未在大规模在线角色中消费这些文件。

'''+table(banks,bankcols)+'''

最大池 2.048 GB 材料已实际生成；M0 在线核只生成/消耗计数部分约 0.975 GB，不能把其 3.575 秒当完整容量池离线时间。9.570 秒的完整池文件测试是独立测量，不能与另一组在线时间相加冒称同一 ticket 的已部署端到端结果。预处理实际交付网络字节和时间仍待验证。

更大的 MusicBrainz 输入在先审计 O(N+K) 状态及时间包络后，只实测 M0/M1 特化：

'''+table(extra,cols)+'''

K=4582、L=311,099,472、M=1 用户仍收 108 B，实际全部 harness 时钟中位数约 81.6 秒，其中约 48.4 秒是测试输入生成，新增阶段含生成小计约 32.3 秒。云端也绝非只做 O(M) 工作：实际材料约 10.11 GB。固定 512 MiB VM 限额下运行，峰值约 16.5 MB。该 L 的全域内存置换按已测实现缩放需约 77 GB RSS，未执行；这是估计，不是已测失败或时延。

TPC-H 短前缀最大 K=10934、M=9411 给出 L=65,617,284,810。仅 D 材料银行即 TB 级、超过可用磁盘；参考解码和 K·2M 存储也越过本原型预算，C++ 置换 uint32 域亦不支持该码长。未执行，见 `larger-workload-resource-review.json`；没有填入外推时间。

## 渐近成本及安全模型

忽略帧、填充和公共参数检查，以 Ring64/GF129 常数宽度计：

| 返回方式 | 云本地计算 | 云间载荷 | 新鲜离线材料 | 用户载荷/恢复 |
|---|---|---|---|---|
| 安全全量 A | O(L) Ring 掩蔽 | 64.25L | 112.25L | 34L / O(L) |
| 全域置换 B（pair 投影） | O(L) | 36L | 110L | 32M / O(M)，对照排序额外 O(M log M) |
| 通用线性 A-convert | 转换 + O(L log M) | 2L 次 64 位转换 + 68.25L；可优化为 K+N 次转换 | 同转换材料 + 118.25L | 68M / 参考解码非快速 |
| 静态目标 C | O(L log M)+O(K) 64位电路 | 68.25L 或目标掩码版 32.5L | 118.25L 或 80.5L，加16N、转换材料 | 68M / 参考解码非快速 |
| 分组 D | O((L+KR) log R)+O(KM)+K 个转换 | 0.5L+136KM+转换 | 32.5L+204KT_max+16N+转换 | 68M / 完整论文应为 O(M log²M·129)，未复现 |
| D-sum，M=1 | O(L+K)+K 个转换 | 0.5L+68K+转换 | 32.5L+102K+16N+转换 | 34 / O(1) |

转换每 64 lane 批次使用 126 个 AND；当前 ripple 实现有 126 次依赖打开，真实跨云延迟未经验证。逐块消息可流水化但没有测 WAN 或生产流水，不能直接将 AF_UNIX 结果用于远程云时延判断。一般解码仍用普通稠密多项式运算，部分二次、完整基展开/递归最坏可能立方；没有偷换渐近阶。

正确性由不可约域、可逆非零打包、正确 Ring64 转换、H 的线性性和码距离保证。重复值依靠独立定位点保留重数；两字段在同一载荷内配对。协议只打开独立掩蔽差、总 M，以及置换基线的随机位置 Keep。D 不打开按 c 的计数或 W。半诚实可信离线相关性模型下可模拟本方消息；不新增 HE/OT 假设，但新增预处理类型/静态状态、要求足够私有随机熵和最终用户私有通道。详细模拟论证、有限视图枚举和所有剩余条件见 `security-review.md`。

## 正式 PMEQ 接入和最终裁决

当前 `targetaggregation.Execute` 及 `candidatequery` 仍是 26K 槽，目标 ID 在本次私有 Match/路由里按 c,u 动态选出；D 的优化需要任务定义的固定全局 j 返回侧表。这两种坐标不能直接互换。需要先证明/实现真实 KNγ Keep 输出的接点和侧表绑定，或将新的返回域状态安全随原私有路由生成并计其成本。现有步骤5(1)、群等值匹配、位置过滤、关联矩阵、桶聚合、全球映射、跨块累加、最终比较均未修改；本次也未验证一个生产适配器已经存在。

G6 只建议改最后逐槽返回段（最新版本地存档约1762–1776行）调用独立 S_SRE，前面匹配/聚合模拟保持原样；AP 明确只允许总 M，不包含 Mc/原始支持。当前仓库仍承诺隐藏最终数、历史论文仅G0..G5，版本须统一。不能把论文 HE 正确性直接当两云组合安全证明，也不能擅自重写原论文。具体位置与证明缺口均列于安全报告。

PASS 未满足：快速解码、大规模独立云端/用户通道、完整离线池在线消费与交付、票据生命周期、真实坐标/ID绑定和G6组合尚未闭合。FAIL 也不成立：数学、局部安全原型和低 M 性能已有明确正向证据。结论为 CONDITIONAL。

**终端问题的回答：已经找到在指定全域共享契约下、尤其 M=1 时显著优于所测全域置换的候选；尚未找到并验证一个直接接入当前 PMEQ、保持真实 PSMJ 不变且对全部要求 M 都具有论文快速性能的通用方案。**
'''
    (P/'feasibility-report.md').write_text(report)
    sources={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in P.iterdir() if f.is_file() and (f.suffix in ['.cpp','.py'] or f.name in ['prototype','prototype-v2','hybrid','grouped','prototype-large','full-secure','ring-sum1','offline-bank','extended-tests'])}
    env=json.loads((P/'environment.json').read_text());env.update(status='Completed all final matrices; fast decoder and production integration unverified',final_source_and_binary_sha256=sources,final_audit=audit,offline_bank_retention='Only latest two party material files retained; per-run hashes/certificates stored; not installed',cpu_scope='v2 0/2/4/6; v3 8 serial idle; v4 8/10 large guarded; v5 12 paired under v4 background; v6 14 offline bank; v7 0/2 larger sparse')
    (P/'environment.json').write_text(json.dumps(env,indent=2));print('REPORT GENERATED FROM COMPLETED DATA',audit['raw_records'])
if __name__=='__main__':main()
