#!/usr/bin/env python3
"""Build final decisions from audited measurements; never invent missing metrics."""
import csv, json, pathlib, statistics
P = pathlib.Path(__file__).resolve().parent
data = list(csv.DictReader((P/'performance-medians.csv').open()))
audit = json.loads((P/'performance-audit.json').read_text())
assert audit['rows'] == 870 and audit['groups'] == 174
VERSION = 'grouped-ring/full-adaptive-reservation'
def row(L,M,method,version=VERSION):
    matches=[r for r in data if r['version']==version and int(r['L'])==L and int(r['M'])==M and r['method']==method]
    assert len(matches)==1
    return matches[0]
def val(r,k):
    assert r[k]!='', (r['version'],k)
    return float(r[k])
def f(r,k): return f'{val(r,k):.6f}'
def integer(r,k): return f'{int(val(r,k)):,}'
A,B,G=[row(60012150,2,m) for m in ('full','shuffle','sre')]
online=val(B,'online_return_wall_s')/val(G,'online_return_wall_s')
cold=val(B,'end_to_end_cold_return_s')/val(G,'end_to_end_cold_return_s')
saving=100*(1-val(G,'cloud_bytes')/val(B,'cloud_bytes'))
extra=100*(val(G,'reserved_material_bytes')/val(B,'reserved_material_bytes')-1)
strict=[row(6001210,2,m,'strict-private-grouped-clock') for m in ('full','shuffle','sre')]
table='| 指标（五次中位数） | 原全量返回 A | 全域秘密置换 B | G-BRE C |\n|---|---:|---:|---:|\n'
for title,k,fmt in [
 ('两云新增CPU秒','cloud_cpu_s',f),('云间实际应用字节','cloud_bytes',integer),
 ('完整离线材料body字节','reserved_material_bytes',integer),('实际离线材料文件字节（含header）','reserved_material_file_bytes',integer),('离线生成与fsync秒','offline_s',f),
 ('用户实际接收字节','user_bytes',integer),('用户解析/恢复秒','user_decode_s',f),
 ('单云在线RSS高水位字节','cloud_peak_rss_max_bytes',integer),
 ('两云RSS高水位之和字节','cloud_peak_rss_sum_bytes',integer),
 ('DO离线RSS高水位字节','offline_peak_rss_bytes',integer),
 ('在线返回阶段时间和秒','online_return_wall_s',f),
 ('离线加在线返回阶段时间和秒','end_to_end_cold_return_s',f)]:
    table+='| '+title+' | '+' | '.join(fmt(r,k) for r in (A,B,G))+' |\n'
small='| 来源/形状 | L | K | M | B在线秒 | G在线秒 | B离线+在线秒 | G离线+在线秒 |\n|---|---:|---:|---:|---:|---:|---:|---:|\n'
for label,L,K,M in [('TPC-H target domain',6001215,1,1),('TPC-H target domain',6001215,1,2),('TPC-H two anchors',12002430,2,2),('TPC-H ten anchors',60012150,10,2),('MusicBrainz shape',3123216,46,1),('MusicBrainz shape',35238024,519,667)]:
    b,g=row(L,M,'shuffle'),row(L,M,'sre')
    small+=f'| {label} | {L:,} | {K} | {M} | {f(b,"online_return_wall_s")} | {f(g,"online_return_wall_s")} | {f(b,"end_to_end_cold_return_s")} | {f(g,"end_to_end_cold_return_s")} |\n'
strict_table='| 指标（同一私密输入，五次） | A | B | G-BRE |\n|---|---:|---:|---:|\n'
for title,k in [('完整在线进程时钟秒','strict_protocol_wall_s'),('离线加完整在线时钟秒','strict_cold_protocol_s'),('用户进程墙钟秒','client_process_wall_s'),('含参考结果核验的外层墙钟秒','harness_wall_including_client_and_oracle_s')]:
    strict_table+='| '+title+' | '+' | '.join(f(r,k) for r in strict)+' |\n'
profile=[json.loads(x) for x in (P/'primitive-profile-raw.jsonl').read_text().splitlines()]
q=[x for x in profile if x.get('n')==65536 and x['scope']=='single_process_legacy_kernel_diagnostic'];assert len(q)==5
profile_text='\n'.join(f'- {k}：{statistics.median(x[k] for x in q):.9g}'+(' B' if 'bytes' in k else ' 秒') for k in ['conversion_wall_including_offline_s','conversion_offline_s','conversion_wire_bytes','pack_s','GF129_mask_offline_s','GF129_mask_online_s','GF129_mask_wire_bytes'])
final=r'''# PMEQ 安全结果提取最终决策

**结论：CONDITIONAL。已找到并完整实测一个在 M≤3、按锚重用结构成立时优于全域秘密置换的独立返回构件；未找到、也不宣称找到对全部 M 都降低完整成本的通用替代。** 推荐 G-BRE（Grouped-anchor BCH–Ring Extraction），M≥4使用原私有置换回退。全部M的输出保持精确；小M优势不能外推到高M。正式仓库、论文、原始数据和上一阶段证据均未修改。

## 第一部分：最后推荐哪个方案

### 接口与数学原理

云u输入原来的Boolean Keep份额 b_i^(u)、动态模2^64锚ID A_c^(u)、已经正确对齐的目标ID T_i^(u)，i=cN+j，L=KN。锚ID在同一公开c行重复；目标ID可随(c,j)动态变化。输出到授权QU是有重数候选对列表 {(A_c,T_i):b_i=1}，云只得到总数M，QU继续原有编辑距离验证。**没有把候选提取称为最终编辑距离结果。** 原PSMJ匹配、位置过滤、秘密关联聚合、桶/全域映射、跨块累积和最终SCMP均不变。

推荐原始出口 G-BRE；如果调用方已经完成原两ID逐槽掩蔽，则使用 RC-BRE（reuse-count BCH–Ring），保留原B2A已有的总数Ring份额，新增在线仅打开该总数；已有掩蔽成本必须仍计入完整边界。两者是同一个有界稀疏BCH／模环编码族，不是两套无限扩张的替代研究。

G-BRE流程如下。

1. DO离线为每槽提供r的Boolean/Ring双共享、独立目标掩码t及[rt]，为每锚/公开编码行提供独立Ring Beaver triple，同时完整预留私有置换银行。DO无需知道未来锚ID、Keep、M或查询令牌，在线不参与。
2. 仅开e=b XOR r，计算[B]=(1−2e)[r]+e·1_u，局部求和后开M。原Keep、Mc和坐标均不打开。
3. M=0空返回。M=1仅需两个Ring总和。M=2/3：目标侧开f=T−t并算[Yγ]=(1−2e)([rt]+f[r])+e[T]；其重构严格为bT。按公开行a_0(i)=1、a_(k+1)(i)=bit_k(i)聚合W_(c,k)=Σ_j a_k(cN+j)[B_i]，只对秘密W和A_c做K(h+1)次普通RingMul。yδ_k=Σ_c[A_c W_(c,k)]，yγ_k=Σ_i a_k(i)[Yγ_i]。所有c都执行，W和Mc均秘密。公开dyadic树隐式计算，非稠密逐槽逐行矩阵。
4. 本地对**原Boolean Keep份额**执行GGS Definition19/Lemma23的转置加法FFT，获得GF(2^32)中M个奇数BCH矩。α_i=(1<<h) XOR i，h=ceil(log2L)，L≤2^31；域模多项式z^32+z^7+z^3+z^2+1已独立Rabin证明不可约。
5. 每云最后一次发自己的编码份额给QU。QU合并奇矩，用Frobenius补偶矩，BM及确定性全32维trace分裂恢复至多3个根；无随机失败、无扫描L。二元仿射行的任意≤3列在F2满秩，所选minor具有奇行列式，故可在原Ring模2^64逆解两ID，使用同一支持和同一逆矩阵保证配对和重数。
6. M≥4直接原私有全域置换，公开的只有置换后Keep位置，原位置由另一方秘密排列遮蔽；仅向QU返回M对。计数和完整备用材料都收费。容量不够在公开维度校验时拒绝，绝不截断秘密结果。

正确性是逐项代数恒等式，加上BCH Vandermonde距离界与小M模环minor引理。ID为0/0、最大64位、重复ID及模环回绕均合法；载荷无须非零标记，支持来自Keep。M=4的矩形位置0,1,2,3明确产生Ring编码核(1,−1,−1,1)，所以不得把小M解码扩展到4；回退是协议组成部分。

### 预处理、复杂度与新鲜性

令公开cap=Lmax=Kmax N，hmax=ceil(log2cap)。G-BRE完整材料body是
`152 cap + 8 ceil(cap/8) + 48 Kmax(hmax+1) + 16` 字节；另8个56B文件header。该值**包括整套104cap+6ceil(cap/8)字节置换回退银行**，不因为M小就省略。所有银行先生成，支持容量前缀；回退补公开零至cap。M1实际只用一行锚乘法，但仍计满预留。

M≤3云间应用字节分别为：M0 `2ceil(L/8)+164`；M1 `16L+2ceil(L/8)+32K+312`；M2/3 `16L+2ceil(L/8)+32K(h+1)+312`。M≥4为count消息加完整cap置换 `32cap+4ceil(cap/8)+74ceil(cap/4096)+74`。QU收到144B(M0)、176B(M1)、`32(h+1)+8M+144`B(M2/3)，或`32M+144`B(回退)。这些是实际应用write/header公式，非TCP/IP/TLS网络字节。

块C=4096，Keep FFT为O(L log R)，R=nextpow2(2M)且这里R≤8。Ring树总O(L)，公开区间分解和高位行处理可保守界为O(h(L/C+K)log C)，另K(h+1)安全Ring乘法。编码分支内存O(L/8+Kh+C)，用户小M恢复poly(h,M)，不用接收或遍历L。完整协议仍预留O(cap+Kmax hmax)离线材料；回退及本机DO银行生成仍可能占O(cap)内存，不能称全协议常数内存。N很小时K h不再远小于L，优化不保证有效。

每票据使用独立秘密256-bit DO种子及唯一nonce；现原型PRG标签不自动含nonce，因此只换binding但复用同keyfile不安全，严格禁止。每个耦合票据一次claim，未用备用银行也退休；实际复制重放测试已拒绝。O_EXCL固定registry是正常运行防重复原型，崩溃后持久原子消费和生产密钥池仍待实现。云各持本方状态，私有信道向QU；单机同UID两进程验证执行分离，不证明恶意OS隔离。

具体公式/证明：[grouped-protocol-proof-zh.md](grouped-protocol-proof-zh.md)，源码：[roles-grouped-ring.cpp](roles-grouped-ring.cpp)、[small_bch.hpp](small_bch.hpp)，原生接口条件：[integration-interface.md](integration-interface.md)。

## 第二部分：能否直接写进论文

**可以写进论文作为明确限定M≤3的Secure Result Extraction组件、完整回退协议和真实实验；不能把它写成已实现GGS全稀疏度快速解码，也不能直接宣称正式PMEQ集成与整篇安全证明已经完成。**

| 类别 | 已有证据与边界 |
|---|---|
| 自行严格证明 | 选择重构bT；锚侧分配律与原逐槽编码等价；至多3列二元满秩/奇行列式模环可逆；GF32不可约证书；BCH支持唯一性；重复值、零与最大ID正确；M≥4回退不丢弃结果 |
| 文献直接支持 | GGS26 Definition19/Lemma23转置FFT线性编码；原PMEQ RingMul/B2A及G3私有置换模拟（沿用其假设，未独立重写全部底层证明） |
| 实验已验证 | 两真实云进程，各只接受本方输入/材料路径；完整offline、实际write/QU文件；五次中位数；私密随机材料、容量前缀、重放拒绝；原生LLAMA SCMP出口与原masked pair逐槽/多重集一致 |
| 尚待生产/完整证明 | 正式typed packet/serializer接入；崩溃一致票据消费；密钥池新鲜性；生产私有角色隔离；通用并发/恶意安全；现native 26K域与归档论文KNγ全域语义一致性；全MusicBrainz/TPC-H原查询一遍运行及G6完整定稿 |

模拟论证限定非串通半诚实两云、可信离线DO及私有本方状态：e/f联合均匀且与输入无关；对本方count share而言peer share由M唯一确定；每个锚乘法的W−u、A−v使用独立Ring掩码，包括同A重复调用；本方编码是本方已模拟视图的局部函数，另一方QU消息不送云；回退调用G3模拟。此为组件混合/顺序组合论证，详见[security-review.md](security-review.md)，不是UC、恶意或耐崩溃实现证明。理论相关随机量是完美安全，AES展开是原PRG假设下计算安全。

泄露为既有公开域/桶访问/K/cap/票据数量和M；不含Mc、原Keep、原坐标及跨查询支持关联。分支、循环、消息长度只依赖这些公开量。QU解码错误不回传云。正式`SECURITY_INVARIANTS.md:441`仍有隐藏实际基数的旧承诺，归档G6 AP与本任务允许M；定稿必须显式统一版本，不能宣称相对隐藏M定义完全不变。

### 独立核查上一阶段

上一阶段确实实现了GGS快速**编码**，GF129双ID打包也无损（最高有效位可保障0/0非零）；但一般M快速解码Theorem25未完成，旧全M解码有慢子过程。不能凭小样例说复现论文完整快速算法。原Ring份额不能直接当GF XOR份额；合法转换涉及进位安全电路，成本高。新构造彻底留在原Ring，仅对Keep的原Boolean份额做GF32线性运算，无ID转换，也不需要目标GF长期侧表。方案B静态返回共享状态无法自行处理动态锚/目标路由，未列为已验证生产捷径。

阶段1原CSV、1432行分类、源代码、命令/原始日志和哈希独立核查结果见[phase1-independent-audit.json](phase1-independent-audit.json)与[paper-review.md](paper-review.md)。GGS作者PDF SHA256为`120ed217d3532526c0be64b25f3407f1102bd9ecd0ded60a092b52f53173ac43`；作者Pascal Giorgi、Bruno Grenet、Mark Simkin，2026-02-22元数据版本；EUROCRYPT2026 PartV pp366–391。论文来源[作者PDF](https://membres-ljk.imag.fr/Bruno.Grenet/publis/GGS26.pdf)、[DOI](https://doi.org/10.1007/978-3-032-25330-9_13)。官方实现搜索未找到，不等于证明不存在；ePrint下载403已记录，没有假称读到。

### 严格测试

870条实际主性能记录，174组各五次，中位数独立按字节公式审核。不同版本和输入边界不混池，旧v2离线RSS没有测则留空。正确性证据还包括：重跑原GF129 160例；820组随机BCH/Ring支持和680组三元支持；20k次域乘法对照/1000逆；45个任意Ring密集向量dyadic树oracle；最终私密G容量/重复/边界70例；原生raw出口与旧native masked pair等价30例；v5 CountReuse30例及备用退休检查；120例离线先生成容量测试；60例单方视图/新鲜秘密份额；20例有意超容量/无回退等拒绝；五个私密600万槽测试和同输入A/B/G十五个严格时钟实验。各版本额外smoke结果不用于凑唯一测试数。4096视图枚举是Z2缩小模型证据，非一般域安全证明。

原native测试用原已存在的测试audit sink导出**各自原始**selected份额；用旧原生masked pair定义QU oracle，逐槽校验b乘原ID。不把两方重构明文重新分享冒充接入。可信fixture可读两方进行核验，执行中的两云只拿各自路径。sink不可上线。Go Run覆盖82.0%、targetaggregation总语句70.2%，不是全部PSMJ覆盖率。详见[correctness-report.md](correctness-report.md)、[native-grouped-equivalence-results.json](native-grouped-equivalence-results.json)、[grouped-private-large-results.json](grouped-private-large-results.json)、[strict-private-performance.json](strict-private-performance.json)。

## 第三部分：到底快不快

主比较使用同一raw BooleanKeep＋Ring ID边界，L=60,012,150，K=10，M=2，五次固定种子。A含计数/两ID安全选择/全量输出；B直接原始槽全域私有置换，无多余先掩蔽；G含计数、目标选择、按锚RingMul、FFT、QU解码及**整个未用备用银行生成**。所有offline先于查询fixture。配对性能实验在独立registry的反事实世界使用同一初始share与备用银行以控制变量，每个方案均收费；这是实验对照，生产多查询不得复用这些材料。后面的私密完整时钟实验则对每个方案实际生成全新独立DO密钥和银行。

__TABLE__

相对B，G的在线阶段时间和快 **__ONLINE__倍**，离线+在线阶段时间和快 **__COLD__倍**，云间应用字节少 **__SAVING__%**；离线材料反而多 **__EXTRA__%**。用户1024B vs B208B，均轻量；A约1.935GB，虽本机生成/读写更快但不满足短结果目标。未测WAN/TLS和离线材料网络分发，不能据此声称部署网络端到端快同样倍数。

**计时边界审计：** 主表`online_return_wall_s`=实测并行两云parent墙钟+QU内部解析解码，`end_to_end_cold_return_s`=实测offline生成/fsync加该阶段和。含两云进程启动、票据claim与材料读取；未含QU子进程启动、外部fixture/hash、独立expected检查。必须叫阶段时间和，不能叫单个完整外层时钟。CPU是两角色getrusage之和；编码/计数等各子计时之和不得再当并行墙钟。两个RSS高水位之和是可复测上界指标，不是同时采样峰值。G完整DO离线仍9.129GB，完整stage内存上界应取DO/两云高水位和/QU的max，约9.129GB；B约14.928GB，不能用G单云22.5MB冒充完整预处理峰值。

补充同一600万私密raw输入（L=6,001,210,K=10,M=2）A/B/G真实outer clock，所有完整银行先于fixture，由秘密DO种子生成，各五次。`strict_protocol_wall_s`=两云实际parent墙钟+QU子进程实际墙钟−单独测量的expected validation；另外保留含oracle的实际外层harness墙钟。它补足前表QU进程启动漏项，但不是对60m完整时钟的外推。

__STRICT__

__STRICT_RATIO__

补充真实负载**形状**（K/M来自归档查询统计/原实验域）如下。payload与Keep用可复现随机份额生成，不是假称整个数据库查询都重跑了；实际原生接口另有上述真实SCMP测试。

__SMALL__

MusicBrainz M667走原置换，G多计数及备用材料，完整阶段时间和18.749s vs B17.718s，**没有全成本收益**。其online中位数稍低属于同算法/本机缓存与调度差异，不作为算法优势。M10/100/1000已在final-v5的1m组实测回退；M=L只在安全小规模。没有完成最初所有L×M笛卡尔积的**最终G全成本**重复测试，尤其60m其余M，不能声称该完整矩阵已验证；范围在CSV逐行列明。M0的早停也可加在置换前，是通用优化，不应算作G专属突破。

### 真正瓶颈与保留的优化

1. 原GF129输入转换是瓶颈。65536槽、五次单进程内核诊断中位数如下；不是物理两云协议的端到端证据，不与主表混比：

__PROFILE__

2. 无锚聚合的raw BCH/Ring仍要逐槽两ID选择，线上约32.25L字节，完整185L材料，真实raw-adaptive表没有全成本优势。即使masked边界只需90B count，前面的选择成本不能消失。
3. G保留原Ring且利用同锚重用，将一侧L次掩蔽乘法替换为K(h+1)次，才获得完整raw阶段约16.25L通信的实质下降。没有通过公开Mc、ID或者除Mc来恢复锚。
4. byte-table/KeepFFT优化使1mM2局部编码0.018698→0.011094s约1.69倍，但完整raw在线0.067901→0.067793s无可测显著收益；只认局部收益。streaming duplex减少分块往返/内存，但未测WAN，不写WAN吞吐结论。
5. 全额备用银行生成是当前最大的剩余瓶颈：仍约153L材料、大DO内存，高M没有优势。更大L=311,099,472的全银行/双置换内存超过本机资源预算，未运行；旧小分支性能不可当作新完整银行实测。L>2^31也超过当前GF32标签界限。[larger-resource-review.json](larger-resource-review.json)只有公式预算，未计成功性能。

## 第四部分：论文必须改哪几处

以归档G6文本为准，SHA256 `97d0522323b289c6978776c89ba965e2fd1c12ef72378a7c62c10e4e638a52c2`；正式Final29是另一个G0–G5版本，不可套用这些行号。所有精确原样上下文在[paper-edit-locations.md](paper-edit-locations.md)。推荐完整可粘贴英文：[pmeq-extraction-grouped-draft.tex](pmeq-extraction-grouped-draft.tex)，中文：[latex-explanation-zh.md](latex-explanation-zh.md)。草稿没有覆盖原文；环境没有TeX引擎，未声称PDF编译通过。

1. **保留5(1) 1331–1343行**的原文调用`Keep ← SCMP.Comp(C,lambda)`及此前所有步骤，零修改。
2. **替换5(2) 1345–1376行**。原文：

```latex
the servers recover $\mathsf{Keep}_c^{\mathtt P}[j]$.
If $\mathsf{Keep}_c^{\mathtt P}[j] = 1$, the servers compute
```

这一原文明确开了原Keep，与任务约束冲突，不能保留。替换为：

```latex
Let $i=(c-1)N_\gamma+(j-1)$ and $L=KN_\gamma$.
After Step~5(1), the servers retain their Boolean Keep shares and
the original ring shares of the aligned identifiers. They invoke
$\mathsf{G\mbox{-}BRE}$ with the public dimensions and a fresh
offline extraction ticket. Only $M=\sum_i b_i$ is opened.
Each server sends its final encoding share directly to the query user.
The complete protocol and its bounded-sparsity decoder are specified
in the Secure Result Extraction component below.
```

3. **步骤6开头1379–1395行**原文`The query user reconstructs the candidate record pair`改为：

```latex
The query user reconstructs and decodes the two extraction messages
to obtain the multiset of all $M$ candidate record pairs, preserving
multiplicity and the pairing of identifiers. It then retrieves the
corresponding records through the existing authorized data-access
mechanism and performs the original local edit-distance verification.
```

原ED公式及取记录授权机制保持。
4. **offline 935–945行存储状态前**，原文`Each CS_u stores its local shares ...`后新增，不重写Outsource：

```latex
The owner additionally prepares a public-capacity pool of fresh,
query-independent extraction tickets. Each ticket contains only the
appropriate party's shares of the correlations and a complete private
permutation fallback bank. The servers bind and consume one ticket per
query, retiring unused branches as well. All materials are distributed
offline; the owner is absent from query processing.
```

组件中的材料定义/容量/成本全文必须一起加入，不能仅添加这段抽象调用。正式生产packet需要替换旧最终B2A/两Mask材料，而非两套都保留却只计一套。
5. **AP 1422–1429行**原文`the number of returned tuples`明确化：

```latex
The returned-tuple count is the single total $M$; it does not include
per-anchor counts, the original Keep vector, original hit coordinates,
or cross-query linkage. Extraction message lengths depend only on
the existing public parameters, the public capacity, and $M$.
```

同步旧隐藏M实现说明属于版本一致性工作，不能删去这一条件。
6. **G6仅替换尾段1762–1776行**。原文`S calls the simulations of B2A and Mul to simulate Pair...`并交付逐槽returned shares；修改为：

```latex
After simulating the unchanged matching, aggregation, and comparison
steps, $\mathcal S$ invokes $\mathcal S_{\mathsf{SRE}}$ on the corrupted
server's local input shares and the permitted leakage, including $M$.
It samples the masked selector openings, derives the peer count share,
and invokes the ordinary ring-multiplication simulators for all public
anchor-row products. Local encodings are deterministic functions of
this simulated view. For $M\ge4$, it invokes the private-permutation
simulator from $G_3$. The peer's final message is delivered only to the
authorized user. Fresh offline correlations and private output channels
give the required sequential composition under the stated assumptions.
```

完整独立构件定义、两个正确性引理、单方模拟命题及全部条件在英文草稿中。不要重写之前匹配/聚合/G3，也不要把这段当作已完成所有底层协议证明。

原生`native-count-share.patch`是RC-BRE选项的本地字段/求和接口，已`git apply --check`通过，未应用。G-BRE生产raw Packet改动尚未实现；测试audit导出不是可直接上线补丁。全域对象对齐必须由现PSMJ提供，不由SRE改变。

## 第五部分：剩余工作与投入边界

**已完成且有证据支持：** 上阶段独立审计；原算法真实encoder/decoder缺口定位；GF32证书；小M支持与Ring恢复严格证明/实测；G分配律优化与密集oracle；物理双进程全成本比较及五次重复；私密大输入/完整时钟；原native原份额/原masked oracle接入；正负容量/重放/重复编号；两份英文草稿/最小定位/未应用补丁；正式文件与阶段1哈希保持。

**已实现但条件未闭合：** G/RC组件正常运行安全与一次性ticket；单机AF_UNIX物理通信并非跨主机环境；AES新鲜key规则依赖调用方遵守；票据消费未做崩溃原子持久化；大M原置换回退全成本没有收益；全域native版本与论文版本接口要对齐。

**尚未实现：** 正式G-BRE typed integration与相关材料packet；真实数据库整查询重新评测；生产密钥池和崩溃恢复；WAN/offline分发计时；GGS Theorem25一般M快速解码；大于2^31的标签扩展；整篇G6组合证明最终核稿。不存在已部署/已编译PDF/已验证大M更快的结论。

**不建议继续投入：** 用稠密矩阵/随机哈希假冒GGS快速构造；把GF XOR运算直接抬到Ring；把≤3仿射编码硬扩到4；在当前机器运行明显超预算完整银行；继续优化pack微秒而忽略离线银行和逐槽安全选择。若真实负载多数M≥4，建议保留原置换，不强加G的额外备用材料。

最终直接回答：**已经找到M≤3时完整本机成本和云间通信均有真实优势、保持PSMJ主体不变且QU轻量准确恢复全部候选的方案；全部M可精确回退，但没有证据支持对全部查询普遍优于全域秘密置换。可作为有界组件写入论文，正式全域集成/生产保障与最终证明仍是CONDITIONAL。**

复现：[REPRODUCE.md](REPRODUCE.md)。原始测量：[performance.csv](performance.csv)、各版本JSONL与严格时钟JSON；审核：[performance-audit.json](performance-audit.json)。保护检查：[preservation-check.json](preservation-check.json)。没有将公式外推或内核模拟计作真实协议性能。
'''
final=final.replace('__TABLE__',table).replace('__SMALL__',small).replace('__STRICT__',strict_table).replace('__PROFILE__',profile_text)
for key,value in [('ONLINE',online),('COLD',cold),('SAVING',saving),('EXTRA',extra)]: final=final.replace('__'+key+'__',f'{value:.3f}')
sb,sg=strict[1:]
final=final.replace('__STRICT_RATIO__',f'该私密严格进程时钟中，G在线比B快{val(sb,"strict_protocol_wall_s")/val(sg,"strict_protocol_wall_s"):.3f}倍；计入全部offline后快{val(sb,"strict_cold_protocol_s")/val(sg,"strict_cold_protocol_s"):.3f}倍。结果说明QU进程启动计入后仍有优势，并未把内核计时冒充完整协议。')
assert '__TABLE__' not in final
(P/'FINAL-PMEQ-EXTRACTION-DECISION.md').write_text(final)
morning=f'''# 早晨摘要

1. **找到了吗？** 找到有界有效方案：M≤3；全部M准确性通过原置换回退保证，未找到全M通用性能优势。
2. **哪条最好？** G-BRE：按锚聚合的 BCH／原模环安全提取，避免ID有限域转换；M≥4回退。已masked出口可用RC-BRE。
3. **快多少/省多少？** L=60,012,150,K=10,M=2五次中位数：在线阶段和{f(G,'online_return_wall_s')}s vs {f(B,'online_return_wall_s')}s，快{online:.2f}倍；云间{integer(G,'cloud_bytes')}B vs {integer(B,'cloud_bytes')}B，少{saving:.2f}%；全部材料生成+返回阶段和{f(G,'end_to_end_cold_return_s')}s vs {f(B,'end_to_end_cold_return_s')}s，快{cold:.2f}倍。离线材料**多{extra:.2f}%**。这些是本机阶段和；另600万私密输入完整进程时钟在线{f(sg,'strict_protocol_wall_s')}s vs {f(sb,'strict_protocol_wall_s')}s，完整cold {f(sg,'strict_cold_protocol_s')}s vs {f(sb,'strict_cold_protocol_s')}s。无WAN外推。
4. **保持PSMJ原样吗？** 主体及5(1)不变，只新增最后提取和必要材料。正式文件未改；原生出口测试通过，生产raw接口/全域版本对齐还未集成。
5. **QU轻量且全部恢复吗？** 是：M2大测试仅1024B，解码约{val(G,'user_decode_s')*1000:.3f}ms；重复、零/max ID与配对均验证。大M回退收32M+144B；仍需原编辑距离验证。
6. **能用于论文定稿吗？** 可写已证明小M构件、完整回退及实验，整体**CONDITIONAL**；不能声称完成GGS一般快速解码或正式全域部署与全部安全证明。
7. **最严重问题？** 完整备用置换银行仍O(L)离线开销/DO内存，M≥4没有完整成本收益；production ticket/key/崩溃隔离与native26K→论文KNγ语义对齐尚待落实。

所有870主测量记录均真实执行、174组各五次；另有原生/私密/边界/负例。正式266个tracked文件、原已有工作树状态、阶段1报告/source哈希保持。详见[最终决策](FINAL-PMEQ-EXTRACTION-DECISION.md)、[正确性](correctness-report.md)、[安全性](security-review.md)、[实际数据](performance.csv)、[严格完整时钟](strict-private-performance.json)。

推荐英文独立草稿：[pmeq-extraction-grouped-draft.tex](pmeq-extraction-grouped-draft.tex)；[原文精确位置](paper-edit-locations.md)、[集成边界](integration-interface.md)、[复现命令](REPRODUCE.md)。没有覆盖正式论文。
'''
(P/'MORNING-SUMMARY.md').write_text(morning)
(P/'feasibility-report.md').write_text('''# 第二阶段可行性判定

**CONDITIONAL（全PMEQ集成）；PASS仅限已证明/实测的有界独立构件，不是原GGS一般快速方案。**

G-BRE利用同锚ID重用，把anchor逐槽安全选择替换为公开行聚合后的K(h+1)个秘密Ring乘法；原PSMJ5(1)以前不变，QU准确恢复全部M候选，小M≤3用BCH/Ring，M≥4回退原私有置换。ID无跨域转换，无DO或QU中途在线。完整备用材料全计入。

实测比较、全部正确性/安全假设与正式集成限制详见[FINAL-PMEQ-EXTRACTION-DECISION.md](FINAL-PMEQ-EXTRACTION-DECISION.md)。数学正确性已闭合于该接口；生产typed binding/原生全域语义、崩溃原子ticket、key新鲜性和整篇组合证明未最终集成。高M全成本不优，不可通用PASS。原GGS Theorem25完整快速解码没有实现，不推荐现GF129跨域输入准备作为PMEQ通用加速路线。
''')
(P/'final-verdict.txt').write_text(f'找到M≤3时优于全域秘密置换的G-BRE：60,012,150槽/K10/M2实际五次在线阶段和{f(G,"online_return_wall_s")}s vs {f(B,"online_return_wall_s")}s（{online:.2f}倍），云间少{saving:.2f}%；计全部备用银行离线与在线{f(G,"end_to_end_cold_return_s")}s vs {f(B,"end_to_end_cold_return_s")}s。全部M精确回退，但无全M通用性能优势。整体CONDITIONAL，正式PSMJ/论文未修改。\n')
print((P/'final-verdict.txt').read_text(),end='')
