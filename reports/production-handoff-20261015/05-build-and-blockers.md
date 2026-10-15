# 05 编译检查、容量事实与阻塞顺序

## 本轮允许的实际检查

没有运行测试函数、密码算子、在线查询或秘密索引构建。`go test -exec /bin/true -run '^$'`仅编译/链接测试包，并用/bin/true替代测试可执行文件；日志中的`ok`不代表测试正确性通过，秒数也不是协议性能。数据库检查仅catalog、MOVIE小表静态计数和最终100k候选子集公开画像。

### 环境

- go version go1.27.1 linux/amd64，SDK为`artifacts/n-domain-regression-pilot-runtime/go/bin/go`；默认PATH无go。
- g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0；OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)。
- Module pmeq/Go1.27.1；ristretto255 v0.2.0、edwards25519 v1.1.0；GOMODCACHE=`verification/anchor-replacement/cache/mod`。
- Python3.12虚拟环境`imdb_final_dataset/.venv`，duckdb1.5.6；唯一需补传的依赖声明是`imdb_final_dataset/requirements.txt`。
- 原生库`/home/tenggn/projects/clean_pmeq/imdb_q_crypto_preexperiment_20261014/native/libphase6scmp.a`，143132字节，SHA256=`73fcbbccf6e42345f3c861caa4d3ff52383048a7c867d39eb5926b27e58d529e`。本轮没有重建或上传.a。
- 真实桥：tools/build_phase6_native.sh、phase6_scmp_bridge.cpp、scmp_key_codec.h；依赖third_party/ezpc_fss pinned repaired LLAMA；C++17/O3/AES/SSE2/SSE4.1/PCLMUL，链接stdc++/crypto/pthread。其他目录同名.a不能混用。
- 编译限制：GOMAXPROCS=2，包并行1，GOMEMLIMIT=1GiB（GC目标不是OS硬上限），单命令180秒；GOPROXY/GOSUMDB=off、GOTOOLCHAIN=local、-mod=readonly；缓存/临时产物只写/tmp；没有安装或下载依赖。只读画像DuckDB512MB、单线程，Python地址空间6GiB、180秒期限。

### 结果

| 检查 | 结果 | 证据 |
|---|---|---|
| go build -p 1 -tags phase6native ./internal/... | 通过，退出0 | evidence/production_native_build.log与resources.txt，峰值RSS253252KiB |
| 所有internal测试包只编译/链接 | 未通过，退出1 | evidence/test_compile_only.log，峰值RSS106496KiB |
| discovery单包-gcflags=-e补全错误 | 未通过，17条定位 | evidence/discovery_compile_all_errors.log；没有运行测试 |

生产库可编译不证明电影外包、当前位置域或正式查询正确。旧测试需要更新到新锚标签/诊断接口，不能通过恢复旧锚矩阵字段“修好”。

### 精确编译阻塞

```text
internal/discovery/diagnostics_test.go:25:108: b.HitB2A undefined (type AnchorBlock has no field or method HitB2A)
internal/discovery/diagnostics_test.go:25:153: b.Incidence undefined (type AnchorBlock has no field or method Incidence)
internal/discovery/diagnostics_test.go:25:208: b.ReservedDenseProducts undefined (type AnchorBlock has no field or method ReservedDenseProducts)
internal/discovery/diagnostics_test.go:25:250: b.ObjectThreshold undefined (type AnchorBlock has no field or method ObjectThreshold)
internal/discovery/diagnostics_test.go:31:72: b.HitB2A undefined (type AnchorBlock has no field or method HitB2A)
internal/discovery/diagnostics_test.go:31:82: b.Incidence undefined (type AnchorBlock has no field or method Incidence)
internal/discovery/diagnostics_test.go:31:95: b.ObjectThreshold undefined (type AnchorBlock has no field or method ObjectThreshold)
internal/discovery/diagnostics_test.go:41:17: operations.DenseProducts undefined (type AnchorOperations has no field or method DenseProducts)
internal/discovery/diagnostics_test.go:41:47: s.Operations.DenseProducts undefined (type AnchorOperations has no field or method DenseProducts)
internal/discovery/diagnostics_test.go:42:17: operations.IncidenceChunks undefined (type AnchorOperations has no field or method IncidenceChunks)
internal/discovery/diagnostics_test.go:42:49: s.Operations.IncidenceChunks undefined (type AnchorOperations has no field or method IncidenceChunks)
internal/discovery/diagnostics_test.go:47:10: b.Incidence undefined (type AnchorBlock has no field or method Incidence)
internal/discovery/domain_test.go:155:61: unknown field Incidence in struct literal of type AnchorStatic
internal/discovery/token_signature_experiment_test.go:150:18: u.f undefined (type *UserPacket has no field or method f)
internal/discovery/token_signature_final_validation_test.go:42:18: u.f undefined (type *UserPacket has no field or method f)
internal/discovery/token_signature_final_validation_test.go:87:53: d.f undefined (type cloudToken has no field or method f)
internal/discovery/token_signature_final_validation_test.go:92: d.f undefined (type cloudToken has no field or method f)
```

## 已证实的结构性问题

| 项目 | 事实与源码 | 修复边界 |
|---|---|---|
| 参数与字段域分散 | anchorindex/logical_key.go、targetcrypto/canonical.go仍area/area_alias；indexbuild.Q与多个token编码器固定4 | 做当前IMDb专用集中参数和typed输入，不开发任意数据库框架，不只改parser |
| 宽位置未贯通 | discovery/offline.go与targetposition.Preprocess仍7，token生成Upos62，cloud.OpenMaskedPositions(…,7)，targetposition.Begin限制4h/62/127 | 主原生支持7/10不代表在线已适配；同配置传递给所有阶段，不能截断 |
| 目标重复次数 | 全MOVIE q4最大12；本次10k候选最大4（2对象超3），100k最大9（11对象超3） | 当前gen/sidecar.go `counts[id]>3`明确拒绝；sidecar.go、protocol.go亦绑定3，需按最终样本固定并验证，不能仅改manifest |
| 电影生产入口缺失 | 当前无cmd/电影DO，旧音乐测试并非入口 | 新增固定电影配置装配入口，保留对象≠连接支持，禁止读旧状态 |
| 测试接口过期 | 上述4个测试文件引用旧锚Incidence、DenseProducts、u.f/d.f | 按锚zero/目标matrix现方案更新测试，不恢复废弃字段或吞编译错 |
| r4专用查询尚未显式化 | 当前query默认取全部floor(len/4)块 | 若采用07的固定r4，应从完整原始查询选4个完整块；不改原文，且两侧token/offline/计数一致 |

## 位置位宽、符号和掩码

`anchorfilter.DeriveBin`要求 `Upos+1 < 2^(Bin-1)`，同时ConsumeBounds验证用户预处理bin相等，masked界为L和R+1（模2^Bin）。这是带符号比较安全域，不能只看“273小于512”就认定9位足够。

| q | 母库锚最大0基位置 | 目标最大0基位置 | 最小签名安全Bin（锚/目标） |
|---:|---:|---:|---|
| 3 | 270 | 239 | 10 / 9 |
| 4 | 269 | 238 | 10 / 9 |
| 5 | 268 | 237 | 10 / 9 |
| 6 | 267 | 236 | 10 / 9 |

原生后端只支持7或10，不支持9。统一Bin10、Upos270可覆盖这四种q位置，是前次局部单元测试已有的候选参数；正式本轮仅按q4设计，不开展四q性能实验。Bin10掩码0..1023、Bout1、opaque368字节；必须同步Go/native/C ABI/keycodec/掩码/预处理/token/位置打开函数与校验。计数的Z128/Bin7仍保留：r≤14/16、目标重复最大12均小于64，但扩大重复次数边界后仍需正确性测试确认，不能把计数域一起粗暴扩位。

## 矩阵维度与全局数量

目标本质是每电影1个MOVIE对象，D26含25个公开虚位；当前实现只支持16或26，不能擅自改为1。目标每桶矩阵D×T，T是该桶填充posting总数；每组另存D个目标ID份额。重复同q的各位置仍为不同posting，不能删除以绕过MaxMultiplicity。

每方TG01字节公式：

```
57 + 4*B + 4*G + D*L + 8*D*G
```

G为目标逻辑(join,q)组数，L为填充槽总数，B=65536。两方乘2。这是源码格式精确字节算术，不是完成的外包存储实测。当前代码会因重复次数先拒绝，须修复统一参数后才可能实际构造。

`Lineage.N`是锚对齐域而非目标行数，100k×10k可表示；真实风险是用错N或把对象ID当连接ID，不是必须把两表补齐同样大小。当前uint32域能容纳100000，Ring64业务载荷也足够；120071是旧默认wrapper，不是动态ForDomain的统一上限。

## 分桶、填充和资源风险：不要把统计画像当已通过生产

- 真实填充梯度最高32768；锚GF局部D≤32768、T≤65536；公开画像中的候选100k锚最大组10022、最大桶T16404/D16384，暂未超这些上限。正式秘密密钥改变桶布局，必须先计数、验证才分配大状态。
- public profile使用明确公开测试键与候选IMDb字段帧。它不是秘密索引，且字段域尚待正式固定；分桶最大值仅是该画像，不是所有密钥的确定上界。
- 锚CS1静态σ每非空桶4*N_anchor字节；本次53116非空桶，N=100000约19.787GiB。不能因为K小就忽略O(N×非空桶)静态存储和DO构造循环。此处只算当前源码的结构成本，未从旧性能数字推算时间。
- 全局Keep比较O(N)，压缩也保留全域数组。Go对象/切片/GC与多进程复制会高于序列化字段计数。`go build`的约0.24GiB不是未来运行峰值。
- 目标路由是K×r次，S/G容量必须覆盖重复路由访问；不得仅按唯一桶数或最终ED命中数预算。目标位置宽到Bin10会增大每槽SCMP字节。
- 预算在07：仅一个离线查询批次；公开C=10000时100k×100k超限，不能执行。C=1024虽预算下降但诊断有3次K超限；不得丢弃这些结果伪称全通过。
- 未测DO临时峰值、实际Go堆、磁盘序列化速度、两个独立云进程RSS和真实密码延迟/通信；没有资源许可就不启动正式构造。当前磁盘是否足够按07规划总额检查，但速度未知。

## 建议的第一个正式迁移任务与顺序

首先由用户决定07中的最终配置/公开容量/查询域；若超预算，保留现规模，报告后由用户选择，不自动缩减。

选定后，一次实现**当前IMDb与最终规模的专用生产契约和入口**：集中固定参数与预算→来源ID/连接ID映射及固定字段域→q/r/位置/比较域同步→BS02/PS01/PL01/TG01/QU12/用户恢复绑定→构建前/在线容量拒绝门→DO/离线/云/用户命令。锚zero、目标matrix保持数学语义；然后修复上述过时测试并用最终冻结规模做端到端验收。小型单元测试可验证编解码与边界，但不走1k→5k→10k反复改架构路线。

用户恢复后是否加完整ED仍待最终数学定义确认；交接包先完成，不以未确认内容擅自重写协议。缺失信息、范围与复现命令见README及07。
