# IMDb 100,000 × 10,000 生产迁移：第一轮验收

日期：2026-10-15。基线为本工作区当前源码及 `reports/production-handoff-20261015/`。交接包所称提交 `b1276fe4e1bf1988da068e99215f1c5e68983068` 在本地对象库中不存在（`git cat-file -t` 返回 bad object）；本轮没有获取远程提交，也没有重置或覆盖工作树。开始时已有大量修改和未跟踪文件，本轮未清理它们。

## 已冻结的唯一正式样本

`imdb_production_20261015/` 来自只读的 `imdb_final_dataset/data/imdb_final.duckdb`，按交接报告 07 的 SHA256 排序及种子 `20261015` 取前 10,000 个 `expectedRows>0` 电影，再从这些电影的真实 `MOVIECAST_OBJECTS` 中取前 100,000 条。未改动母库。锚对象序列 SHA256 为 `7a31b5cc73af844a2a9fec83d964fd7e7927d4aee597047b10c2c241eede4fb7`；目标序列为 `b9f050071281497cdc123321be8aa498af77dc30e8ff494d43574f47e3d0b488`，均等于交接包。锚连接覆盖 8,895 部电影，目标有 1,105 部电影没有选中的锚关联，全部锚连接可在目标集合中解析。

`manifest.json` 记录采样规则、顺序、母库/来源清单哈希及每个样本文件哈希。`MOVIECAST_SOURCE.parquet` 与 `identity_map.jsonl` 保留 100,000 条来源元组；`repeated_sources.jsonl` 逐条列出 17,237 个同电影同别名重复组中的 89,937 个来源对象。不同 `objectId` 始终获得不同的 1-based 锚编号；电影数值后缀是双方一致的连接 ID，也是目标对象 ID，原始 `tconst` 保留用于反向映射。

## 本轮源码与验证

- `internal/imdbprod/` 固定公开参数、样本摘要、字段、身份映射与布局绑定；任何公开候选数 `K>10000` 拒绝。数学域保持 Ring64 对象/连接、Ring32 位置、GF16 锚标签、Z128 计数/矩阵、F2 命中。
- `anchorindex`、`targetcrypto`、`indexbuild`、`anchorquery`、`targetquery` 增加电影版本化键域和对应构建/查询路径。锚字段为 `MOVIECAST.aliasTitle/tconst`，目标字段为 `MOVIE.primaryTitle/tconst`。双侧只取前 4 个完整、不重叠的 q4 签名。
- `discovery.NewMovieStatic`、`Provision`、令牌 QU13、云端解码、持久化预留以及 `targetposition.PreprocessWithDomain` 绑定电影布局；电影路径使用 Bin10/Upos270 与固定 C=10000、D26、r=4、桶数 65536。旧实验路径仍按其旧版参数工作，不能装载成电影静态状态。目标实际 keyed 桶容量若超过当前公开 44 槽/11 组预算会拒绝，不动态改 C。
- 目标侧最大同对象同 q4 重复从 3 统一调至 4：生成器、侧车 manifest 与在线协议校验一致。测试验证 4 次对应 26 维矩阵同一局部 ordinal，5 次拒绝；Z128 计数域未改变。
- `imdbrecovery.Recover` 对真实两方结果份额使用既有 D26 解码，再经可信映射反查，并拒绝外来 ID 与不一致的电影连接；没有用明文答案替代密码计算。
- 按现有 `zeroagg` 标签与诊断结构修复交接包所列 17 个普通测试编译错误，并修复额外发现的 4 个原生测试旧 `Incidence` 字段错误；未恢复废弃的锚矩阵字段。

通过的检查：冻结对象摘要及文件哈希、映射 110,000 条往返与连接一致性、目标真实 q4 最大重复数 4、电影小型索引键域和点/桶一致性、4 签名令牌边界、目标矩阵重复/局部坐标、旧零点诊断集成测试；`go test -exec /bin/true -run '^$' ./internal/...` 全包编译通过；`go build -p 1 -tags phase6native ./internal/...` 通过；指定本地原生库的 `phase6native` 测试包编译通过；原生 Bin10 全域比较及区间/混域拒绝测试通过。编译替代执行器的 `ok` 仅代表编译，不代表测试运行。未运行 100k 秘密索引构建、批量离线材料或长期性能实验。

另在 `/tmp` 重新执行冻结脚本，所得 6 个载荷文件的 SHA256 与正式样本逐一相同；在 `/tmp` 从原生桥和第三方源码重新编译 `libphase6scmp.a`，并用新编译库重跑上述 Bin10 原生测试，通过。上述检查均未改动正式母库或旧原生库。

## 外包前资源预算与启动门

可执行只读检查：`tools/preflight_imdb_production.py`，结果见 `reports/imdb-production-preflight-20261015.json`。按交接包公开布局和一次离线查询批次：单方锚 CS1 σ 为 `21,246,400,000` 字节（19.79 GiB）；双侧锚索引约 278.21 MB；双侧目标矩阵约 88.00 MB；双侧静态语义字段约 21.66 GB。离线批次约 4.63 GB，其中目标位置相关材料 2.65 GB、目标矩阵 1.66 GB、目标 PE 84.15 MB、锚全局材料 86.20 MB、锚局部最大形状材料 150.20 MB。规划内存 `1.5×(静态+离线)+2 GiB` 为 41.58 GB；当前 MemAvailable 48.05 GB。双云两份持久文件加一份 staging 的磁盘规划下限 74.24 GB；当前可用 869.27 GB。查询保留 C=10000、4 次目标路由、公开 S=1,760,000、G=440,000；实际秘密 K 超限拒绝。

σ 当前以每非空桶 N×4 字节显式存储。53,116 个非空桶合计单方 21.25 GB；若全量装载，加上 DO 的 π/ρ/σ、两方索引、Go 对象开销和临时拷贝，41.58 GB 规划值不是堆峰值保证。按桶持久化并按需加载是启动完整构建/在线云进程的前置实现。保留同样的秘密排列语义时，可复用单桶缓冲、逐桶写入并释放 DO 中间排列，避免同时常驻全部 σ；改变存储生命周期无需改变协议，但需要与 BS02 哈希/一次性材料状态一起验证。

**目前启动门未通过**：真实私钥桶布局尚未校验是否落在 44 槽/11 组公开预算内；按桶 σ 存储和懒加载未实现；DO/双云堆峰值与临时盘副本未实测；完整电影 DO 构建及恢复命令入口未完成。当前版本不可启动十万规模外包。

## 剩余生产接口缺口

1. 实现电影 DO 的逐桶构建、BS02/PS01/PL01/TG01 持久化装配和按桶 σ 懒加载；把电影绑定摘要写入静态 artifact manifest、云装载和用户恢复的每一层，并拒绝旧状态。
2. 对实际私钥构建前的公开桶布局做只读核验；若超过已固定的 44/11 槽/组上界，应明确拒绝并另行审核资源预算，不能截断候选或根据秘密 K 改 C。
3. 完成一次性离线材料的分批持久化与云端进程级装载接口、电影 DO/用户 CLI、以及完整双侧编辑距离最终语义的验收定义。`RunCloudLocal` 仍是本地双云传输协调器，不代表远程部署。
4. 在上述门槛解决后，对同一正式参数/接口进行受控真实密码端到端正确性验收与峰值内存/磁盘实测，然后才启动唯一 100k×10k 的正式外包。不得把历史 1k/5k/10k 样本当成阶段性生产架构。

本轮新增或明确编辑：`tools/freeze_imdb_production.py`、`tools/preflight_imdb_production.py`、`imdb_production_20261015/`、`internal/imdbprod/`、`internal/imdbrecovery/`、`internal/anchorindex/{encode,logical_key}.go`、`internal/anchorquery/query.go`、`internal/targetcrypto/{canonical,scalar,bucket,point}.go`、`internal/indexbuild/{builder,movie_build_test}.go`、`internal/targetquery/{query,movie_query_test}.go`、`internal/targetposition/position.go`、`internal/targetaggregation/{sidecar,protocol,protocol_test}.go`、`internal/targetaggregation/gen/{sidecar,movie_multiplicity_test}.go`、`internal/discovery/{types,offline,cloud,local,token,reservation,persistent_zero,diagnostics_test,domain_test,token_signature_experiment_test,token_signature_final_validation_test,database_scalability_native_test,real_native_test}.go` 以及本报告与资源结果。部分这些文件在本轮开始前已有未提交修改，本轮没有将它们恢复到 HEAD。

提交范围还包含本轮开始前已经存在、且当前源码编译依赖的 `internal/` 工作区基线、原生桥/头文件、修复版第三方 LLAMA 源码、Python 依赖声明和交接包。它们被原样纳入提交以保存本地生产基线；上段列出的文件才是本轮明确改造的范围。母库与历史实验结果文件未纳入提交。
