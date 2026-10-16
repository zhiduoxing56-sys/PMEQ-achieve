# IMDb 固定 D=1、目标矩阵、独立 SCMP 库存入口验收

日期：2026-10-16。分支：`production/imdb-d1-matrix-inventory-20261016`。本次直接修改正式命令 `tools/imdb_ticket`：目标对象聚合固定为矩阵，目标对象公开坐标容量固定为 D=1，目标位置比较材料固定从独立的一次性 SCMP 库存领取。命令不提供 D=26、零点聚合或旧整票 SCMP 模式选择；传入旧模式参数会报未知参数。旧版实验命令及既有封存数据未改动。

## 适用的索引与材料

本次 D=1 只适用于已审计的固定 IMDb 索引：10,000 条目标记录、10,000 个不同连接值，每个连接值恰有一个目标对象。`BuildTargetAuxiliaryD1` 在可信离线阶段复核映射、原目标索引哈希和最大连接值多重度，再封存新的 D=1 双云辅助文件。对其他数据库，建库时必须按其公开的实际最大多重度设定 D，不能照搬 1。

正式命令复用原已封存主索引 `.private/imdb-v2-production`、独立 D=1 辅助状态 `.private/imdb-v4-d1-aux` 和已生成的 1,920,000 槽库存 `.private/imdb-v3-scmp-stock`。新会话票据及结果分别进入 `.private/imdb-production-d1-tickets`、`.private/imdb-production-d1-query-results`。旧票据无法作为新会话加载：版本、D、辅助封存摘要、索引封存摘要、库存 ID 与各角色摘要均受检查。每次发行只预生成查询会话和矩阵等非 SCMP 材料；目标路由后按公开实际槽数从库存领取原生 SCMP 密钥。用户只生成一次令牌，查询中 DO 不上线。

库存的初始容量和实际消费不同。库存两方负载合计 2,956,800,000 字节，未为本次验收再生成第二份。两次新查询分别领取 180 和 13,288 槽，未绑定槽可继续给后续查询使用；含此前实验在内的账本目前显示累计领取或烧毁 53,872 槽、未绑定 1,866,128 槽、尚需补库 53,872 槽才能再次保证完整最坏查询。高容量发行前执行 Windows C 盘、WSL 和目标路径预算检查；票据预算保留 Windows C 盘 15 GiB 安全余量及 1 GiB 临时空间。验收后 Windows C 盘余量约 31.67 GB。库存不足时拒绝新会话，不能截断结果。要承诺下一条任意最坏容量查询，必须在下一条查询开始前离线补足已消费槽；现有库存不会自行恢复。

## 真实双云密码查询

使用两条此前冻结且已有独立明文 oracle 的合法查询，完整运行可信离线发行、一次用户令牌、两云查询和用户候选对恢复。两条查询的结果分别为 3 对和 302 对；逐项比较锚 ID、锚对象 ID、目标 ID、目标 `tconst`，与原 D=26 矩阵链路及独立明文 oracle 的集合完全一致，缺失、多余、重复均为零。比较为集合比较，恢复顺序允许不同。库存消费记录与票据三方一次性消费标记均落盘。

| 冻结查询 | 票据 ID | K / 实际槽 | 结果对数 | 发行中的材料生成 / 持久化 | 云端在线 | 目标位置 / 目标矩阵 | 完整查询进程 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| first | `1cb88b95bcc6c76a4d224a91bff4886e` | 3 / 180 | 3 | 6.775 / 0.646 秒 | 161.901 毫秒 | 7.245 / 0.505 毫秒 | 45.915 秒 |
| tail | `4569591c94ddf43357a175b90d0f5668` | 302 / 13,288 | 302 | 6.993 / 0.629 秒 | 427.345 毫秒 | 95.623 / 5.871 毫秒 | 45.566 秒 |

两张新票据分别约 308.33 MB 和 316.28 MB，目录合计 624,610,932 字节，包含仍按公开最大形状生成的其他材料；不含全量 SCMP 库存。尾查询新增加的双云换掩码本地计算为 3.762/3.874 毫秒，首查询为 0.153/0.158 毫秒。一次换掩码通信依赖轮次仍在；原生 SCMP Eval 次数没有减少。完整进程约 36–38 秒用于重新验证封存索引，不能把 6–7 秒材料生成时间当作完整发行进程或在线时间。以上为单机实测各一次，不是稳定吞吐量基准。

## 复现与故障检查

在隔离源码目录编译：

```bash
PATH=/home/tenggn/projects/new-pmeq/.tools/go/bin:$PATH GOCACHE=/tmp/pmeq-prod-d1-gocache GOTMPDIR=/tmp CGO_LDFLAGS='-L/tmp/pmeq-v3-native -lphase6scmp' LD_LIBRARY_PATH=/tmp/pmeq-v3-native go build -tags phase6native -o /tmp/imdb_ticket_prod_d1 ./tools/imdb_ticket
PATH=/home/tenggn/projects/new-pmeq/.tools/go/bin:$PATH GOCACHE=/tmp/pmeq-prod-d1-gocache GOTMPDIR=/tmp CGO_LDFLAGS='-L/tmp/pmeq-v3-native -lphase6scmp' LD_LIBRARY_PATH=/tmp/pmeq-v3-native go test -tags phase6native ./internal/discovery ./internal/targetaggregation ./internal/scmpstock ./internal/targetposition -count=1
PATH=/home/tenggn/projects/new-pmeq/.tools/go/bin:$PATH GOCACHE=/tmp/pmeq-prod-d1-gocache GOTMPDIR=/tmp go test ./internal/candidatequery ./internal/imdbowner -count=1
```

相关测试均通过。执行命令时从 PMEQ 根目录运行；`--phase buckets --query-file <查询>` 得到四个公开桶，`--phase issue --generate-full-ticket --buckets <四桶>` 发行，`--phase run --ticket <新票据> --query-file <相同查询>` 执行。上述两张票据已消费，不能重跑；用正式命令重新运行第一张票据，实测退出码 1 并报 `one-use ticket has already been consumed`。`--phase status` 读取库存账本；`--phase profile --buckets <四桶>` 只测内存材料生成，不写票据或消费库存。传入 `--d-target 26` 或 `--target-aggregation zero-poly` 均立即报未知参数。库存重复领取、错误版本/角色/域/索引及跨进程消费检查由 `internal/scmpstock` 和 `internal/discovery` 的原生测试覆盖。

原封存主索引仍绑定旧 D=26 目标辅助文件，`VerifyProduction` 和 `OpenParty` 启动时会检查它们，然后本入口载入单独封存的 D=1 辅助文件。故 `.private/imdb-v2-production/target/cs0.aggregation.bin` 和 `cs1.aggregation.bin` 各 43,997,865 字节现在仍不可删除；不修改旧封存即可保持原验收证据。将来若重封完整 D=1 主索引，需再次审计可清理性。

2026-10-16 后续清理：经用户明确授权，只删除 `.private/imdb-v2-tickets` 中三张已经三方消费的旧 D=26 票据：`2dd8bad25cfc426e58e504f232644078`（4,840,690,049 字节）、`4bdd92d0ca7532421f2892abf76c6447`（4,848,639,475 字节）和 `bc4e7b1ec1abc02e0f15e582936ab14c`（4,840,690,053 字节），合计 14,530,019,577 字节。删除前的 159 个文件路径、大小、SHA-256 与三方消费标记记录在仅本地保存的 0600 文件 `.private/imdb-v2-consumed-ticket-cleanup-20261016.json`。旧结果、独立明文 oracle、新旧 D=1 票据、SCMP 库存、账本、D=1 辅助状态、主索引及旧 D=26 辅助文件均保留。WSL 内部可用空间相应增加，但 Windows C 盘可用量未因删除立即增加；虚拟磁盘未执行压缩。

此验收证明固定索引上全链路运行与一次性状态约束；底层 DCF 单方密钥联合视图、多查询换掩码组合安全和真实分机密钥隔离仍需正式密码学及部署验收。不能以这些测试宣称完整生产安全证明已完成。
