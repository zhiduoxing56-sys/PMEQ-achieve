# IMDb 目标对象坐标 D=1：隔离链路验收

日期：2026-10-16。分支：`experiment/imdb-d1-20261016`。本版复用已封存主索引和现有一次性 SCMP 库存；新的目标聚合辅助状态、票据和查询结果分别保存在 `.private/imdb-v4-d1-aux`、`.private/imdb-v4-d1-tickets`、`.private/imdb-v4-d1-query-results`。原 D=26 查询入口及票据仍可用。

## 适用条件和实现

封存的 IMDb 目标映射有 10,000 条目标记录、10,000 个不同连接值，每个连接值恰有一个目标对象。`D` 是建库时可公开的**同一连接值最多目标对象数**，因此这份固定索引可选 D=1；这不适用于未经审计的其他索引。可信离线构造器重读封存的两方 PSMJ 文件及目标映射，核对文件哈希和 `MaxAliases==1`，若一个连接值出现两个目标对象即拒绝生成 D=1 辅助状态。

`BuildTargetAuxiliaryD1` 生成独立两方 sidecar 和辅助封存，引用原生产封存哈希、索引 ID 和原目标索引。D=1 会话票据使用 `PMEQ-INVENTORY-SESSION-D-v1`，把 D、辅助封存摘要、原生产封存摘要、SCMP 银行 ID 和角色材料哈希绑定在票据中。云端载入各自 D=1 sidecar，原生 SCMP 库存、一次用户令牌、目标路由后的按需领取及后续矩阵对象聚合保持原密码链路。结果 wire 由可信静态 D 检查长度；错误 D、错误辅助摘要或旧票据版本不能混用。

## 真实封存索引结果

两条查询均在此前已冻结，有独立明文 oracle。`first` 为 `.private/imdb-v2-e2e-first/query.json`，`tail` 为 `.private/imdb-v2-e2e-tail/query.json`。对每个恢复对逐项比较锚 ID、锚对象 ID、目标 ID、目标 tconst；D=1、原 D=26 矩阵和明文 oracle 的集合完全相等，缺失、多余、重复和错对象 ID 均为零。

| 冻结查询 | K / 实际目标槽 | D=1 对数 | D=1 票据字节 | 预处理 / 持久化 | 完整发行进程 | 云端在线 | 目标矩阵聚合 | 峰值 RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| first | 3 / 180 | 3 | 308,330,757 | 6.779 / 0.583 秒 | 53.02 秒 | 160.389 毫秒 | 0.456 毫秒 | 764,560 KiB |
| tail | 302 / 13,288 | 302 | 316,280,177 | 6.923 / 0.648 秒 | 54.47 秒 | 403.733 毫秒 | 14.313 毫秒 | 799,740 KiB |

完整查询进程分别为 46.54、46.76 秒，峰值 RSS 为 609,728、743,908 KiB。每次启动仍重新验证原生产封存，查询进程的封存复核分别花 36.528、37.329 秒。两次云端在线只测量各一轮，不能把时间差当作稳定加速比。

同查询原 D=26 矩阵票据为 1,945,330,349、1,953,279,775 字节；D=1 分别少 1,636,999,592、1,636,999,598 字节。原 D=26 矩阵云端在线为 174.280、570.761 毫秒，目标聚合为 3.612、87.924 毫秒。D=1 目标聚合公开字段预算为 103,480,000 字节，D=26 为 1,730,480,000 字节。D=1 两方静态 sidecar 总共 4,953,330 字节，辅助封存目录总共 4,954,702 字节。这里不包含已有的 2,956,800,000 字节 SCMP 库存负载；本轮未生成第二份库存。

SCMP 库存初始 1,920,000 槽，v3 旧验收已消费 26,936 槽；本轮又按实际需求领取并永久消费 180+13,288 槽。目前账本 `NextFree=40,404`，未绑定剩余 1,879,596 槽，低于完整最坏查询需要的 1,920,000 槽；完整最坏保证须在下一查询前补 40,404 槽或拒绝接纳。两次新增换掩码通信仍分别为 3,108、212,836 字节，增加一次云间依赖轮次，与 D 无关。用户无需第二次上线，在线未生成 SCMP 密钥。

高容量发行前分别检查了 WSL 路径和 Windows C 盘。C 盘可用量约 32.80 GB，结束后约 32.61 GB；持久化流写入还要求 15 GiB C 盘余量与 1 GiB 临时预算。D=1 票据的新静态预算为 1 GiB，超出会拒绝写入；两张票据实际合计 624,610,934 字节。Windows C 可用量的变化不等同于 WSL 虚拟磁盘内部文件增量。

## 旧辅助材料判定

原 `.private/imdb-v2-production/target/cs0.aggregation.bin` 和 `cs1.aggregation.bin` 各 43,997,865 字节。它们仍被原生产封存、`VerifyProduction`/`OpenParty` 和保留的 D=26 回归路径引用；当前 D=1 命令启动时也先验证原封存。因此它们**没有失效，未删除**。原 PSMJ、payload、anchor 目录、密钥、SCMP 库存、消费账本及历史票据同样保留。将来若彻底停用 D=26 并建立独立 D=1 主封存，才可以重新审计这两份 sidecar 是否可清理；当前不能把它们按“节省空间”直接移除。

## 测试与限制

从隔离源码目录执行：

```bash
PATH=/home/tenggn/projects/new-pmeq/.tools/go/bin:$PATH GOCACHE=/tmp/pmeq-d1-gocache GOTMPDIR=/tmp go test ./internal/candidatequery ./internal/discovery ./internal/targetaggregation ./internal/imdbowner
PATH=/home/tenggn/projects/new-pmeq/.tools/go/bin:$PATH GOCACHE=/tmp/pmeq-d1-gocache GOTMPDIR=/tmp go test ./internal/targetaggregation/gen -run 'TestPublicCoordinateCapacity|TestMovieMultiplicityAndD26Coordinates' -count=1
PATH=/home/tenggn/projects/new-pmeq/.tools/go/bin:$PATH GOCACHE=/tmp/pmeq-d1-gocache GOTMPDIR=/tmp CGO_LDFLAGS='-L/tmp/pmeq-v3-native -lphase6scmp' LD_LIBRARY_PATH=/tmp/pmeq-v3-native go test -tags phase6native ./internal/discovery ./internal/targetaggregation ./internal/scmpstock ./internal/targetposition -count=1
```

以上相关测试通过，D=1 原生双云完整小型链通过。`go test ./internal/targetaggregation/gen` 的全包测试另依赖未随隔离快照提供的 MusicBrainz `area_alias` 外部数据，因此其大样本审计用例未运行成功；D=1 容量和 D=26 重复投递定向用例可独立运行。真实两张 D=1 票据的三方消费标记均存在；跨进程重放被拒为 `one-use ticket has already been consumed`，将 D=1 票据交给旧 D=26 入口被拒为 `ticket, auxiliary or stock version mismatch`。

编译命令：在隔离源码目录执行 `PATH=/home/tenggn/projects/new-pmeq/.tools/go/bin:$PATH GOCACHE=/tmp/pmeq-d1-gocache CGO_LDFLAGS='-L/tmp/pmeq-v3-native -lphase6scmp' go build -tags phase6native -o /tmp/imdb_ticket_d1 ./tools/imdb_ticket_v3`。从 PMEQ 根目录运行 `/tmp/imdb_ticket_d1 --phase auxiliary --d-target 1` 创建一次辅助状态；`--phase buckets --d-target 1 --query-file <冻结查询>` 取四个公开锚桶；`--phase issue --generate-full-ticket --d-target 1 --target-aggregation matrix --buckets <四桶>` 发行新票据；再以 `--phase run --d-target 1 --ticket <新票据ID> --query-file <同一查询>` 执行。原两张票据已消费，不能重跑。辅助状态生成阶段实测耗时未单独计时，本报告不声称其生成速度。

本轮证明的是固定 IMDb 索引满足 D=1 形状且全链路结果正确。`D` 必须在其他数据库的建库审计中按其真实最大连接值多重度设定，并作为公开索引参数绑定；不能把 D=1 当作通用常量。v3 报告中的 SCMP/DCF 多查询安全证明义务和双机角色文件隔离义务仍在，单元测试和这两条真实查询不能代替正式密码学证明。
