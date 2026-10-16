# IMDb 反方向离线外包建库验收（2026-10-16）

## 范围与隔离

本轮只补 `MOVIE.primaryTitle` 的 BSMJ 和 `MOVIECAST.aliasTitle` 的 PSMJ、对象关联矩阵及对应锚对象载荷，用于衡量外包建库时间与存储。没有发行票据、生成令牌或执行反方向查询。输入是已冻结的 10 万条 MOVIECAST、1 万条 MOVIE 映射；DO 只读现有密钥和样本。反向键有独立的表/字段域标签，输出使用新 IndexID、LayoutID 和 `.private/imdb-reverse-outsource-v1` 命名空间，原封存查询索引、D=1 辅助文件和 SCMP 库存未作为输出。

代码分支：`experiment/imdb-reverse-outsource-20261016`。反向矩阵格式标记为版本 2；现有正式查询加载器只接受其既有版本和维度，因此此处产物是**完整的离线外包计量产物，不是反方向在线查询版本**。MOVIECAST 的对象坐标维度按真实最大连接重数取得 D=531，同一对象在同一四元组内的最大重复投递为 5，没有沿用正向 D=1、原始 D=26 或原目标桶 48 槽上限。

## 实际规模与审计

| 项目 | 实测 |
| --- | ---: |
| MOVIE 锚对象 | 10,000 |
| MOVIE BSMJ 逻辑组 / 非空桶 | 43,964 / 32,108 |
| MOVIECAST 目标对象 | 100,000 |
| MOVIECAST PSMJ 逻辑组 / 真实投递 / 填充槽 | 337,668 / 1,371,570 / 2,894,340 |
| 最大目标桶组数 / 填充槽 | 19 / 1,312 |
| 最大对象连接重数 D / 单组同对象重复数 | 531 / 5 |
| 矩阵构建审计错误 | 0 |

矩阵生成器先认证两方 PSMJ 文件的长度与 SHA-256，再重构目标槽以核对真实对象 ID、连接值、填充标记、对象坐标和重复投递，最后为两方分别采样系数与对象 ID 份额。审计覆盖全部 65,536 个桶、337,668 组、2,894,340 个物理槽；共享矩阵按原 GF127 关联和 Ring64 ID 编码写入，未使用明文矩阵代替。小型真实密码测试覆盖表域分离、重复四元组、多对象同连接值、两方 PSMJ 序列化、矩阵生成及 BS02 锚桶往返读取。

## 时间与空间

单次完整建库调用的实测进程墙钟为 **339.954 秒（5 分 39.954 秒）**，其中包含该调用内约 11 秒真实密钥布局预检；不包含 `go run` 的编译时间，也不包含此前另行运行的预检和事后的独立哈希复核。

| 阶段 | 实测墙钟 | 两方文件内容字节 |
| --- | ---: | ---: |
| MOVIECAST PSMJ 构建、写盘 | 29.191 秒 | 101,389,228 |
| MOVIECAST 对象矩阵构建、写盘 | 59.069 秒 | 5,945,842,154 |
| MOVIE 锚载荷生成、写盘 | 0.041 秒 | 840,092 |
| MOVIE BSMJ 逐桶构建、写盘 | 240.231 秒 | 1,324,202,592 |
| 上述角色文件合计 | — | **7,372,274,066** |

CS0 为 3,044,490,761 字节，CS1 为 4,327,783,305 字节；CS1 保存锚桶的 N=10,000 置换份额，因此两方大小不同。包括 JSON 报告和文件系统目录的 `du -sb` 为 **7,397,538,172 字节**。本次进程峰值 RSS **663,986,176 字节**。文件数量为 64,222 个角色文件，另有 3 个 JSON 清单/报告。

开始写盘时 Windows C 盘余量 27,885,576,192 字节，结束时读数 29,700,603,904 字节；主机余量在构建期间发生了外部变化，**不能把这个差值归因于本次清理或建库**。WSL 内部空间与 Windows C 空间分别检查。生成前根据完整 keyed 布局估算最大新增 8,457,770,564 字节，要求 C 盘保留至少 15 GiB 加 2 GiB 临时空间，并在大文件写入时复核；实际写入低于估算。未生成第二套同规模库存。

## 发布与复核

构建器只接受全新的独立输出目录；先写 `.private/.imdb-reverse-outsource-incomplete-*`，全部槽数、布局、矩阵审计、输出哈希和空间门禁通过后才原子更名。`build-report.json` 保存每个角色文件的相对路径、大小与 SHA-256。发布后独立重读全部 **64,222** 个文件，逐个核对大小与 SHA-256，结果 PASS；另以原解析器读回两方完整 PSMJ 和抽样 BS02 锚桶，结果 PASS。产物不是现有正式查询链路的输入。

本轮还按用户授权删除了八张已消费的旧影子/v3 实验票据，总计 **25,626,119,610 字节**。删除前逐文件哈希、三方消费标记和对应完成记录均核对；私有清单在 `.private/consumed-shadow-v3-ticket-cleanup-20261016.json`。旧查询完成记录保留，现行主索引、SCMP 库存、D=1 辅助文件、当前正式票据和密钥未删除。

## 复现命令

Go 工具链：`/home/tenggn/projects/new-pmeq/.tools/go/bin/go`，测试使用 `GOPROXY=off GOCACHE=/tmp/pmeq-reverse-go-cache GOTMPDIR=/tmp`。具体 `--sample`、`--keys`、`--private-root`、`--output` 参数见 [命令说明](tools/imdb_reverse_outsource/README.md)。

```sh
go test ./tools/imdb_reverse_outsource -run 'TestReverseOfflineCryptoArtifacts|TestPublishedReverseArtifacts' -count=1 -v
go test ./internal/anchorindex ./internal/targetcrypto ./tools/imdb_reverse_outsource -count=1
go test ./internal/indexbuild ./internal/targetaggregation/gen -run 'TestMovieBuildUsesSameJoinAndVersionedFields|TestMovieMultiplicityAndD26Coordinates|TestPublicCoordinateCapacity' -count=1
go run ./tools/imdb_reverse_outsource --phase preflight [README 中的输入与输出参数]
go run ./tools/imdb_reverse_outsource --phase build [README 中的输入与输出参数]
```

已发布目录不能原地再运行 `build`，以防覆盖。旧正向完整查询索引仍位于 `.private/imdb-v2-production`，本轮没有运行反方向查询，也没有将两套索引包装成可同时查询的新生产版本。
