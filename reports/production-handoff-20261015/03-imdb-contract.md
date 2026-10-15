# 03 IMDb 数据与索引输入契约

来源：本次 `read_only=True` 打开正式 DuckDB，读取catalog/DESCRIBE；全量行数引用现有验收清单。另对759,363条MOVIE做只读唯一性/数值编码与q4结构统计，未扫描全量MOVIECAST、未创建索引或修改数据库。

## 真实字段与数量

| 表/视图 | 对象数 | 字段与类型 |
|---|---:|---|
| MOVIECAST | 41,286,264 | `tconst` VARCHAR；`actorId` VARCHAR；`directorId` VARCHAR；`aliasTitle` VARCHAR；`actorName` VARCHAR；`directorName` VARCHAR |
| MOVIE | 759,363 | `tconst` VARCHAR；`primaryTitle` VARCHAR；`originalTitle` VARCHAR |
| PERSON | 15,731,120 | `nconst` VARCHAR；`primaryName` VARCHAR；`primaryProfession` VARCHAR |

MOVIECAST业务视图严格六列；物理对象视图 `MOVIECAST_OBJECTS` 另有 `objectId VARCHAR`，不是额外业务字段。MOVIE以tconst、PERSON以nconst作为自然对象标识。DESCRIBE显示nullable YES，是视图类型元数据，不代表已验证的必需值实际缺失。关系为经过数据验收的逻辑外键，不是DuckDB已声明的FK约束。

## 实际视图与可携带性

### MOVIECAST

```sql
CREATE VIEW MOVIECAST AS SELECT tconst, actorId, directorId, aliasTitle, actorName, directorName FROM MOVIECAST_OBJECTS;
```

### MOVIECAST_OBJECTS

```sql
CREATE VIEW MOVIECAST_OBJECTS AS SELECT * FROM read_parquet('/home/tenggn/projects/clean_pmeq/imdb_final_dataset/data/MOVIECAST/*.parquet');
```

### MOVIE

```sql
CREATE VIEW MOVIE AS SELECT * FROM read_parquet('/home/tenggn/projects/clean_pmeq/imdb_final_dataset/data/MOVIE.parquet');
```

### PERSON

```sql
CREATE VIEW PERSON AS SELECT * FROM read_parquet('/home/tenggn/projects/clean_pmeq/imdb_final_dataset/data/PERSON.parquet');
```

### MOVIECAST_SOURCE

```sql
CREATE VIEW MOVIECAST_SOURCE AS SELECT * FROM read_parquet('/home/tenggn/projects/clean_pmeq/imdb_final_dataset/provenance/MOVIECAST_SOURCE/*.parquet');
```

DuckDB不是独立封装的三表文件。迁移必须保留34个数据Parquet文件（MOVIECAST32分片、MOVIE与PERSON各1）及来源Parquet，且处理绝对路径绑定。本轮没有移动文件或改写视图。

## 关系、对象身份与正式投影

- MOVIECAST.tconst → MOVIE.tconst；MOVIECAST.actorId/directorId → PERSON.nconst。既有validation分别记录41,286,264成功连接、0悬空。主查询只使用前一条关系。
- 锚投影：`objectId`（来源身份）、`tconst`（连接）、`aliasTitle`（检索）；六业务字段其余列保持正式库，不作为本轮主查询索引输入。
- 目标投影：`tconst`同时是电影对象身份和连接值、`primaryTitle`为检索串。originalTitle不参与主查询。PERSON不参与本轮索引。
- 人员三业务字段和primaryProfession原始字符串保持，不能因主查询不用而改表或分拆职业。
- 原始titleType=movie；演员取principals actor/actress，导演取crew并去同电影同ID重复，别名以titleId/ordering保留；同电影全演员关联×全导演×全别名来源记录。

来源对象标识：`mc1|tconst|actorOrdering|directorId|aliasOrdering`。`MOVIECAST_SOURCE` 实际列为：`objectId` VARCHAR；`tconst` VARCHAR；`actorOrdering` BIGINT；`directorId` VARCHAR；`aliasOrdering` BIGINT。不能以电影编号或字符串内容作为锚唯一ID。

## 数量、缺失与来源证据

以下41M/759k/15M为母库数量，不能当作本轮密码外包对象数。正式实验每侧上限100,000，最终子库仍待确认，见07。

- 全量验收：`imdb_final_dataset/checks/validation.json`、`delivery_acceptance.json`、`build_complete.json`。数据schema与这些文件的哈希见随附JSON。
- 锚关联电影525,080个，最大单电影15,456锚对象；全量目标759,363个不同tconst。一个电影在MOVIE仅1个对象，不应把演员/导演展开数当作目标序号数。
- 既有统计aliasTitle码点范围1–273，primaryTitle范围1–242；两侧无空字符串。
- 既有验收：必需演员/导演/别名缺失的电影按统一原因排除MOVIECAST；MOVIE仍完整保留电影范围。PERSON保留官方缺失：primaryName缺88，primaryProfession缺3,193,944，本轮不修补。
- 原始来源datasets.imdbws.com；冻结批次混合2026-10-12和10-13，冻结时间2026-10-14，不能声称五文件同日。source_manifest记录大小、SHA及真实原获取路径。

## 整数载荷适配：事实与尚未决定的方案

当前代码：`AreaRecord.ID`、`AreaAliasRecord.ID/Area`为uint64；全局对象ID以Ring64分享；位置为Ring32；局部GF16标签表示桶内坐标，不能把全局对象ID截为16位。`GeneratePayloadWithJoins(ids,joins,...)`已支持对象ID和连接ID不同，不必重写该数学机制。

本次MOVIE数值后缀诊断：{"noncanonical_pattern_count": 0, "not_uint64_count": 0, "distinct_numeric_suffixes": 759363, "min_suffix": 9, "max_suffix": 48922505}。全部759,363个数值后缀不同且在uint64内。该诊断证明候选编码可行，不等于已决定生产编码。

建议首个迁移任务针对最终选定IMDb配置实现一份专用、集中维护的契约，不开发通用数据库适配框架。需要固定的规则：

| 编码项目 | 当前事实 | 待确定生产规则 |
|---|---|---|
| 锚对象ID | 原始为可追溯复合字符串；样本为冻结池rank | 全量稳定非零uint64映射，保留反向objectId/provenance；绑定数据集版本和抽样种子 |
| 目标对象ID | tconst唯一，样本采用数值后缀 | 选原tconst映射或其后缀；不得用索引槽/随机排列位置替代对象身份 |
| 连接ID | 官方tt字符串；现CanonicalJoin为8字节无符号BE | 确定前缀/补零/反编码规范，证明全域单射；两侧同一个编解码器 |
| 布局坐标 | uint32坐标是秘密对齐位置，不是业务ID | Lineage.N明确为N_anchor；另记录N_target=759363，禁止误填为同一个表规模 |
| 密钥域 | BSMJ/area/name/id 与 PSMJ/area_alias/name/area仍硬编码 | 新字段描述符应全链共同绑定；不能只改parser，或只改query一侧 |
| 格式/版本 | BS02/PS01/PL01/TG01/QU12等既有格式 | 新电影配置、IDmap和参数摘要的持久化绑定策略待定；不能接受旧运行态作新库 |

当前实现并不要求所有目标ID小于N_anchor；RecoverForDomain主要用N约束K和消息长度。目标ID属于独立uint64对象域，需由可信ID映射验证成员关系。源对象多次命中应聚合，但不同objectId即便同名也必须保留。

## 文件来源与只读证据

[当前数据库事实](evidence/db-contract-facts.json)、[样本路径/哈希/数量](06-test-fixtures.json)、[目标矩阵结构计数](evidence/target-matrix-capacity.json)。实际源文件/验收清单元数据见本包manifest与额外输入证据JSON；数据库和样本载荷不公开上传。
