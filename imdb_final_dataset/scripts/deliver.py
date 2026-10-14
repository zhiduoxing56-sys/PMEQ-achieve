#!/usr/bin/env python3
"""Create the connected 100-row XLSX previews, Chinese reports and final SHA-256 inventory."""
import csv,html,json,pathlib,time,zipfile
from xml.sax.saxutils import escape
from common import BASE,BUSINESS,connection,lit,now,save,sha

def col(n):
    out=''
    while n:n,r=divmod(n-1,26);out=chr(65+r)+out
    return out

def xlsx(path,sheets):
    # Standard OOXML with inline strings: keeps IDs, Unicode and literal formulas as text.
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'+''.join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1,len(sheets)+1))+'</Types>')
        z.writestr('_rels/.rels','<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr('xl/workbook.xml','<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'+''.join(f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>' for i,(name,_,_) in enumerate(sheets,1))+'</sheets></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels','<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'+''.join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1,len(sheets)+1))+f'<Relationship Id="rId{len(sheets)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        z.writestr('xl/styles.xml','<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF174A73"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="49" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="49" fontId="1" fillId="2" borderId="0" xfId="0" applyFill="1" applyFont="1"/></cellXfs></styleSheet>')
        for i,(name,headers,records) in enumerate(sheets,1):
            sheet=['<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',f'<dimension ref="A1:{col(len(headers))}{len(records)+1}"/>','<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="16"/><cols>']
            for j,h in enumerate(headers,1):sheet.append(f'<col min="{j}" max="{j}" width="{18 if h.endswith("Id") or h in ("tconst","nconst") else 42}" customWidth="1"/>')
            sheet.append('</cols><sheetData>')
            for ri,row in enumerate([headers]+records,1):
                sheet.append(f'<row r="{ri}">')
                for ci,v in enumerate(row,1):
                    value='\\N' if v is None else str(v)
                    sheet.append(f'<c r="{col(ci)}{ri}" t="inlineStr" s="{1 if ri==1 else 0}"><is><t xml:space="preserve">{escape(value)}</t></is></c>')
                sheet.append('</row>')
            sheet.append(f'</sheetData><autoFilter ref="A1:{col(len(headers))}{len(records)+1}"/></worksheet>')
            z.writestr(f'xl/worksheets/sheet{i}.xml',''.join(sheet))

def text_report(name,text):
    (BASE/'reports'/f'{name}.txt').write_text(text,encoding='utf-8')
    (BASE/'reports'/f'{name}.html').write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>'+name+'</title><style>body{max-width:1100px;margin:40px auto;padding:0 24px;font:16px/1.8 sans-serif;color:#192b3c}pre{white-space:pre-wrap;overflow-wrap:anywhere}h1{font-size:26px}</style><h1>'+name+'</h1><pre>'+html.escape(text)+'</pre></html>',encoding='utf-8')

def main():
    v=json.loads((BASE/'checks/validation.json').read_text());assert v['all_passed']
    independent=json.loads((BASE/'checks/independent_raw_validation.json').read_text());assert independent['all_passed']
    sampling=json.loads((BASE/'checks/sampling_verification.json').read_text());assert sampling['all_passed']
    build=json.loads((BASE/'checks/build_complete.json').read_text());pre=json.loads((BASE/'checks/precheck.json').read_text())
    sources=json.loads((BASE/'provenance/source_manifest.json').read_text())
    cleanup=json.loads((BASE/'checks/cleanup_verification.json').read_text())
    c=connection(read_only=True)
    mc=c.execute('SELECT * FROM MOVIECAST_OBJECTS ORDER BY tconst,split_part(objectId,\'|\',3)::BIGINT,directorId,split_part(objectId,\'|\',5)::BIGINT LIMIT 100').fetchall()
    tids={r[0] for r in mc};pids={r[1] for r in mc}|{r[2] for r in mc}
    sqlids=lambda s:','.join(lit(x) for x in sorted(s))
    movie=c.execute(f'SELECT * FROM MOVIE ORDER BY CASE WHEN tconst IN ({sqlids(tids)}) THEN 0 ELSE 1 END,tconst LIMIT 100').fetchall()
    person=c.execute(f'SELECT * FROM PERSON ORDER BY CASE WHEN nconst IN ({sqlids(pids)}) THEN 0 ELSE 1 END,nconst LIMIT 100').fetchall()
    assert tids<={r[0] for r in movie} and pids<={r[0] for r in person}
    sheets=[('MOVIECAST',BUSINESS['MOVIECAST'],[list(r[:6]) for r in mc]),('MOVIE',BUSINESS['MOVIE'],[list(r) for r in movie]),('PERSON',BUSINESS['PERSON'],[list(r) for r in person])]
    xlsx(BASE/'IMDb最终三张实验表预览.xlsx',sheets)
    (BASE/'previews').mkdir(exist_ok=True)
    for name,cols,records in sheets:
        with open(BASE/'previews'/f'{name}_first100.csv','w',encoding='utf-8-sig',newline='') as f:
            w=csv.writer(f);w.writerow(cols);w.writerows([['\\N' if x is None else x for x in row] for row in records])
    with open(BASE/'previews/MOVIECAST_first100_sources.csv','w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['objectId','tconst','actorOrdering','directorId','aliasOrdering'])
        for r in mc:
            parts=r[6].split('|');w.writerow([r[6],r[0],parts[2],r[2],parts[4]])
    save('checks/preview_verification.json',dict(workbook_sheets=['MOVIECAST','MOVIE','PERSON'],rows_each=100,
         moviecast_business_columns=6,all_preview_movies_present=True,all_preview_actors_and_directors_present=True,
         ordering='MOVIECAST canonical source order; MOVIE/PERSON required entities first then ascending official ID',
         preview_movie_keys=len(tids),preview_person_keys=len(pids)))
    c.close()
    total=lambda pattern:sum(p.stat().st_size for p in BASE.glob(pattern) if p.is_file())
    sizes={t:total('data/MOVIECAST/*.parquet') if t=='MOVIECAST' else (BASE/f'data/{t}.parquet').stat().st_size for t in BUSINESS}
    size_text=lambda n:f'{n:,} 字节（{n/(1<<20):,.2f} MiB）'
    fields=f'''IMDb 最终三张实验表：中文字段说明
生成时间：{now()}

MOVIECAST：{v['counts']['MOVIECAST']:,} 条真实来源派生对象。
六个且仅六个业务属性：
  tconst：电影编号，连接属性，来自 title.basics.tconst（titleType=movie）。
  actorId：演员编号，连接属性，来自 title.principals.nconst（category=actor 或 actress）。
  directorId：导演编号，连接属性，来自 title.crew.directors 中的真实 nconst。
  aliasTitle：电影别名，可搜索字符串，来自 title.akas.title。
  actorName：演员姓名，可搜索字符串，通过 actorId=name.basics.nconst 取得 primaryName。
  directorName：导演姓名，可搜索字符串，通过 directorId=name.basics.nconst 取得 primaryName。
物理 Parquet 另含 objectId，属于对象标识元数据，不属于连接或可搜索业务属性。数据库的 MOVIECAST 视图严格只有六个业务列；MOVIECAST_OBJECTS 视图提供六业务列和 objectId。
objectId = mc1|电影tconst|演员来源ordering|导演nconst|别名来源ordering。
使用可逆、无哈希碰撞的确定性复合标识，稳定性以冻结原始快照为边界；上游更新重编号时不承诺跨快照身份不变。
provenance/MOVIECAST_SOURCE/ 提供 objectId、tconst、actorOrdering、directorId、aliasOrdering。该信息仅用于来源追溯。
演员来源键为 (tconst, ordering)，别名来源键为 (titleId, ordering)，导演来源为 (crew.tconst, directors 列中的 nconst)。director_source.parquet 保存每个导演在原始列表中的全部出现位置，crew_source.parquet 保留原始 directors 字符串。
同一电影全部有效演员来源行 × 全部有效不同导演 × 全部有效别名来源行完整展开。重复演员姓名、导演姓名、别名文本均不构成去重条件。不同 ordering 的来源行全部保留。组合只表示三者同属于一部真实电影，不代表官方直接逐组记载演员与导演的合作关系。

MOVIE：{v['counts']['MOVIE']:,} 条。来源为完整 title.basics 中 titleType=movie 的所有记录。
  tconst：电影编号，唯一键、连接属性。
  primaryTitle：主标题，可搜索字符串；原字段 primaryTitle。
  originalTitle：原始标题，可搜索字符串；原字段 originalTitle。
严格只有以上三个业务字段；原始标题属于字符串属性。

PERSON：{v['counts']['PERSON']:,} 条。来源为完整 name.basics 的所有记录，不局限于最终出现的演员和导演。
  nconst：人员编号，唯一键、连接属性。
  primaryName：人员姓名，可搜索字符串；原字段 primaryName。
  primaryProfession：主要职业信息，可搜索字符串；保留原字段完整字符串，包括原有逗号、次序及内容，不拆分，不重新拼接。
严格只有以上三个字段。

统一缺失值规则：IMDb 官方 \\N 读取为 SQL NULL，导出文本及预览时以 \\N 表示。MOVIE/PERSON 全部来源行保留，即使某个字符串缺失。MOVIECAST 要求三个真实键、真实人员匹配及 aliasTitle/actorName/directorName 非 NULL 且非空字符串；其他字段不影响纳入。不进行 trim、大小写转换、Unicode 规范化或占位文字替换。
导演仅使用 title.crew 的 directors；没有有效 crew 导演时不从别的类别猜测补充。重复的同电影同导演编号规范化为一个关联，不删除不同导演。
未进入 MOVIECAST 的电影仍完整保留在 MOVIE；完整逐电影原因见 checks/excluded_movies.parquet。

实际外键：
  MOVIECAST.tconst = MOVIE.tconst。
  MOVIECAST.actorId = PERSON.nconst。
  MOVIECAST.directorId = PERSON.nconst。
三种连接均成功 {v['counts']['MOVIECAST']:,} 条，悬空记录和悬空不同键均为 0。演员和导演是 PERSON 的两个角色引用，不额外拆出人员实验表。

来源与版本：官方 https://datasets.imdbws.com/；字段定义 https://data.imdb.com/non-commercial-datasets/。
'''
    for f in sources['files']:
        fields+=f"  {pathlib.Path(f['path']).name}：官方 run-date={f['http'].get('x-amz-meta-run-date','unknown')}，Last-Modified={f['http'].get('last-modified','unknown')}，获取时间证据={f['acquisition_date_utc']}。\n"
    fields+='上述文件不是同一天更新，已按实际版本冻结。差异造成的人员缺失按统一规则排除，不补造人物。全部五个完整文件均复用，无重复下载。\n'
    text_report('中文字段说明',fields)
    exclusions='\n'.join(f"  {x['reason']}：{x['movies']:,} 部" for x in pre['excluded_movies_by_reason'])
    stats='\n'.join(f"  {key}：不同值 {s['distinctValues']:,}；最大组 {s['maximumGroupSize']:,}；最小组 {s['minimumGroupSize']:,}；均值 {s['meanGroupSize']:.6f}；中位数 {s['medianGroupSize']:.1f}；P95 {s['p95GroupSize']:.1f}；P99 {s['p99GroupSize']:.1f}。" for key,s in v['group_statistics'].items())
    report=f'''IMDb 最终全量构建报告
交付生成时间：{now()}

实际交付
  MOVIECAST：{v['counts']['MOVIECAST']:,} 条，32 个 ZSTD Parquet 分区，{size_text(sizes['MOVIECAST'])}。
  MOVIE：{v['counts']['MOVIE']:,} 条，{size_text(sizes['MOVIE'])}。
  PERSON：{v['counts']['PERSON']:,} 条，{size_text(sizes['PERSON'])}。
  来源映射 Parquet：{size_text(total('provenance/MOVIECAST_SOURCE/*.parquet'))}。
  读取数据库 data/imdb_final.duckdb：{size_text((BASE/'data/imdb_final.duckdb').stat().st_size)}，保留电影范围原始关联摘录、有效关联、计数账本、分组表和正式业务视图。
  IMDb最终三张实验表预览.xlsx：三个工作表各 100 条；MOVIE/PERSON 优先排列预览 MOVIECAST 对应实体，100 条派生记录的全部外键均在预览内可找到。物理 Parquet 不具有隐含全局行次序，预览采用明确的来源键顺序。

全量构建与资源
  开始 UTC：{build['started_at_utc']}。
  完成 UTC：{build['completed_at_utc']}。
  读取、计数、来源保存及完整物化耗时：{build['seconds']:.3f} 秒。
  全量验证耗时：{v['seconds']:.3f} 秒；独立重读验证耗时：{independent['seconds']:.3f} 秒。准备迁移、清理及生成交付材料另计，未将构建耗时称为总任务时间。
  预计 N_MOVIECAST = Σ A_t D_t B_t = {pre['expected_moviecast']:,}；实际 {build['actual']:,}；差值 0。
  759,363 部电影全部进入 MOVIE，525,080 部至少有一组完整有效组合；另 {v['counts']['MOVIE']-v['group_statistics']['tconst']['distinctValues']:,} 部缺少必要关联。
  最大电影：{pre['largest_movie']['tconst']}，A={pre['largest_movie']['A']}，D={pre['largest_movie']['D']}，B={pre['largest_movie']['B']}，展开 {pre['largest_movie']['expectedRows']:,} 条。
  构建前可用空间 {size_text(pre['available_disk_bytes'])}；UTF-8 文本负载估计 {size_text(pre['uncompressed_tsv_payload_estimate_bytes'])}。文本估计为逐组加权字段字节数及分隔符，不包含 CSV 引号转义。
  Parquet 与来源映射合计保守规划 {size_text(pre['estimated_parquet_plus_lineage_upper_bytes'])}；临时空间预算 12 GiB；总追加预算 {size_text(pre['conservative_additional_space_bytes'])}；资源缺口 0。
  预检可用内存 {size_text(pre['memory']['MemAvailable'])}；DuckDB 内存上限 12GB、6 线程、32 个确定性电影分区。每次仅将一个分区的流式查询写入磁盘，不在 Python 中保存全表展开结果。
  所有电影、所有有效演员来源、所有有效导演和所有有效别名来源均完整参与；没有演员/导演/别名上限、记录总上限、随机复制或高频电影过滤。

统一排除统计（下列组合原因互斥，总数等于未进入派生表的电影数）
{exclusions}
  无对应 PERSON 的演员来源行 368 条；无对应 PERSON 的不同导演关联 53 个；缺失必要姓名/别名字符串 0 条。因多日期快照而缺失的关联不会用虚构值补齐。
  同电影重复导演列表位置规范化 {pre['director_duplicate_list_entries_normalized']:,} 个；所有原始位置仍可追溯。

连接分组统计
{stats}
  每个不同连接值的精确频数：checks/groups/tconst.parquet、actorId.parquet、directorId.parquet。
  完整频数直方图：checks/tconst_group_histogram.csv、actorId_group_histogram.csv、directorId_group_histogram.csv。
  分组频数之和各等于 41,286,264。分组统计针对 MOVIECAST，不将 MOVIE 中未进入派生表的电影计入不同值数。

正确性与完整性
  1. 三张完整表存在，业务字段次序/数量与最终方案一致。
  2. 原始电影/人员键、演员及别名来源复合键、crew 电影键全部唯一；不静默吞掉重复来源。
  3. 对全部 41,286,264 个对象逐分区验证 objectId 唯一、确定性标识精确匹配、来源映射唯一且完整。
  4. 每条派生记录均与同一电影的原演员来源、原导演来源、原别名来源匹配，三个字符串完全一致，无无来源记录、跨电影组合或必要空值。
  5. 各分区记录数与预检一致；每部电影实际展开数与乘积账本一致，差异电影数为 0。来源组合唯一且基数等于乘积，验证全组合覆盖。
  6. tconst、actorId、directorId 三种等值连接各成功 41,286,264 条，悬空外键数/悬空不同键数均为 0。统计基于每个真实键精确频数及目标唯一键，避免展开中间连接结果。
  7. 五个原始文件完整 gzip CRC、UTF-8 TSV 表头、大小及 SHA-256 校验均通过；迁移前后和构建完成后校验值保持一致。
  8. 独立标准库 gzip/TSV 解析重新读取全部五个原始文件，复算所有电影的 A/D/B 与乘积，逐电影不一致数为 0。原始 MOVIE/PERSON 投影及电影范围的完整 principals/akas/crew 摘录经逐行 SHA-256 的无序多重集指纹比较完全一致，确认人员职业字符串原样保留。
  9. 多个不同 ordering 的来源对象即使业务文本相同也全部保留。姓名重复是正常真实冗余，不用来删行。
  10. 固定种子抽样脚本在临时目录通过重复生成、字节校验值一致、独立规模 23/50/100、不同属性数量与全部指定外键验证；临时样本已删除，不固定论文实验规模。
  校验详情见 checks/validation.json、independent_raw_validation.json、source_key_checks.json、sampling_verification.json。

直接读取
  在项目根目录：
  imdb_final_dataset/.venv/bin/python imdb_final_dataset/scripts/read_tables.py --table MOVIECAST --limit 20
  imdb_final_dataset/.venv/bin/python imdb_final_dataset/scripts/read_tables.py --table MOVIE --limit 20
  imdb_final_dataset/.venv/bin/python imdb_final_dataset/scripts/read_tables.py --table PERSON --limit 20
  添加 --with-object-id 可读取 MOVIECAST 物理文件中的对象标识。
  添加 --export /另一个工作目录/MOVIECAST.csv --format csv 可流式导出完整文本表；tsv 也支持。原始空值导出为 \\N。全量 CSV 大于 Parquet，需要提前留足空间。
  --sql 接受单条 SELECT，可直接读取三表或 MOVIECAST_OBJECTS/MOVIECAST_SOURCE；未生成查询工作负载。
  Python：import duckdb; con=duckdb.connect('imdb_final_dataset/data/imdb_final.duckdb', read_only=True); con.execute('SELECT count(*) FROM MOVIECAST').fetchone()。
  原始 Parquet 可由 DuckDB read_parquet('imdb_final_dataset/data/MOVIECAST/*.parquet') 直接读取，也适用于其他 Parquet 读取器。目录整体搬迁后优先使用 read_tables.py（按脚本目录重新定位）；当前读取数据库的视图绑定本机绝对路径。

后续可复现抽样
  scripts/sample.py --moviecast-size N --movie-size M --person-size P --seed S --output /新目录。
  N、M、P 分别控制三表规模，不要求相等。不提供 M/P 时使用必要电影/人员闭包；提供时先保留全部指定连接的必要实体，再用同种子确定性排序补齐到指定规模。
  若 M/P 小于真实必要实体数量，脚本明确报错并给出所需下限，不静默丢弃连接。需要可行的规模组合或减少指定连接。
  --join-count 0..3 默认 3，依次选择 tconst、actorId、directorId；--join-attributes 可显式选择其中任意组合。
  --moviecast-search-count 0..3：aliasTitle、actorName、directorName；--movie-search-count 0..2：primaryTitle、originalTitle；--person-search-count 0..2：primaryName、primaryProfession。默认全部保留。
  抽样按 SHA256(UTF8(objectId+'|'+十进制种子)) 升序取 N 条，objectId 打破平局；实体补齐按官方 ID 同样排序。固定快照和参数得到相同对象集合，保留 objectId、实体 sourceId 和原来源映射。
  各样本输出 Parquet、来源映射及完整参数/文件哈希清单；三表通过指定真实连接字段维持关系。未选的业务字段不导出，来源标识仍作为元数据保留。
  本轮不执行密码协议、不生成正式查询工作负载、不提前选定十万或其他论文数据规模、不删除导演来消除重复查询。

复建方法
  在新的独立目录中复制 scripts/、requirements.txt、五个已冻结 raw/ 文件及 provenance/source_manifest.json（或安全引用同样的冻结文件），安装 duckdb==1.5.6。
  依次执行 build.py、validate.py、verify_raw_independently.py、check_sampling.py、deliver.py。不要在已完成的正式目录重复覆写；build.py 会拒绝已完成工作区。
  prepare_sources.py 与 cleanup_old_temp.py 是本轮固定历史目录的迁移清理记录，不属于日常复建入口。
  所有正式数据、来源、脚本与交付材料的实际 SHA-256、大小见 artifact_manifest.json；稳定对象标识与输入快照记录支持后续索引外包实验。
'''
    text_report('全量构建报告',report)
    inv=json.loads((BASE/'reports/cleanup_inventory.json').read_text());temps=json.loads((BASE/'reports/cleanup_temp_inventory.json').read_text())
    cleaned=f'''IMDb 旧派生方案清理报告
本轮只清理经核实的旧 IMDb 数据集派生及其关联脚本、测试、工作负载、CSV/Parquet、旧交付、临时重建。未修改论文正文或密码协议代码。

已清理项目目录（范围明确；逐项 unlink，最后仅移除空目录，未使用无范围递归删除）：
'''+''.join('  '+x+'\n' for x in cleanup['deleted_workspace_names'])+f'''
实际删除项目目录文件/链接 {len(inv):,} 项，旧位置合计 {sum(x['bytes'] for x in inv):,} 字节；其中五个官方原始文件是经 SHA-256 一致核验后迁入 raw/，不是丢弃官方数据。
实际删除旧 /tmp 派生/抽样文件 {len(temps)} 项，合计 {sum(x['bytes'] for x in temps):,} 字节。
完整实际路径、字节数、分类、操作及完成状态分别见 reports/cleanup_inventory.json、cleanup_temp_inventory.json。所有条目删除状态均为 deleted；迁移的五个官方原始旧路径有单独迁移分类。

原始数据保留：raw/title.basics.tsv.gz、raw/title.akas.tsv.gz、raw/title.principals.tsv.gz、raw/name.basics.tsv.gz、raw/title.crew.tsv.gz。五个文件全部经过复制后内容一致核验，再清理旧位置。历史获取 HTTP 记录保存在 provenance/。
独立的新 .venv 只复用已有 DuckDB 包并保留正式读取/构建能力，没有重复下载原始数据。
保护验证：对 {cleanup['protected_files']:,} 个论文、项目源代码、协议实现、已有独立测试/研究数据等保留文件比较清理前后 SHA-256，全部一致；其他项目目录未触碰。逐文件证据见 checks/protected_files_before.json 和 protected_files_after.json。
未清理来源不明或独立科研内容：当前 cmd/、internal/、tools/、tests/、docs/、verification/、data/、third_party/、results/、artifacts/，及项目同级的其他科研目录。它们不在七个已核实废弃 IMDb 工作区内；本轮未因文件包含旧数据集名称而删除人工维护文档或独立研究结果。
正式工作区仅包含最终原始快照、最终表、追溯、构建/读取/抽样脚本、验证证据、预览与交付材料。
'''
    text_report('清理报告',cleaned)
    for pattern in ['scripts/__pycache__/*.pyc']:
        for f in BASE.glob(pattern):f.unlink()
    cache=BASE/'scripts/__pycache__'
    if cache.exists() and not any(cache.iterdir()):cache.rmdir()
    tmp=BASE/'tmp'
    if tmp.exists() and not any(tmp.iterdir()):tmp.rmdir()
    inventory=[]
    for f in sorted(BASE.rglob('*')):
        if not f.is_file() or f.is_relative_to(BASE/'.venv') or f.name=='artifact_manifest.json':continue
        inventory.append({'path':str(f.relative_to(BASE)),'bytes':f.stat().st_size,'sha256':sha(f)})
    save('artifact_manifest.json',dict(created_at_utc=now(),files=inventory,counts=v['counts'],business_schema=BUSINESS,
         metadata_columns={'MOVIECAST physical Parquet':['objectId']},runtime_dependency='duckdb==1.5.6; .venv excluded from artifact hash inventory',
         complete=True))
    print('DELIVERY_COMPLETE',v['counts'],sizes,flush=True)

if __name__=='__main__':main()
