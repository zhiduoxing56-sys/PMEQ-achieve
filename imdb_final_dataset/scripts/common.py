import datetime, hashlib, json, pathlib
import duckdb

BASE = pathlib.Path(__file__).resolve().parents[1]
BUSINESS = {'MOVIECAST':['tconst','actorId','directorId','aliasTitle','actorName','directorName'],
            'MOVIE':['tconst','primaryTitle','originalTitle'],
            'PERSON':['nconst','primaryName','primaryProfession']}

def lit(s): return "'"+str(s).replace("'","''")+"'"
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(8<<20),b''): h.update(b)
    return h.hexdigest()
def save(path,data):
    p=BASE/path; p.parent.mkdir(parents=True,exist_ok=True)
    tmp=p.with_suffix(p.suffix+'.tmp')
    tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2,default=str)+'\n');tmp.replace(p)
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def connection(db=None,read_only=False):
    c=duckdb.connect(str(db or BASE/'data/imdb_final.duckdb'),read_only=read_only)
    if not read_only:
        c.execute("SET memory_limit='12GB'; SET threads=6; SET preserve_insertion_order=false")
        c.execute('SET temp_directory='+lit(BASE/'tmp'))
    return c
def read_raw(name):
    return "read_csv("+lit(BASE/'raw'/f'{name}.tsv.gz')+", delim='\t', header=true, all_varchar=true, quote='', escape='', nullstr='\\N', parallel=false, strict_mode=true, max_line_size=1048576)"
def copy(c,sql,path):
    p=BASE/path;p.parent.mkdir(parents=True,exist_ok=True)
    c.execute(f'COPY ({sql}) TO {lit(p)} (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 122880)')
def scalar(c,sql): return c.execute(sql).fetchone()[0]
def rows(c,sql):
    r=c.execute(sql);cols=[x[0] for x in r.description]
    return [dict(zip(cols,row)) for row in r.fetchall()]
