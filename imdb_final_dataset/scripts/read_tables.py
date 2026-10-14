#!/usr/bin/env python3
"""Read portable Parquet tables or stream full text exports, no data-size cap."""
import argparse
from common import BASE,BUSINESS,connection,lit

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--table',choices=BUSINESS,default='MOVIECAST')
    p.add_argument('--limit',type=int,default=20)
    p.add_argument('--sql',help='Read-only SQL over MOVIECAST, MOVIE, PERSON, MOVIECAST_OBJECTS and MOVIECAST_SOURCE')
    p.add_argument('--export',help='Output CSV or TSV path; streams every row selected by SQL or table')
    p.add_argument('--format',choices=['csv','tsv'],default='csv')
    p.add_argument('--with-object-id',action='store_true')
    a=p.parse_args();c=connection(':memory:')
    for t in ['MOVIE','PERSON']:
        c.execute(f'CREATE VIEW {t} AS SELECT * FROM read_parquet({lit(BASE/f"data/{t}.parquet")})')
    c.execute(f'CREATE VIEW MOVIECAST_OBJECTS AS SELECT * FROM read_parquet({lit(BASE/"data/MOVIECAST/*.parquet")})')
    c.execute('CREATE VIEW MOVIECAST AS SELECT '+','.join(BUSINESS['MOVIECAST'])+' FROM MOVIECAST_OBJECTS')
    c.execute(f'CREATE VIEW MOVIECAST_SOURCE AS SELECT * FROM read_parquet({lit(BASE/"provenance/MOVIECAST_SOURCE/*.parquet")})')
    table='MOVIECAST_OBJECTS' if a.with_object_id and a.table=='MOVIECAST' else a.table
    sql=a.sql or 'SELECT * FROM '+table
    statements=c.extract_statements(sql)
    if len(statements)!=1 or str(statements[0].type)!='StatementType.SELECT':p.error('Only one SELECT statement is allowed')
    if a.export:
        from pathlib import Path
        dest=Path(a.export).resolve()
        if dest.is_relative_to(BASE):p.error('Export outside the frozen formal workspace')
        c.execute(f'COPY ({sql}) TO {lit(dest)} (HEADER,FORMAT CSV,DELIMITER {lit(chr(9) if a.format=="tsv" else ",")},NULL {lit(chr(92)+"N")})')
        print(dest)
    else:
        r=c.execute(f'SELECT * FROM ({sql}) LIMIT {a.limit}')
        print('\t'.join(x[0] for x in r.description))
        for row in r.fetchall():print('\t'.join('\\N' if x is None else str(x) for x in row))

if __name__=='__main__':main()
