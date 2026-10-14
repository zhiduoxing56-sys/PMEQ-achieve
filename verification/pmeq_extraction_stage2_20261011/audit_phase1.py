#!/usr/bin/env python3
"""Independent checks of archived evidence; never rewrites phase-one files."""
from pathlib import Path
import hashlib,json,csv,collections,statistics
P=Path(__file__).resolve().parent;OLD=P.parent/'ggs26_20261010'
reports={n:(OLD/n).read_text() for n in ['paper-review.md','correctness-report.md','security-review.md','feasibility-report.md']}
rows=list(csv.DictReader((OLD/'performance.csv').open()))
checks=[]
for row in rows:
 if row['kernel_version']!='v2' or not row['status'].startswith('PASS'):continue
 L=int(row['L']);M=int(row['M']);chunks=(L+4095)//4096
 if row['method']=='full-secure':
  assert int(row['user_bytes'])==34*L+74*chunks
  assert int(row['cloud_bytes'])==64*L+2*((L+7)//8)+16+37*(6*chunks+2)
  assert int(row['material_bytes'])==112*L+2*((L+7)//8)
  checks.append('full-secure')
 elif row['method']=='shuffle-pair-projection':
  assert int(row['user_bytes'])==32*M+74
  assert int(row['material_bytes'])==110*L
  assert int(row['cloud_bytes'])==36*L+37*(int(row['frames'])-2)
  checks.append('shuffle')
 elif row['method']=='linear-B' and M:
  assert int(row['user_bytes'])==68*M+74
  checks.append('GF129-user')
src=(OLD/'prototype.cpp').read_text()
assert 'void trans(' in src and 'deg=0,shift=1' in src
assert 'Poly pmul' in src and 'for(size_t i=0;i<a.size();i++)for(size_t j=0;j<b.size();j++)' in src
e=json.loads((OLD/'extended-tests.json').read_text())
raw_files=list(OLD.glob('*raw.jsonl'))
raw_status=collections.Counter()
for f in raw_files:
 for line in f.read_text().splitlines():
  try:r=json.loads(line)
  except json.JSONDecodeError:continue
  raw_status[r.get('status','UNSPECIFIED')]+=1
manifest=json.loads((OLD/'deliverable-manifest.json').read_text())
integrity={n:hashlib.sha256((OLD/n).read_bytes()).hexdigest()==v['sha256'] for n,v in manifest.items()}
assert all(integrity.values())
out={'status':'PASS_INDEPENDENT_ARCHIVE_CHECK','report_bytes_read':{n:len(t.encode()) for n,t in reports.items()},'csv_rows':len(rows),'independently_recomputed_formula_checks':dict(collections.Counter(checks)),'phase1_deliverable_manifest_matches':integrity,'raw_record_status_counts':dict(raw_status),'fast_encoder':'LCH transpose implemented','fast_decoder':'NOT IMPLEMENTED; ordinary BM/dense polynomial operations are reference only','security_scope':'C++ common trusted coordinator; isolated Python tests exist; public 64-bit benchmark seed is not secret','integration':'No native KN_gamma adapter; targetaggregation is 26K with dynamic IDs and masked final ID shares','metric_gap':'material delivery / deployed two-cloud wall time not measured','coverage_evidence':e}
(P/'phase1-independent-audit.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps(out,ensure_ascii=False))
