import pathlib,json,hashlib,subprocess
p=pathlib.Path(__file__).resolve().parent;root=p.parent.parent
checks={}
for n,h in json.loads((p/'tracked-before.json').read_text()).items():checks[n]=hashlib.sha256((root/n).read_bytes()).hexdigest()==h
older={n:hashlib.sha256((p.parent/'ggs26_20261010'/n).read_bytes()).hexdigest()==h for n,h in json.loads((p/'phase1-before.json').read_text()).items()}
a=subprocess.check_output(['git','status','--porcelain=v1','-z'],cwd=root);before=(p/'git-status-before.txt').read_bytes();(p/'git-status-after.txt').write_bytes(a)
manifest=json.loads((p.parent/'ggs26_20261010'/'workload-provenance.json').read_text());sources={v['copy']:hashlib.sha256(pathlib.Path(v['copy']).read_bytes()).hexdigest()==v['sha256'] for v in manifest}
snapshot=p/'go-snapshot';difference=[]
for f in (root/'internal').rglob('*'):
 if f.is_file() and (snapshot/'internal'/f.relative_to(root/'internal')).exists():
  if f.read_bytes()!=(snapshot/'internal'/f.relative_to(root/'internal')).read_bytes():difference.append(str(f.relative_to(root)))
assert difference==['internal/targetaggregation/protocol.go'],difference
out={'status':'PASS' if all(checks.values()) and all(older.values()) and a==before and all(sources.values()) else 'FAIL','tracked_files_checked':len(checks),'tracked_mismatches':[n for n,v in checks.items() if not v],'phase1_top_level_files_checked':len(older),'phase1_mismatches':[n for n,v in older.items() if not v],'exact_porcelain_z_status_unchanged':a==before,'workload_source_certificates':sources,'independent_native_snapshot_modified_original_files':difference,'formal_patch_applied':False,'scope':'tracked content hashes, all phase1 top-level hashes, archived workload provenance and exact full git status; not a hash of every ignored/untracked dataset byte'}
(p/'preservation-check.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out));assert out['status']=='PASS'
