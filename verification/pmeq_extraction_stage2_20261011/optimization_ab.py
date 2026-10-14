import pathlib,os,json,shutil
import role_driver as d
P=pathlib.Path(__file__).resolve().parent
root=P/'optimization-ab';root.mkdir(exist_ok=False);out=[]
for trial in range(5):
 folder=root/str(trial);meta=d.make(folder,1000000,2,False,seed=202610111700+trial)
 for version in ['roles-v1','roles','roles-final']:
  dest=folder/version;dest.mkdir()
  for f in folder.glob('*.bin'):os.link(f,dest/f.name)
  d.EXE=P/version
  r=d.execute(dest,'sre',cpu_pins=(8,10),client_cpu=12);r.update(meta,trial=trial,version=version,scope='raw shared inputs; branch-only preparation; paired counterfactual instances');out.append(r)
 print('COMPLETE OPTIMIZATION PAIR',trial,flush=True)
(P/'optimization-ab-results.json').write_text(json.dumps(out,indent=2)+'\n')
