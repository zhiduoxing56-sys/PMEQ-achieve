import json,pathlib,os,subprocess
import role_driver as d
p=pathlib.Path(__file__).resolve().parent;c=json.loads((p/'native-command.json').read_text());env=os.environ.copy();env.update(c['env_overrides']);exports=p/'native-coverage-exports';exports.mkdir(exist_ok=True);env['PMEQ_EXTRACTION_OUTPUT_DIR']=str(exports)
a=c['command'][:];a[a.index('-count=5')]='-count=1';a+=['-coverprofile='+str(p/'native.coverage')]
with (p/'native-coverage.log').open('w') as f:r=subprocess.run(a,cwd=c['cwd'],env=env,stdout=f,stderr=subprocess.STDOUT,preexec_fn=d.limits(14))
assert not r.returncode
r=subprocess.run([a[0],'tool','cover','-func='+str(p/'native.coverage')],cwd=c['cwd'],env=env,capture_output=True,text=True);assert not r.returncode;(p/'native-coverage-functions.txt').write_text(r.stdout)
print(r.stdout)
