import json,pathlib,subprocess,os
import role_driver as d
p=pathlib.Path(__file__).resolve().parent;c=json.loads((p/'native-command.json').read_text());env=os.environ.copy();env.update(c['env_overrides']);env['PMEQ_COUNT_PROFILE']=str(p/'local-count-profile-raw.jsonl');a=c['command'][:];a[a.index('TestNativeExtractionExport')]='TestLocalCountSumProfile';a[a.index('-count=5')]='-count=1'
with (p/'local-count-profile.log').open('w') as log:r=subprocess.run(a,cwd=c['cwd'],env=env,stdout=log,stderr=subprocess.STDOUT,preexec_fn=d.limits(14))
assert not r.returncode
