import pathlib,json,subprocess,os,struct
import role_driver as d
p=pathlib.Path(__file__).resolve().parent;root=p/'final-negative-v5';root.mkdir(exist_ok=False);out=[]
for trial in range(5):
 for cap,L,M,expected in [(65,66,1,'capacity'),(17,17,4,'capacity exceeded')]:
  f=root/f'{trial}-{L}';meta=d.make(f,cap,min(M,cap),False,extra_shuffle=cap!=17,private_identifiers=True)
  if L>cap:
   # local dimensions-only failure before any secret-dependent exchange
   x=f/'input0.bin';v=bytearray(x.read_bytes());struct.pack_into('<Q',v,8,L);x.write_bytes(v)
  try:d.execute(f,'sre',adaptive=cap!=17,cpu_pins=(8,10),client_cpu=12)
  except RuntimeError as e:assert expected in str(e);out.append({'trial':trial,'case':expected,'status':'EXPECTED_REJECTION','detail':str(e)})
  else:raise AssertionError('negative case passed')
 for args,reason in [(['prep',root,2**31+1,root/'absent.key',0,'binding',0],'public L'),(['inputs',root,3,4,root/'absent.key',0,'binding',0],'M exceeds')]:
  q=subprocess.run([str(d.EXE),*map(str,args)],capture_output=True,text=True);assert q.returncode and reason in q.stderr
  out.append({'trial':trial,'case':reason,'status':'EXPECTED_REJECTION','detail':q.stderr})
(p/'final-negative-v5-results.json').write_text(json.dumps(out,indent=2)+'\n');print('COMPLETE',len(out),'EXPECTED REJECTIONS')
