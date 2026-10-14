#!/usr/bin/env python3
"""Run the fixed two-table query on a saved sample, using Unicode codepoint edits."""
import argparse,json,pathlib
from sample_and_plaintext import ed_through3
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--sample',type=pathlib.Path,required=True)
 p.add_argument('--qdelta',required=True)
 p.add_argument('--qgamma',required=True)
 p.add_argument('--tau-delta',type=int,choices=range(4),required=True)
 p.add_argument('--tau-gamma',type=int,choices=range(4),required=True)
 a=p.parse_args()
 anchors=json.loads((a.sample/'MOVIECAST.json').read_text())
 targets=json.loads((a.sample/'MOVIE.json').read_text())
 tm={r['tconst']:(r,ed_through3(r['primaryTitle'],a.qgamma)) for r in targets}
 pairs=[]
 for r in anchors:
  da=ed_through3(r['aliasTitle'],a.qdelta)
  if da>a.tau_delta:continue
  m,dm=tm[r['tconst']]
  if dm<=a.tau_gamma:
   pairs.append(dict(anchorObjectId=r['objectId'],targetObjectId=m['objectId'],anchorRecordId=r['recordId'],
     targetRecordId=m['recordId'],tconst=r['tconst'],deltaDistance=da,gammaDistance=dm))
 pairs.sort(key=lambda x:(x['anchorObjectId'],x['targetObjectId']))
 print(json.dumps(dict(Qdelta=a.qdelta,Qgamma=a.qgamma,tauDelta=a.tau_delta,tauGamma=a.tau_gamma,
     distance_unit='Unicode codepoints; case and original content preserved',pairCount=len(pairs),pairs=pairs),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
