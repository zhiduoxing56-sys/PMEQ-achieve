"""Read-only verification of the original tracked tree and complete git status."""
import json,hashlib,subprocess
from pathlib import Path
P=Path(__file__).resolve().parent;R=P.parent.parent
def main():
    before=json.loads((P/'tracked-before.json').read_text());changed=[]
    for f,h in before.items():
        a=R/f
        if not a.exists() or hashlib.sha256(a.read_bytes()).hexdigest()!=h:changed.append(f)
    status=subprocess.check_output(['git','--no-optional-locks','status','--porcelain=v1','-z'],cwd=R)
    (P/'git-status-after.txt').write_bytes(status);old=(P/'git-status-before.txt').read_bytes()
    # verification/ was already untracked before this task; require the entire
    # original porcelain output to match, rather than ignoring that directory.
    out=dict(status='PASS' if not changed and status==old else 'FAIL',tracked_files_checked=len(before),changed_tracked_files=changed,git_status_exactly_unchanged=status==old,original_tree_was_dirty=True,initial_status_sha256=hashlib.sha256(old).hexdigest(),final_status_sha256=hashlib.sha256(status).hexdigest())
    (P/'preservation-check.json').write_text(json.dumps(out,indent=2));print(json.dumps(out));assert out['status']=='PASS'
if __name__=='__main__':main()
