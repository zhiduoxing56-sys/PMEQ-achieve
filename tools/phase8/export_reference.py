#!/usr/bin/env python3
"""Instrument a /tmp COPY of the existing standalone, never the old repository."""
import sys
from pathlib import Path
src=Path('/home/tenggn/projects/new-pmeq/dmpf_agg_proto/src/bin/boolean_equality_audit.rs')
dst=Path(sys.argv[1]).resolve()
if not str(dst).startswith('/tmp/'):
    raise SystemExit('destination must be under /tmp')
s=src.read_text().replace('let listener = TcpListener::bind', '''if let Ok(dir) = env::var("PMEQ_AUDIT_EXPORT") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/x0.bin"),bytes(&x0)).unwrap();
        std::fs::write(format!("{dir}/x1.bin"),bytes(&x1)).unwrap();
        std::fs::write(format!("{dir}/truth.bin"),truth.iter().map(|v|*v as u8).collect::<Vec<_>>()).unwrap();
    }
    let listener = TcpListener::bind''').replace('let mut errors = 0;', '''if let Ok(dir) = env::var("PMEQ_AUDIT_EXPORT") {
        std::fs::write(format!("{dir}/out0.bin"),bytes(&a.0)).unwrap();
        std::fs::write(format!("{dir}/out1.bin"),bytes(&b.0)).unwrap();
    }
    let mut errors = 0;''')
dst.parent.mkdir(parents=True,exist_ok=True)
dst.write_text(s)
