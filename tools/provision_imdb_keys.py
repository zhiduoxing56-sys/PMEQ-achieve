#!/usr/bin/env python3
"""Create the production DO/query-user key pair once, only in an ignored local file."""
import datetime
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / ".private" / "imdb-production-keypair.json"


def main():
    DEST.parent.mkdir(mode=0o700, exist_ok=True)
    if DEST.exists():
        raise SystemExit("existing production key pair retained; refusing to replace it")
    anchor = os.urandom(32)
    target = os.urandom(32)
    raw = (json.dumps({
        "version": "IMDB-100K-10K-20261015-v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "anchor_key_hex": anchor.hex(),
        "target_key_hex": target.hex(),
    }, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(DEST, flags, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    d = os.open(DEST.parent, os.O_RDONLY)
    try:
        os.fsync(d)
    finally:
        os.close(d)
    print("created local production key pair; fingerprint=" + hashlib.sha256(b"PMEQ-IMDB-KEYPAIR-v1" + anchor + target).hexdigest())


if __name__ == "__main__":
    main()
