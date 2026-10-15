#!/usr/bin/env python3
"""Encrypt the existing IMDb key once and verify an isolated local restore.

Run from a trusted interactive terminal. The passphrase is read without echo,
sent to GPG on a pipe, and never passed in argv, an environment variable, or
the report. The original key is read only and never moved or regenerated.
"""

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / ".private/imdb-production-keypair.json"
SAMPLE_VERSION = "IMDB-100K-10K-20261015-v1"
DOMAIN = b"PMEQ-IMDB-KEYPAIR-v1"


def identity(raw: bytes) -> str:
    data = json.loads(raw)
    if data.get("version") != SAMPLE_VERSION:
        raise ValueError("key file sample version mismatch")
    a = bytes.fromhex(data["anchor_key_hex"])
    b = bytes.fromhex(data["target_key_hex"])
    if len(a) != 32 or len(b) != 32 or not any(a) or not any(b):
        raise ValueError("key file shape mismatch")
    return hashlib.sha256(DOMAIN + a + b).hexdigest()


def gpg(passphrase: str, home: Path, *args: str, output=None) -> None:
    # GPG reads only the passphrase from stdin; its input/output paths are
    # explicit arguments. It emits no key data into the caller's logs.
    result = subprocess.run(
        ["gpg", "--homedir", str(home), "--no-options", "--batch", "--no-tty",
         "--no-symkey-cache", "--pinentry-mode", "loopback",
         "--passphrase-fd", "0", *args],
        input=(passphrase + "\n").encode(), stdout=output or subprocess.DEVNULL,
        stderr=subprocess.PIPE, check=False,
    )
    if result.returncode:
        raise RuntimeError("GPG encryption or isolated decryption failed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True,
                        help="existing long-lived backup directory, preferably on another disk")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                        help="existing production key file; needed when running a downloaded copy")
    args = parser.parse_args()
    source = args.source.absolute()
    source_stat = source.lstat()
    parent_stat = source.parent.lstat()
    if not source.is_file() or source_stat.st_mode & 0o777 != 0o600 or parent_stat.st_mode & 0o777 != 0o700:
        raise SystemExit("production key permissions are unsafe")
    if source_stat.st_uid != os.geteuid() or parent_stat.st_uid != os.geteuid():
        raise SystemExit("production key owner mismatch")
    raw = source.read_bytes()
    fingerprint = identity(raw)
    dest_dir = args.destination.resolve(strict=True)
    if not dest_dir.is_dir() or dest_dir == source.parent:
        raise SystemExit("backup destination must be a separate existing directory")
    backup = dest_dir / ("imdb-production-keypair-" + fingerprint + ".gpg")
    if backup.exists():
        raise SystemExit("backup already exists; refusing to overwrite")
    first = getpass.getpass("New backup passphrase (will not echo): ")
    second = getpass.getpass("Repeat backup passphrase: ")
    if first != second or len(first) < 16:
        raise SystemExit("passphrases differ or are shorter than 16 characters")
    del second
    # Reserve the destination name exclusively. GPG writes ciphertext only.
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        # Keep GPG state and restored plaintext in short-lived 0700 directories.
        with tempfile.TemporaryDirectory(prefix="imdb-key-backup-", dir=source.parent) as isolated:
            gpg_home = Path(isolated) / "gpg"
            gpg_home.mkdir(mode=0o700)
            with os.fdopen(fd, "wb") as out:
                gpg(first, gpg_home, "--cipher-algo", "AES256", "--s2k-mode", "3",
                    "--s2k-digest-algo", "SHA256", "--s2k-count", "65011712",
                    "--symmetric", "--output", "-", str(source), output=out)
                out.flush()
                os.fsync(out.fileno())
            if backup.stat().st_size < 64:
                raise RuntimeError("encrypted backup unexpectedly short")
            restored = Path(isolated) / "recovered.json"
            gpg(first, gpg_home, "--decrypt", "--output", str(restored), str(backup))
            if identity(restored.read_bytes()) != fingerprint or restored.read_bytes() != raw:
                raise RuntimeError("isolated restore identity mismatch")
            restored.unlink()
        digest = hashlib.sha256(backup.read_bytes()).hexdigest()
        receipt = {
            "sample_version": SAMPLE_VERSION,
            "key_fingerprint": fingerprint,
            "backup_path": str(backup),
            "backup_sha256": digest,
            "backup_bytes": backup.stat().st_size,
            "isolated_restore_verified": True,
        }
        receipt_path = source.parent / "imdb-key-backup-receipt.json"
        fd = os.open(receipt_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump(receipt, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        print("Encrypted backup and isolated restore verified.")
        print("Backup:", backup)
        print("Public key identity:", fingerprint)
        print("Ciphertext SHA-256:", digest)
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    finally:
        del first


if __name__ == "__main__":
    main()
