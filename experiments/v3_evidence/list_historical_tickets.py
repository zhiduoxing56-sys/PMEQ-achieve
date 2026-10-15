#!/usr/bin/env python3
"""Read-only inventory of historical one-use tickets; never deletes material."""

import hashlib
import json
import argparse
from pathlib import Path


# Run from the PMEQ workspace root so the private namespace is explicit.
ROOT = Path.cwd()
PRIVATE = ROOT / ".private"
TICKET_ROOTS = (
    "imdb-v2-tickets",
    "imdb-shadow-small-matrix-tickets",
    "imdb-shadow-small-zero-poly-tickets",
    "imdb-shadow-tail-matrix-tickets",
    "imdb-shadow-tail-zero-poly-tickets",
)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def one_ticket(root, ticket, verify_material):
    files = [p for p in ticket.rglob("*") if p.is_file() and not p.is_symlink()]
    markers = [ticket / role / (ticket.name + ".consumed") for role in ("user", "cs0", "cs1")]
    markers = [p for p in markers if p.is_file()]
    material = [p for p in files if p.name == "material.bin"]
    manifests = [p for p in files if p.name == "manifest.json"]
    seal = ticket / "ticket-seal.json"
    receipt = ticket / "trusted-seal.sha256"
    result_roots = []
    if root.name == "imdb-v2-tickets":
        result_roots = [PRIVATE / "imdb-v2-e2e-results"]
    else:
        result_roots = [PRIVATE / root.name.replace("-tickets", "-results")]
    reports = [str(p / ticket.name / "complete.json") for p in result_roots if (p / ticket.name / "complete.json").is_file()]
    if len(markers) == 3:
        state = "consumed"
    elif markers:
        state = "uncertain_or_partial"
    elif seal.is_file() and len(material) == 3 and len(manifests) == 3 and receipt.is_file():
        state = "unconsumed_sealed"
    else:
        state = "damaged_or_incomplete"
    verified = None
    if verify_material:
        verified = seal.is_file() and receipt.is_file() and len(manifests) == 3 and len(material) == 3
        if verified:
            declared = json.loads(seal.read_text())
            verified = receipt.read_text().strip() == digest(seal)
            for i, role in enumerate(("user", "cs0", "cs1")):
                manifest = ticket / role / "manifest.json"
                body = ticket / role / "material.bin"
                meta = json.loads(manifest.read_text())
                verified = verified and digest(manifest) == declared["RoleManifestSHA256"][i]
                verified = verified and body.stat().st_size == meta["MaterialBytes"]
                verified = verified and digest(body) == meta["MaterialSHA256"]
    return {
        "path": str(ticket),
        "bytes": sum(p.stat().st_size for p in files),
        "state": state,
        "consumed_markers": [str(p) for p in markers],
        "complete_reports": reports,
        "ticket_seal_sha256": digest(seal) if seal.is_file() else None,
        "trusted_receipt_present": receipt.is_file(),
        "role_manifest_count": len(manifests),
        "material_file_count": len(material),
        "independent_backup_verified": False,
        "hash_evidence_verified": verified,
        "cleanup_candidate": state == "consumed" and bool(reports),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-material", action="store_true", help="stream-hash each historical material file")
    args = parser.parse_args()
    entries = []
    for name in TICKET_ROOTS:
        root = PRIVATE / name
        if root.is_dir():
            entries.extend(one_ticket(root, p, args.verify_material) for p in sorted(root.iterdir()) if p.is_dir())
    print(json.dumps({"read_only": True, "delete_performed": False, "entries": entries}, indent=2))


if __name__ == "__main__":
    main()
