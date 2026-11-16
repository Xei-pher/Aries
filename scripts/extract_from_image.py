from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from dissect.target import Target

from common import case_dir, evidence_path, load_case


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_destination(root: Path, requested: str | None, source_name: str) -> Path:
    base = (root / "extracted").resolve()
    base.mkdir(parents=True, exist_ok=True)
    dest = (base / (requested or source_name)).resolve()
    try:
        dest.relative_to(base)
    except ValueError as exc:
        raise SystemExit("--out must stay inside the case extracted/ directory") from exc
    dest.parent.mkdir(parents=True, exist_ok=True)
    return dest


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract one file from an E01 through Dissect into the Aries case workspace")
    ap.add_argument("--case", required=True)
    ap.add_argument("--path", required=True, help="Path inside the target, e.g. sysvol/Windows/System32/winevt/Logs/Security.evtx")
    ap.add_argument("--out", help="Relative output path underneath case/extracted/")
    ap.add_argument("--e01", help="Override the E01 registered in the case")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    case = load_case(args.case)
    image = Path(args.e01) if args.e01 else evidence_path(case, "e01")
    if not image or not image.is_file():
        raise SystemExit(f"E01 evidence is missing or unreadable: {image}")

    internal = args.path.replace("\\", "/").lstrip("/")
    source_name = Path(internal).name or "artifact.bin"
    root = case_dir(args.case)
    dest = safe_destination(root, args.out, source_name)
    if dest.exists() and not args.force:
        raise SystemExit(f"Destination exists: {dest}. Use --force to overwrite it.")

    print(f"Opening target: {image}")
    target = Target.open(str(image))
    src = target.fs.path(internal)
    if not src.exists():
        raise SystemExit(f"Path not found in target: {internal}")
    if not src.is_file():
        raise SystemExit(f"Target path is not a file: {internal}")

    with src.open("rb") as fin, dest.open("wb") as fout:
        shutil.copyfileobj(fin, fout, length=8 * 1024 * 1024)

    digest = sha256_file(dest)
    metadata = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_image": str(image),
        "source_target_path": internal,
        "destination": str(dest),
        "size_bytes": dest.stat().st_size,
        "sha256": digest,
    }
    sidecar = dest.with_name(dest.name + ".aries.json")
    sidecar.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
