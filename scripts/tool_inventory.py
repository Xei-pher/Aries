from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from common import aries_root

# Current Zimmerman command-line forensic utilities we can safely discover and
# invoke from an existing C:\Tools tree. GUI-only utilities are intentionally
# omitted from the automatic wrapper.
KNOWN_EZ = [
    "AmcacheParser.exe",
    "AppCompatCacheParser.exe",
    "bstrings.exe",
    "EvtxECmd.exe",
    "Hasher.exe",
    "JLECmd.exe",
    "LECmd.exe",
    "MFTECmd.exe",
    "PECmd.exe",
    "RBCmd.exe",
    "RecentFileCacheParser.exe",
    "RECmd.exe",
    "RLA.exe",
    "SBECmd.exe",
    "SQLECmd.exe",
    "SrumECmd.exe",
    "SumECmd.exe",
    "WxTCmd.exe",
    "iisGeoLocate.exe",
]


def find_all(root: Path, filename: str) -> list[str]:
    if not root.exists():
        return []
    return [str(p) for p in sorted(root.rglob(filename)) if p.is_file()]


def main() -> None:
    ap = argparse.ArgumentParser(description="Inventory Aries DFIR tools")
    ap.add_argument("--tools-root", default=r"C:\Tools")
    args = ap.parse_args()

    tools_root = Path(args.tools_root)
    data = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "tools_root": str(tools_root),
        "python_tools": {
            "vol": shutil.which("vol"),
            "target-query": shutil.which("target-query"),
            "target-info": shutil.which("target-info"),
            "target-dump": shutil.which("target-dump"),
        },
        "eztools": {},
    }
    for filename in KNOWN_EZ:
        matches = find_all(tools_root, filename)
        data["eztools"][Path(filename).stem] = {
            "found": bool(matches),
            "preferred": matches[0] if matches else None,
            "all": matches,
        }

    out_dir = aries_root() / "config"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "tools.json"
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(json.dumps(data, indent=2))
    print(f"\nInventory written: {out}")


if __name__ == "__main__":
    main()
