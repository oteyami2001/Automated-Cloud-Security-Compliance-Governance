#!/usr/bin/env python3
"""Build the Lambda deployment package reproducibly.

1. Regenerate ``src/acscg/data/control-catalog.json`` from ``controls/control-catalog.yaml``
   (the Lambda runtime has no YAML parser).
2. Zip ``src/acscg`` (``*.py`` and ``data/*.json``) with fixed timestamps and permissions in sorted
   order, so the same commit always yields the same SHA-256 (verifiable in CI and in Terraform).

Usage:
    scripts/build_lambda.py                  # write dist/acscg-lambda.zip, print its sha256
    scripts/build_lambda.py --catalog-only   # regenerate the packaged catalog only
    scripts/build_lambda.py --check          # exit 1 if the packaged catalog is stale
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "acscg"
CATALOG_JSON = PACKAGE / "data" / "control-catalog.json"
OUTPUT = ROOT / "dist" / "acscg-lambda.zip"
FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def catalog_json() -> str:
    data = yaml.safe_load((ROOT / "controls" / "control-catalog.yaml").read_text("utf-8"))
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def write_catalog() -> bool:
    content = catalog_json()
    changed = not CATALOG_JSON.exists() or CATALOG_JSON.read_text("utf-8") != content
    if changed:
        CATALOG_JSON.write_text(content, "utf-8")
    return changed


def package_files() -> list[Path]:
    files = [p for p in PACKAGE.rglob("*") if p.is_file() and (p.suffix == ".py" or p.parent.name == "data")]
    return sorted(f for f in files if "__pycache__" not in f.parts)


def build(output: Path = OUTPUT) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in package_files():
            info = zipfile.ZipInfo(str(path.relative_to(PACKAGE.parent)), date_time=FIXED_TIME)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main() -> int:
    args = sys.argv[1:]
    if "--check" in args:
        if not CATALOG_JSON.exists() or CATALOG_JSON.read_text("utf-8") != catalog_json():
            print("stale: src/acscg/data/control-catalog.json (run scripts/build_lambda.py --catalog-only)")
            return 1
        return 0
    write_catalog()
    if "--catalog-only" in args:
        return 0
    print(f"{OUTPUT.relative_to(ROOT)} sha256={build()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
