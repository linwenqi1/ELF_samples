#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
from pathlib import Path


TARGET_RE = re.compile(r"\*\*Target:\*\*\s+`([^`]+)`")


def find_report_dirs(base: Path) -> list[Path]:
    candidates: list[Path] = []
    for name in ("04_BENIGN", "04_genign", "04_benign"):
        candidates.extend(base.rglob(name))
    return [p for p in candidates if p.is_dir()]


def extract_targets(report_path: Path) -> list[str]:
    try:
        text = report_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    matches = TARGET_RE.findall(text)
    return [m.strip() for m in matches if m.strip()]


def main() -> None:
    root = Path(__file__).resolve().parent
    reports_base = root / "malware_report" / ""
    malware_bin = root / "malware" / "Gafgyt"
    retest_dir = root / "malware" / "Gafgyt" / "retest"
    retest_dir.mkdir(parents=True, exist_ok=True)

    report_dirs = find_report_dirs(reports_base)
    if not report_dirs:
        print(f"No report dirs found under {reports_base}")
        return

    targets: set[str] = set()
    for report_dir in report_dirs:
        for report_file in report_dir.rglob("*.txt"):
            for target in extract_targets(report_file):
                targets.add(target)

    if not targets:
        print("No targets found in reports.")
        return

    copied = 0
    missing: list[str] = []
    for target in sorted(targets):
        src = malware_bin / target
        if src.exists():
            shutil.copy2(src, retest_dir / src.name)
            copied += 1
        else:
            missing.append(target)

    print(f"Targets found: {len(targets)}")
    print(f"Copied: {copied} -> {retest_dir}")
    if missing:
        print("Missing in malware/Gafgyt/bin:")
        for item in missing:
            print(f"  - {item}")


if __name__ == "__main__":
    main()
