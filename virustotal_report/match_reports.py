#!/usr/bin/env python3
"""
Cross-check DeepSeek analysis reports under malware_report/*/analysis_reports_comparison
against VirusTotal metadata in all_samples.json.

What it does:
1) Recursively scan analysis reports (skip 04_BENIGN) to extract:
   - sha256 (from "Target" line)
   - family (from "Family:" line)
   - threat categories (from "Threat Categories:" line)
2) Look up sha256 in all_samples.json.
3) Compare normalized tags (case-insensitive, split on non-alnum and '/').
4) Emit a CSV summarizing match status per sample and print an overview.

Usage:
    python match_reports.py \
        --reports-root ../malware_report \
        --vt-json all_samples.json \
        --out match_results.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Regexes for parsing report fields
TARGET_REGEX = re.compile(r"Target:\s*`([0-9a-fA-F]{64})", re.IGNORECASE)
FAMILY_REGEX = re.compile(r"Family:\s*`([^`]+)`|Family:\s*\*\*([^*]+)\*\*", re.IGNORECASE)
CATEGORIES_REGEX = re.compile(r"Threat Categories:\s*`([^`]*)`|Threat Categories:\s*\*\*([^*]*)\*\*", re.IGNORECASE)


def normalize_tokens(text: str) -> Set[str]:
    """Split text on non-alnum and '/' then lowercase; drop empties."""
    parts = re.split(r"[^A-Za-z0-9]+|/", text)
    return {p.lower() for p in parts if p}


def normalize_list(vals: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for v in vals:
        out |= normalize_tokens(v)
    return out


def token_similar(a: str, b: str) -> bool:
    """Lightweight fuzzy check: prefix/substring len>=4 or high ratio."""
    if a == b:
        return True
    # quick substring/prefix match for abbreviations (len>=4 to avoid noise)
    if len(a) >= 4 and len(b) >= 4:
        if a in b or b in a:
            return True
        if a.startswith(b) or b.startswith(a):
            return True
    # fallback ratio
    try:
        from difflib import SequenceMatcher
        return SequenceMatcher(None, a, b).ratio() >= 0.82
    except Exception:
        return False


def sets_overlap_fuzzy(src: Set[str], targets: List[Set[str]], enable_fuzzy: bool) -> bool:
    # exact match first
    if any(src & t for t in targets if t):
        return True
    if not enable_fuzzy:
        return False
    # fuzzy cross-product check (small sets, tokens only)
    for tset in targets:
        for a in src:
            for b in tset:
                if token_similar(a, b):
                    return True
    return False


def overlap_score(src: Set[str], tgt: Set[str], enable_fuzzy: bool) -> float:
    """Return similarity in [0,1] between two token sets.

    Score = matched_tokens / max(len(src), len(tgt), 1)
    where a report token is counted as matched if it equals (or fuzzily equals)
    any VT token. This bounds the score, avoids double-counting, and is
    symmetric when len(src)==len(tgt).
    """
    if not src or not tgt:
        return 0.0

    matched = 0
    for a in src:
        # exact hit first
        if a in tgt:
            matched += 1
            continue
        if not enable_fuzzy:
            continue
        if any(token_similar(a, b) for b in tgt):
            matched += 1

    denom = max(len(src), len(tgt), 1)
    return matched / denom


def parse_report(path: Path) -> Optional[dict]:
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return None

    target = None
    m = TARGET_REGEX.search(content)
    if m:
        target = m.group(1)
        # strip trailing extension if present (e.g., .elf)
        target = target.lower()
    else:
        # try more relaxed capture: grab 64 hex before .elf
        m2 = re.search(r"([0-9a-fA-F]{64})\.elf", content)
        if m2:
            target = m2.group(1).lower()
    if not target:
        return None

    fam_match = FAMILY_REGEX.search(content)
    family_raw = fam_match.group(1) if fam_match and fam_match.group(1) else (fam_match.group(2) if fam_match else None)

    cat_match = CATEGORIES_REGEX.search(content)
    cat_raw = cat_match.group(1) if cat_match and cat_match.group(1) is not None else (cat_match.group(2) if cat_match else None)
    cats = []
    if cat_raw:
        cats = [c.strip() for c in re.split(r"[,;]", cat_raw) if c.strip()]

    return {
        "sha": target.lower(),
        "family_raw": family_raw or "",
        "cats_raw": cats,
        "family_tokens": normalize_tokens(family_raw) if family_raw else set(),
        "cat_tokens": normalize_list(cats),
    }


def iter_reports(reports_root: Path) -> Iterable[Path]:
    for family_dir in sorted(p for p in reports_root.iterdir() if p.is_dir()):
        comp = family_dir / "analysis_reports_comparison"
        if not comp.is_dir():
            continue
        for bucket in comp.iterdir():
            if not bucket.is_dir():
                continue
            if bucket.name.upper() == "04_BENIGN":
                continue
            for rpt in bucket.glob("*_deepseek_report.txt"):
                yield rpt


def load_vt(path: Path) -> Dict[str, dict]:
    """Load all_samples.json and supplement with raw_json/*.json if present."""
    with path.open() as f:
        data = json.load(f)
    db: Dict[str, dict] = {k.lower(): v for k, v in data.items()}

    raw_dir = path.parent / "raw_json"
    if raw_dir.is_dir():
        for jf in raw_dir.glob("*.json"):
            try:
                obj = json.load(jf.open())
            except Exception:
                continue
            attrs = obj.get("data", {}).get("attributes", {})
            sha = attrs.get("sha256")
            if not sha:
                continue

            ptc = attrs.get("popular_threat_classification", {}) or {}
            # Map VT fields to our simplified schema
            entry = {
                "suggested_threat_label": ptc.get("suggested_threat_label"),
                "threat_category": [x.get("value") for x in (ptc.get("popular_threat_category") or []) if x.get("value")],
                "threat_name": [x.get("value") for x in (ptc.get("popular_threat_name") or []) if x.get("value")],
            }
            db[sha.lower()] = entry
    return db


def vt_tokens(entry: dict) -> Tuple[Set[str], Set[str], Set[str]]:
    lbl = entry.get("suggested_threat_label") or ""
    cats = entry.get("threat_category") or []
    names = entry.get("threat_name") or []
    return normalize_tokens(lbl), normalize_list(cats), normalize_list(names)


def compare_sets(report_set: Set[str], vt_sets: List[Set[str]], enable_fuzzy: bool) -> bool:
    return sets_overlap_fuzzy(report_set, vt_sets, enable_fuzzy)


def main() -> None:
    parser = argparse.ArgumentParser(description="Match DeepSeek reports to VT metadata")
    parser.add_argument("--reports-root", type=Path, default=Path("../malware_report"))
    parser.add_argument("--vt-json", type=Path, default=Path("all_samples.json"))
    parser.add_argument("--out", type=Path, default=Path("match_results.csv"))
    parser.add_argument("--no-fuzzy", action="store_true", help="Disable fuzzy token matching (substring/ratio)")
    args = parser.parse_args()

    vt_db = load_vt(args.vt_json)

    rows = []
    total = 0
    found = 0
    family_match = 0
    category_match = 0
    any_match = 0
    sim_sum = 0.0
    missing_sha = []

    for rpt in iter_reports(args.reports_root):
        parsed = parse_report(rpt)
        if not parsed:
            continue
        total += 1
        sha = parsed["sha"]
        vt = vt_db.get(sha)
        if not vt:
            missing_sha.append(sha)
            rows.append({
                "sha": sha,
                "report_family": parsed["family_raw"],
                "report_categories": ";".join(parsed["cats_raw"]),
                "vt_found": False,
                "vt_label": "",
                "vt_categories": "",
                "vt_names": "",
                "family_match": False,
                "category_match": False,
                "any_match": False,
                "similarity_score": 0.0,
                "report_path": str(rpt),
            })
            continue

        found += 1
        vt_lbl_set, vt_cat_set, vt_name_set = vt_tokens(vt)
        fuzzy = not args.no_fuzzy
        fam_ok = compare_sets(parsed["family_tokens"], [vt_lbl_set, vt_cat_set, vt_name_set], fuzzy)
        cat_ok = compare_sets(parsed["cat_tokens"], [vt_lbl_set, vt_cat_set, vt_name_set], fuzzy)
        any_ok = fam_ok or cat_ok
        family_match += bool(fam_ok)
        category_match += bool(cat_ok)
        any_match += bool(any_ok)

        # similarity across all tokens (family + categories vs VT label/cat/name)
        report_all = parsed["family_tokens"] | parsed["cat_tokens"]
        vt_all = vt_lbl_set | vt_cat_set | vt_name_set
        sim = overlap_score(report_all, vt_all, fuzzy)
        sim_sum += sim

        rows.append({
            "sha": sha,
            "report_family": parsed["family_raw"],
            "report_categories": ";".join(parsed["cats_raw"]),
            "vt_found": True,
            "vt_label": vt.get("suggested_threat_label", ""),
            "vt_categories": ";".join(vt.get("threat_category") or []),
            "vt_names": ";".join(vt.get("threat_name") or []),
            "family_match": fam_ok,
            "category_match": cat_ok,
            "any_match": any_ok,
            "similarity_score": round(sim, 3),
            "report_path": str(rpt),
        })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [
            "sha", "report_family", "report_categories", "vt_found", "vt_label", "vt_categories", "vt_names", "family_match", "category_match", "any_match", "report_path"
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Processed reports: {total}")
    print(f"Found in VT JSON: {found}")
    print(f"Family match: {family_match}/{found}")
    print(f"Category match: {category_match}/{found}")
    print(f"Any match (family or category): {any_match}/{found}")
    if found:
        print(f"Similarity score avg (family+cats vs VT tokens): {sim_sum / found:.3f}")
    if missing_sha:
        print(f"Missing {len(missing_sha)} sha entries (not in all_samples.json). Example: {missing_sha[:5]}")
    print(f"Saved CSV -> {args.out}")


if __name__ == "__main__":
    main()
