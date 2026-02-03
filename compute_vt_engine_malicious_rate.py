#!/usr/bin/env python3
import csv
import json
from pathlib import Path

def iter_reports(raw_json_dir: Path):
    for path in sorted(raw_json_dir.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            yield path, data
        except Exception:
            continue

def extract_last_analysis_results(report: dict):
    try:
        return report.get("data", {}).get("attributes", {}).get("last_analysis_results", {}) or {}
    except AttributeError:
        return {}

def main():
    base_dir = Path(__file__).resolve().parent
    raw_json_dir = base_dir / "virustotal_report" / "raw_json"
    if not raw_json_dir.exists():
        raise SystemExit(f"Raw JSON directory not found: {raw_json_dir}")

    totals = {}
    for _, report in iter_reports(raw_json_dir):
        results = extract_last_analysis_results(report)
        for engine, details in results.items():
            if not isinstance(details, dict):
                continue
            category = details.get("category")
            if category is None:
                continue
            if category == "undetected":
                continue
            engine_stats = totals.setdefault(engine, {"malicious": 0, "non_undetected": 0})
            engine_stats["non_undetected"] += 1
            if category == "malicious":
                engine_stats["malicious"] += 1

    rows = []
    for engine, stats in totals.items():
        denom = stats["non_undetected"]
        rate = (stats["malicious"] / denom) if denom else 0.0
        rows.append({
            "engine": engine,
            "malicious": stats["malicious"],
            "non_undetected": denom,
            "malicious_rate": rate,
        })

    rows.sort(key=lambda r: (r["malicious_rate"], r["non_undetected"], r["engine"]), reverse=True)

    output_path = base_dir / "analysis_outputs" / "vt_engine_malicious_rate.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["engine", "malicious", "non_undetected", "malicious_rate"],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote: {output_path}")
    print(f"Engines counted: {len(rows)}")

if __name__ == "__main__":
    main()
