#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import statistics
import textwrap
from collections import Counter
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent
MALWARE_DIR = ROOT / "malware_report"
BENIGN_DIR = ROOT / "benign_report"
OUTPUT_DIR = ROOT / "analysis_outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DATE_RE = re.compile(r"_(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2})_")


def iter_jsonl_files(base: Path) -> Iterable[Path]:
    if not base.exists():
        return []
    for raw_dir in base.rglob("raw"):
        if raw_dir.is_dir():
            yield from raw_dir.glob("*.jsonl")


def extract_sha256_and_ts(path: Path) -> tuple[str, str]:
    stem = path.name
    sha = stem.split("_", 1)[0]
    match = DATE_RE.search(stem)
    if match:
        date_part, time_part = match.groups()
        return sha, f"{date_part} {time_part}"
    return sha, "0000-00-00 00-00-00"


def select_latest_reports(paths: Iterable[Path]) -> tuple[list[Path], list[Path]]:
    latest: dict[str, tuple[str, Path]] = {}
    obsolete: list[Path] = []
    for path in paths:
        sha, ts = extract_sha256_and_ts(path)
        if sha not in latest:
            latest[sha] = (ts, path)
            continue
        if ts > latest[sha][0]:
            obsolete.append(latest[sha][1])
            latest[sha] = (ts, path)
        else:
            obsolete.append(path)
    return [item[1] for item in latest.values()], obsolete


def parse_analyzer_entries(jsonl_path: Path) -> tuple[int, list[str]]:
    descriptions: list[str] = []
    alert_count = 0
    try:
        with jsonl_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if '"type"' not in line or '"ANALYZER"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("type") != "ANALYZER":
                    continue
                alert_count += 1
                result = obj.get("result", {})
                desc = result.get("description")
                if isinstance(desc, str) and desc:
                    descriptions.append(desc)
    except OSError:
        return 0, []
    return alert_count, descriptions


def collect_metrics(base: Path, delete_duplicates: bool = False, dry_run: bool = True) -> dict:
    family_metrics: dict[str, dict] = {}
    total_reports = 0
    total_alert_reports = 0
    alerts_per_report: list[int] = []
    family_desc_counts: dict[str, Counter[str]] = {}
    deleted_count = 0

    if not base.exists():
        return {
            "total_reports": 0,
            "alert_reports": 0,
            "alert_rate": 0.0,
            "avg_alerts_per_report": 0.0,
            "family_desc_counts": {},
        }

    all_jsonl_paths = list(iter_jsonl_files(base))
    latest_paths, obsolete_paths = select_latest_reports(all_jsonl_paths)

    if delete_duplicates:
        for path in obsolete_paths:
            if dry_run:
                continue
            try:
                path.unlink()
                deleted_count += 1
            except OSError:
                continue

    family_to_paths: dict[str, list[Path]] = {}
    for path in latest_paths:
        try:
            family = path.relative_to(base).parts[0]
        except Exception:
            family = "unknown"
        family_to_paths.setdefault(family, []).append(path)

    for family, paths in sorted(family_to_paths.items()):
        desc_counter: Counter[str] = Counter()
        family_reports = 0
        family_alert_reports = 0
        family_alerts_per_report: list[int] = []

        for jsonl_path in paths:
            family_reports += 1
            total_reports += 1
            alert_count, descriptions = parse_analyzer_entries(jsonl_path)
            family_alerts_per_report.append(alert_count)
            alerts_per_report.append(alert_count)
            if alert_count > 0:
                family_alert_reports += 1
                total_alert_reports += 1
            desc_counter.update(descriptions)

        family_metrics[family] = {
            "reports": family_reports,
            "alert_reports": family_alert_reports,
            "alert_rate": (family_alert_reports / family_reports) if family_reports else 0.0,
            "avg_alerts_per_report": (statistics.mean(family_alerts_per_report)
                                      if family_alerts_per_report else 0.0),
        }
        family_desc_counts[family] = desc_counter

    return {
        "total_reports": total_reports,
        "alert_reports": total_alert_reports,
        "alert_rate": (total_alert_reports / total_reports) if total_reports else 0.0,
        "avg_alerts_per_report": (statistics.mean(alerts_per_report)
                                  if alerts_per_report else 0.0),
        "family_desc_counts": family_desc_counts,
        "family_metrics": family_metrics,
        "deleted_count": deleted_count,
    }


def write_summary_csv(path: Path, family_metrics: dict) -> None:
    lines = ["family,reports,alert_reports,alert_rate,avg_alerts_per_report"]
    for family, data in family_metrics.items():
        lines.append(
            f"{family},{data['reports']},{data['alert_reports']},"
            f"{data['alert_rate']:.4f},{data['avg_alerts_per_report']:.4f}"
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_family_top_desc_csv(path: Path, family_desc_counts: dict, top_n: int = 5) -> None:
    lines = ["family,description,count"]
    for family, counter in family_desc_counts.items():
        for desc, count in counter.most_common(top_n):
            safe_desc = desc.replace("\n", " ").replace("\r", " ")
            lines.append(f"{family},\"{safe_desc}\",{count}")
    path.write_text("\n".join(lines), encoding="utf-8")


def plot_family_top_desc(family_desc_counts: dict, out_dir: Path, top_n: int = 5) -> None:
    try:
        import matplotlib.pyplot as plt
        try:
            import seaborn as sns
            sns.set_theme(style="whitegrid", context="talk")
            palette = sns.color_palette("viridis")
        except Exception:
            plt.style.use("ggplot")
            palette = None
    except Exception:
        print("matplotlib not available; skipping plots.")
        return

    for family, counter in family_desc_counts.items():
        if not counter:
            continue
        top_items = counter.most_common(top_n)
        labels = [textwrap.fill(d, width=50) for d, _ in top_items]
        counts = [c for _, c in top_items]
        plt.figure(figsize=(11, 5))
        plt.barh(labels, counts, color=palette)
        plt.xlabel("Count")
        plt.title(f"Top {top_n} analyzer descriptions - {family}")
        plt.gca().invert_yaxis()
        for idx, value in enumerate(counts):
            plt.text(value + 0.05, idx, str(value), va="center", fontsize=10)
        safe_name = family.replace("/", "_")
        plt.tight_layout()
        plt.savefig(out_dir / f"top_descriptions_{safe_name}.png", dpi=150)
        plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze analyzer alerts in reports.")
    parser.add_argument("--delete-duplicates", action="store_true",
                        help="Delete older duplicate jsonl reports by sha256 prefix.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show metrics without deleting files (default).")
    args = parser.parse_args()

    delete_duplicates = args.delete_duplicates
    dry_run = args.dry_run or not delete_duplicates

    malware_metrics = collect_metrics(MALWARE_DIR, delete_duplicates, dry_run)
    benign_metrics = collect_metrics(BENIGN_DIR, delete_duplicates, dry_run)

    print("=== Malware analyzer alert rate ===")
    print(f"Reports: {malware_metrics['total_reports']}")
    print(f"Alert reports: {malware_metrics['alert_reports']}")
    print(f"Alert rate: {malware_metrics['alert_rate']:.4f}")
    print(f"Avg alerts per report: {malware_metrics['avg_alerts_per_report']:.4f}")

    print("=== Benign analyzer false positive rate ===")
    print(f"Reports: {benign_metrics['total_reports']}")
    print(f"Alert reports: {benign_metrics['alert_reports']}")
    print(f"False positive rate: {benign_metrics['alert_rate']:.4f}")
    print(f"Avg alerts per report: {benign_metrics['avg_alerts_per_report']:.4f}")

    if delete_duplicates:
        if dry_run:
            print("\nDuplicate deletion: DRY RUN (no files removed)")
        else:
            total_deleted = malware_metrics.get("deleted_count", 0) + benign_metrics.get("deleted_count", 0)
            print(f"\nDuplicate deletion: removed {total_deleted} files")

    write_summary_csv(OUTPUT_DIR / "malware_family_metrics.csv", malware_metrics.get("family_metrics", {}))
    write_summary_csv(OUTPUT_DIR / "benign_family_metrics.csv", benign_metrics.get("family_metrics", {}))
    write_family_top_desc_csv(OUTPUT_DIR / "malware_family_top_descriptions.csv",
                              malware_metrics.get("family_desc_counts", {}))
    write_family_top_desc_csv(OUTPUT_DIR / "benign_family_top_descriptions.csv",
                              benign_metrics.get("family_desc_counts", {}))

    plot_family_top_desc(malware_metrics.get("family_desc_counts", {}), OUTPUT_DIR)
    plot_family_top_desc(benign_metrics.get("family_desc_counts", {}), OUTPUT_DIR)

    print(f"\nCSV and plots saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
