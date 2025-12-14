#!/usr/bin/env python3
"""
Scan analysis reports under ELF_samples and compute detection metrics (Accuracy, per-class F1,
FRR, FNR) per family and overall.

Assumptions:
- Preferred layout (current):
        - `malware_report/<family>/...`   -> malicious ground truth
        - `benign_report/<family>/...`    -> benign ground truth
- Fallback (legacy): Each family folder contains a report directory, and
    ground truth is inferred from subfolder names containing
    "benign" / "malicious" / "malware".
- Verdict is parsed from DeepSeek-style reports: the first line matching "Verdict:" is read.
    If the verdict text contains "malicious"/"suspicious" => predicted malicious,
    contains "benign"/"clean" => predicted benign. Unknown verdicts are skipped.
- FRR (False Rejection Rate) = FP / (FP + TN), benign为真类被误判为恶意。
- FNR (False Negative Rate) = FN / (TP + FN), 恶意被误判为良性。

Usage:
    python3 compute_report_metrics.py --root /path/to/ELF_samples

Outputs are printed to stdout as a compact table plus an overall summary.
"""
from __future__ import annotations

import argparse
import re
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

# Folders to ignore at the ELF_samples root (legacy mode)
SKIP_FOLDERS = {"benign", "malware", "benign_report", "malware_report", ".git", "__pycache__"}
# Possible report directory names (checked in order)
REPORT_DIR_CANDIDATES = (
    "analysis_reports_comparison",
    "analysis_reports",
    "analysis_report",
)


@dataclass
class Counters:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    def update(self, gt: str, pred: str) -> None:
        if gt == "malicious" and pred == "malicious":
            self.tp += 1
        elif gt == "malicious" and pred == "benign":
            self.fn += 1
        elif gt == "benign" and pred == "malicious":
            self.fp += 1
        elif gt == "benign" and pred == "benign":
            self.tn += 1

    def merge(self, other: "Counters") -> None:
        self.tp += other.tp
        self.tn += other.tn
        self.fp += other.fp
        self.fn += other.fn

    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    def f1_malicious(self) -> float:
        """F1 treating malicious as the positive class."""
        p = self.precision()
        r = self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def f1_benign(self) -> float:
        """F1 treating benign as the positive class."""
        # For benign-as-positive: TP_b = TN, FP_b = FN, FN_b = FP
        p = self.tn / (self.tn + self.fn) if (self.tn + self.fn) else 0.0
        r = self.tn / (self.tn + self.fp) if (self.tn + self.fp) else 0.0
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def accuracy(self) -> float:
        denom = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / denom if denom else 0.0

    def frr(self) -> float:
        """False Rejection Rate (benign rejected as malicious)."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def fnr(self) -> float:
        """False Negative Rate (malicious missed as benign)."""
        denom = self.fn + self.tp
        return self.fn / denom if denom else 0.0


VERDICT_REGEX = re.compile(r"Verdict:\s*\*\*(.+?)\*\*", re.IGNORECASE)
RISK_SCORE_REGEX = re.compile(r"Risk\s*Score:[^0-9]*([0-9]+)\s*/\s*100", re.IGNORECASE)


def normalize_verdict(text: str) -> Optional[str]:
    t = text.lower()
    if "malicious" in t or "suspicious" in t:
        return "malicious"
    if "benign" in t or "clean" in t:
        return "benign"
    return None


def parse_risk_score(content: str) -> Optional[int]:
    """Extract numeric risk score (0-100) if present."""
    match = RISK_SCORE_REGEX.search(content)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def parse_report_verdict(report_path: Path) -> Optional[str]:
    try:
        content = report_path.read_text(errors="ignore")
    except Exception:
        return None

    match = VERDICT_REGEX.search(content)
    if match:
        verdict_text = match.group(1)
        verdict = normalize_verdict(verdict_text)
        if verdict:
            return verdict

    # Fallback: scan lines containing "verdict"
    for line in content.splitlines():
        if "verdict" in line.lower():
            maybe = normalize_verdict(line)
            if maybe:
                return maybe

    # Fallback: infer from risk score when verdict is Unknown/empty
    risk = parse_risk_score(content)
    if risk is not None:
        # Treat any non-trivial risk as malicious, low/zero risk as benign
        return "malicious" if risk >= 50 else "benign"
    return None


def infer_ground_truth(folder_name: str) -> Optional[str]:
    name = folder_name.lower()
    if "benign" in name:
        return "benign"
    if "malicious" in name or "malware" in name:
        return "malicious"
    return None


def find_report_root(family_dir: Path) -> Optional[Path]:
    for cand in REPORT_DIR_CANDIDATES:
        candidate = family_dir / cand
        if candidate.is_dir():
            return candidate
    return None


def iter_report_files(label_dir: Path) -> Iterable[Path]:
    for path in label_dir.iterdir():
        if path.is_file() and path.suffix.lower() in {".txt", ".md"}:
            yield path


def iter_report_files_recursive(base: Path) -> Iterable[Path]:
    """Yield report files (.txt/.md) recursively under base."""
    for path in base.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".txt", ".md"}:
            yield path


def compute_family_counters(family_dir: Path) -> Counters:
    counters = Counters()
    report_root = find_report_root(family_dir)
    if not report_root:
        print(f"[WARN] No report directory found in {family_dir}")
        return counters

    for label_dir in report_root.iterdir():
        if not label_dir.is_dir():
            continue
        gt = infer_ground_truth(label_dir.name)
        if not gt:
            print(f"[WARN] Skip unknown label dir: {label_dir}")
            continue

        for report_file in iter_report_files(label_dir):
            pred = parse_report_verdict(report_file)
            if not pred:
                print(f"[WARN] Could not parse verdict in {report_file}")
                continue
            counters.update(gt, pred)
    return counters


def compute_bucket_family_counters(family_dir: Path, gt: str) -> Counters:
    counters = Counters()
    found = False
    for report_file in iter_report_files_recursive(family_dir):
        found = True
        pred = parse_report_verdict(report_file)
        if not pred:
            print(f"[WARN] Could not parse verdict in {report_file}")
            continue
        counters.update(gt, pred)
    if not found:
        print(f"[WARN] No report files found under {family_dir}")
    return counters


def format_metrics(name: str, c: Counters) -> str:
    return (
        f"{name:<15} | TP {c.tp:3d} FP {c.fp:3d} TN {c.tn:3d} FN {c.fn:3d} "
        f"| ACC {c.accuracy():.3f} F1_mal {c.f1_malicious():.3f} F1_ben {c.f1_benign():.3f} "
        f"FRR {c.frr():.3f} FNR {c.fnr():.3f}"
    )


def write_table_csv(path: Path, family_results: list[tuple[str, Counters]], overall: Counters) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    header = [
        "family", "tp", "fp", "tn", "fn",
        "acc", "f1_mal", "f1_ben", "frr", "fnr",
    ]
    for name, c in family_results:
        rows.append([
            name, c.tp, c.fp, c.tn, c.fn,
            f"{c.accuracy():.6f}", f"{c.f1_malicious():.6f}", f"{c.f1_benign():.6f}",
            f"{c.frr():.6f}", f"{c.fnr():.6f}",
        ])
    rows.append([
        "ALL", overall.tp, overall.fp, overall.tn, overall.fn,
        f"{overall.accuracy():.6f}", f"{overall.f1_malicious():.6f}", f"{overall.f1_benign():.6f}",
        f"{overall.frr():.6f}", f"{overall.fnr():.6f}",
    ])
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    print(f"Saved metrics table -> {path}")


def plot_confusion_matrix(path: Path, overall: Counters) -> None:
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError as exc:
        msg = (
            "matplotlib and numpy are required for confusion matrix plotting. "
            "Install with `pip install matplotlib numpy`."
        )
        raise SystemExit(msg) from exc

    cm = np.array([[overall.tp, overall.fn], [overall.fp, overall.tn]], dtype=float)
    labels = ["Malicious", "Benign"]

    fig, ax = plt.subplots(figsize=(4, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], labels)
    ax.set_yticks([0, 1], labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Overall Confusion Matrix")

    # Annotate cells
    for i in range(2):
        for j in range(2):
            ax.text(j, i, int(cm[i, j]), ha="center", va="center", color="black")

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"Saved confusion matrix -> {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute detection metrics from analysis reports")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Path to ELF_samples root (default: this script's directory)",
    )
    parser.add_argument(
        "--table-out",
        type=Path,
        default=None,
        help="Optional path to save metrics table as CSV",
    )
    parser.add_argument(
        "--confusion-out",
        type=Path,
        default=None,
        help="Optional path to save overall confusion matrix PNG",
    )
    args = parser.parse_args()

    root: Path = args.root
    if not root.is_dir():
        raise SystemExit(f"Root path not found: {root}")

    family_results, overall = collect_metrics(root)

    print("\nPer-family metrics (F1, FRR, FNR):")
    print("-" * 70)
    for name, c in family_results:
        print(format_metrics(name, c))
    print("-" * 70)
    print("Overall:")
    print(format_metrics("ALL", overall))

    if args.table_out:
        write_table_csv(args.table_out, family_results, overall)
    if args.confusion_out:
        plot_confusion_matrix(args.confusion_out, overall)


def collect_metrics(root: Path) -> tuple[list[tuple[str, Counters]], Counters]:
    overall = Counters()
    family_results: list[tuple[str, Counters]] = []

    malware_bucket = root / "malware_report"
    benign_bucket = root / "benign_report"

    if malware_bucket.is_dir() or benign_bucket.is_dir():
        bucket_map = [(malware_bucket, "malicious"), (benign_bucket, "benign")]
        for bucket, gt in bucket_map:
            if not bucket.is_dir():
                continue
            for family_dir in sorted(p for p in bucket.iterdir() if p.is_dir()):
                counters = compute_bucket_family_counters(family_dir, gt)
                family_results.append((family_dir.name, counters))
                overall.merge(counters)
    else:
        # Legacy layout fallback
        for family_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            if family_dir.name in SKIP_FOLDERS:
                continue
            if family_dir.name.startswith('.'): 
                continue

            counters = compute_family_counters(family_dir)
            family_results.append((family_dir.name, counters))
            overall.merge(counters)

    return family_results, overall


if __name__ == "__main__":
    main()
