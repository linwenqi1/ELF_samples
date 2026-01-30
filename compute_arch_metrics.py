#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

TARGET_RE = re.compile(r"\*\*Target:\*\*\s+`([^`]+)`")
STATUS_REGEX = re.compile(r"Execution Status[^`\n]*`([^`]+)`", re.IGNORECASE)

ARCH_MAP = {
    2: "sparc",
    3: "x86_32",
    4: "m68k",
    8: "mips",
    20: "ppc32",
    21: "ppc64",
    40: "arm32",
    42: "superh",
    62: "x86_64",
    183: "arm64",
    243: "riscV64",
}

UNIFIED_ARCH_MAP = {
    "x86_32": "x86",
    "x86_64": "x86",
    "arm32": "ARM",
    "arm64": "ARM",
    "ppc32": "PowerPC",
    "ppc64": "PowerPC",
    "mips": "MIPS",
    "sparc": "SPARC",
    "m68k": "m68k",
    "superh": "SuperH",
    "riscV64": "RISC-V",
}


def get_unified_arch(arch: str) -> str:
    return UNIFIED_ARCH_MAP.get(arch, arch)


REPORT_DIR_MARKERS = {
    "analysis_reports_comparison",
    "analysis_reports",
    "analysis_report",
}

LABEL_DIRS = {
    "01_MALICIOUS",
    "02_SUSPICIOUS",
    "03_SECURITY_TOOL",
    "04_BENIGN",
}


@dataclass
class ArchCounters:
    malicious_total: int = 0
    benign_total: int = 0
    
    tp: int = 0
    fn: int = 0
    tn: int = 0
    fp: int = 0
    
    crash: int = 0
    failed_deps: int = 0
    arg_error: int = 0

    @property
    def total(self) -> int:
        return self.malicious_total + self.benign_total

    def error_rate(self) -> float:
        # Error rate only includes crash and failed_deps. arg_error is excluded.
        return (self.crash + self.failed_deps) / self.total if self.total else 0.0

    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def fnr(self) -> float:
        denom = self.fn + self.tp
        return self.fn / denom if denom else 0.0

    def accuracy(self) -> float:
        denom = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / denom if denom else 0.0


def parse_report(report_path: Path) -> tuple[Optional[str], Optional[str]]:
    try:
        content = report_path.read_text(errors="ignore")
    except Exception:
        return None, None

    target_match = TARGET_RE.search(content)
    target = target_match.group(1).strip() if target_match else None

    status_match = STATUS_REGEX.search(content)
    status = status_match.group(1).strip() if status_match else None

    return target, status


def read_elf_arch(binary_path: Path) -> Optional[str]:
    try:
        data = binary_path.read_bytes()[:64]
    except OSError:
        return None

    if len(data) < 20 or not data.startswith(b"\x7fELF"):
        return None

    endian_tag = data[5]
    if endian_tag == 1:
        endian = "<"
    elif endian_tag == 2:
        endian = ">"
    else:
        return None

    e_machine = int.from_bytes(data[18:20], byteorder="little" if endian == "<" else "big")
    return ARCH_MAP.get(e_machine, f"unknown_{e_machine}")


def build_malware_arch_index(root: Path) -> dict[str, str]:
    index: dict[str, str] = {}
    malware_root = root / "malware"
    if not malware_root.is_dir():
        return index

    for path in malware_root.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        arch = read_elf_arch(path)
        if not arch:
            continue
        index.setdefault(path.name, arch)
        if path.suffix == ".elf":
            index.setdefault(path.stem, arch)
    return index


def infer_malware_arch(
    root: Path,
    family: str,
    target: str,
    index: dict[str, str],
) -> str:
    family_dir = root / "malware" / family
    candidates = [family_dir / target]
    if not target.endswith(".elf"):
        candidates.append(family_dir / f"{target}.elf")

    for path in candidates:
        if path.is_file():
            arch = read_elf_arch(path)
            if arch:
                return arch

    if target in index:
        return index[target]
    if target.endswith(".elf") and target[:-4] in index:
        return index[target[:-4]]
    return "unknown"


def iter_report_files(bucket: Path) -> list[Path]:
    files: list[Path] = []
    for path in bucket.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".txt", ".md"}:
            continue
        if "raw" in path.parts:
            continue
        if not REPORT_DIR_MARKERS.intersection(path.parts):
            continue
        files.append(path)
    return files


def update_counters(
    counter: ArchCounters,
    gt: str,
    label_dir: Optional[str],
    status: Optional[str],
) -> None:
    if gt == "malicious":
        counter.malicious_total += 1
    else:
        counter.benign_total += 1

    if status:
        status_upper = status.upper()
        if "CRASH" in status_upper:
            counter.crash += 1
        elif "FAILED_DEPENDENC" in status_upper:
            counter.failed_deps += 1
        elif "ARGUMENT" in status_upper:
            counter.arg_error += 1
    
    # If we have a label_dir, it means we parsed a verdict
    if label_dir:
        # Check correctness
        if gt == "malicious":
            if label_dir in {"01_MALICIOUS", "02_SUSPICIOUS"}:
                counter.tp += 1
            else:
                counter.fn += 1
        else:  # gt == "benign"
            if label_dir in {"03_SECURITY_TOOL", "04_BENIGN"}:
                counter.tn += 1
            else:
                counter.fp += 1


def compute_arch_metrics(root: Path) -> dict[str, ArchCounters]:
    results: dict[str, ArchCounters] = {}
    malware_index = build_malware_arch_index(root)

    malware_bucket = root / "malware_report"
    benign_bucket = root / "benign_report"

    for report_file in iter_report_files(malware_bucket):
        rel = report_file.relative_to(malware_bucket)
        family = rel.parts[0] if rel.parts else "unknown"
        target, status = parse_report(report_file)
        if not target:
            continue
        arch = infer_malware_arch(root, family, target, malware_index)
        unified_arch = get_unified_arch(arch)
        
        label_dir = next((p for p in rel.parts if p in LABEL_DIRS), None)
        
        results.setdefault(unified_arch, ArchCounters())
        update_counters(results[unified_arch], "malicious", label_dir, status)

    for report_file in iter_report_files(benign_bucket):
        rel = report_file.relative_to(benign_bucket)
        arch = rel.parts[0] if rel.parts else "unknown"
        # Benign arch is usually the top folder
        
        unified_arch = get_unified_arch(arch)
        
        target, status = parse_report(report_file)
        if not target:
            continue
        label_dir = next((p for p in rel.parts if p in LABEL_DIRS), None)
        
        results.setdefault(unified_arch, ArchCounters())
        update_counters(results[unified_arch], "benign", label_dir, status)

    return results


def print_table(results: dict[str, ArchCounters]) -> None:
    header = (
        f"{'arch':<15} | {'total':<6} | {'mal/ben':<9} | {'acc':<6} | {'err':<6} | {'FPR':<6} | {'FNR':<6}"
    )
    print(header)
    print("-" * len(header))

    for arch in sorted(results.keys()):
        c = results[arch]
        print(
            f"{arch:<15} | {c.total:<6d} | {c.malicious_total}/{c.benign_total:<5} |"
            f" {c.accuracy():.3f}  | {c.error_rate():.3f}  | {c.fpr():.3f}  | {c.fnr():.3f}"
        )


def write_csv(path: Path, results: dict[str, ArchCounters]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "arch",
                "total",
                "malicious_total",
                "benign_total",
                "accuracy",
                "error_rate",
                "fpr",
                "fnr",
                "tp",
                "tn",
                "fp",
                "fn",
                "crash",
                "failed_deps",
                "arg_error",
            ]
        )
        for arch in sorted(results.keys()):
            c = results[arch]
            writer.writerow(
                [
                    arch,
                    c.total,
                    c.malicious_total,
                    c.benign_total,
                    f"{c.accuracy():.6f}",
                    f"{c.error_rate():.6f}",
                    f"{c.fpr():.6f}",
                    f"{c.fnr():.6f}",
                    c.tp,
                    c.tn,
                    c.fp,
                    c.fn,
                    c.crash,
                    c.failed_deps,
                    c.arg_error,
                ]
            )
    print(f"Saved arch metrics -> {path}")


def print_condition_summary(results: dict[str, ArchCounters]) -> None:
    # Aggregate all
    agg = ArchCounters()
    for c in results.values():
        agg.malicious_total += c.malicious_total
        agg.benign_total += c.benign_total
        agg.tp += c.tp
        agg.tn += c.tn
        agg.fp += c.fp
        agg.fn += c.fn
        agg.crash += c.crash
        agg.failed_deps += c.failed_deps
        agg.arg_error += c.arg_error

    print("\nGlobal Summary:")
    print("-" * 30)
    print(f"Total Samples: {agg.total}")
    print(f"Malicious: {agg.malicious_total}")
    print(f"Benign:    {agg.benign_total}")
    print(f"Overall Accuracy:   {agg.accuracy():.4f}")
    print(f"Overall Error Rate: {agg.error_rate():.4f} (Crash/Dep)")
    print(f"Overall FPR:        {agg.fpr():.4f}")
    print(f"Overall FNR:        {agg.fnr():.4f}")



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute per-architecture accuracy/crash/dependency metrics"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Path to ELF_samples root (default: this script's directory)",
    )
    parser.add_argument(
        "--csv-out",
        type=Path,
        default=None,
        help="Optional path to save metrics as CSV",
    )
    args = parser.parse_args()

    if not args.root.is_dir():
        raise SystemExit(f"Root path not found: {args.root}")

    results = compute_arch_metrics(args.root)
    print_table(results)
    print_condition_summary(results)

    if args.csv_out:
        write_csv(args.csv_out, results)


if __name__ == "__main__":
    main()
