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
    total: int = 0
    parsed_verdict: int = 0
    correct: int = 0
    crash: int = 0
    failed_deps: int = 0
    arg_error: int = 0
    success_total: int = 0
    success_correct: int = 0
    crash_or_failed_total: int = 0
    crash_or_failed_correct: int = 0

    def accuracy(self) -> float:
        return self.correct / self.parsed_verdict if self.parsed_verdict else 0.0

    def crash_rate(self) -> float:
        return self.crash / self.total if self.total else 0.0

    def failed_deps_rate(self) -> float:
        return self.failed_deps / self.total if self.total else 0.0

    def arg_error_rate(self) -> float:
        return self.arg_error / self.total if self.total else 0.0

    def success_accuracy(self) -> float:
        return self.success_correct / self.success_total if self.success_total else 0.0

    def crash_failed_accuracy(self) -> float:
        return (
            self.crash_or_failed_correct / self.crash_or_failed_total
            if self.crash_or_failed_total
            else 0.0
        )


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
    counter.total += 1

    if label_dir:
        counter.parsed_verdict += 1
        is_correct = False
        if gt == "malicious" and label_dir in {"01_MALICIOUS", "02_SUSPICIOUS"}:
            is_correct = True
        elif gt == "benign" and label_dir in {"03_SECURITY_TOOL", "04_BENIGN"}:
            is_correct = True
        if is_correct:
            counter.correct += 1

    if status:
        status_upper = status.upper()
        is_success = "SUCCESS" in status_upper
        is_crash = "CRASH" in status_upper
        is_failed_dep = "FAILED_DEPENDENC" in status_upper
        is_arg_error = "ARGUMENT" in status_upper

        if is_arg_error:
            is_success = True

        if is_crash:
            counter.crash += 1
        if is_failed_dep:
            counter.failed_deps += 1
        if is_arg_error:
            counter.arg_error += 1

        if is_success:
            counter.success_total += 1
            if label_dir and is_correct:
                counter.success_correct += 1

        if is_crash or is_failed_dep:
            counter.crash_or_failed_total += 1
            if label_dir and is_correct:
                counter.crash_or_failed_correct += 1


def compute_arch_metrics(root: Path) -> dict[tuple[str, str], ArchCounters]:
    results: dict[tuple[str, str], ArchCounters] = {}
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
        label_dir = next((p for p in rel.parts if p in LABEL_DIRS), None)
        key = (arch, "malicious")
        results.setdefault(key, ArchCounters())
        update_counters(results[key], "malicious", label_dir, status)

    for report_file in iter_report_files(benign_bucket):
        rel = report_file.relative_to(benign_bucket)
        arch = rel.parts[0] if rel.parts else "unknown"
        target, status = parse_report(report_file)
        if not target:
            continue
        label_dir = next((p for p in rel.parts if p in LABEL_DIRS), None)
        key = (arch, "benign")
        results.setdefault(key, ArchCounters())
        update_counters(results[key], "benign", label_dir, status)

    return results


def print_table(results: dict[tuple[str, str], ArchCounters]) -> None:
    header = (
        f"{'arch':<10} | {'class':<9} | total | parsed | correct | acc | crash | failed_dep | arg_err"
    )
    print(header)
    print("-" * len(header))

    for (arch, cls) in sorted(results.keys()):
        c = results[(arch, cls)]
        print(
            f"{arch:<10} | {cls:<9} | {c.total:5d} | {c.parsed_verdict:6d} |"
            f" {c.correct:7d} | {c.accuracy():.3f} | {c.crash_rate():.3f} |"
            f" {c.failed_deps_rate():.3f} | {c.arg_error_rate():.3f}"
        )


def write_csv(path: Path, results: dict[tuple[str, str], ArchCounters]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "arch",
                "class",
                "total",
                "parsed_verdict",
                "correct",
                "accuracy",
                "crash_rate",
                "failed_dependency_rate",
                "argument_error_rate",
                "success_accuracy",
                "crash_failed_accuracy",
            ]
        )
        for (arch, cls) in sorted(results.keys()):
            c = results[(arch, cls)]
            writer.writerow(
                [
                    arch,
                    cls,
                    c.total,
                    c.parsed_verdict,
                    c.correct,
                    f"{c.accuracy():.6f}",
                    f"{c.crash_rate():.6f}",
                    f"{c.failed_deps_rate():.6f}",
                    f"{c.arg_error_rate():.6f}",
                    f"{c.success_accuracy():.6f}",
                    f"{c.crash_failed_accuracy():.6f}",
                ]
            )
    print(f"Saved arch metrics -> {path}")


def print_condition_summary(results: dict[tuple[str, str], ArchCounters]) -> None:
    totals: dict[str, ArchCounters] = {"malicious": ArchCounters(), "benign": ArchCounters()}
    for (arch, cls), c in results.items():
        agg = totals[cls]
        agg.total += c.total
        agg.parsed_verdict += c.parsed_verdict
        agg.correct += c.correct
        agg.crash += c.crash
        agg.failed_deps += c.failed_deps
        agg.arg_error += c.arg_error
        agg.success_total += c.success_total
        agg.success_correct += c.success_correct
        agg.crash_or_failed_total += c.crash_or_failed_total
        agg.crash_or_failed_correct += c.crash_or_failed_correct

    print("\nConditional accuracy (by class):")
    print("-" * 70)
    for cls in ("malicious", "benign"):
        c = totals[cls]
        print(
            f"{cls:<9} | success acc {c.success_accuracy():.3f} "
            f"({c.success_correct}/{c.success_total}) | "
            f"crash/failed acc {c.crash_failed_accuracy():.3f} "
            f"({c.crash_or_failed_correct}/{c.crash_or_failed_total}) | "
            f"arg_err {c.arg_error}"
        )


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
