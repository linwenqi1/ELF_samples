#!/usr/bin/env python3
"""
Generate quick visual summaries for ELF_samples VirusTotal metadata.

Outputs:
- Pie chart (2 subplots): architecture distribution, top threat labels/categories/names combined.
- Prints earliest/latest first_seen_itw (time span).

Usage:
    python summary_charts.py \
        --json all_samples.json \
        --out vt_pies.png \
        --top 8

Defaults assume the script is run from this directory and the JSON file
is named `all_samples.json`.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import matplotlib.pyplot as plt

# Global style: academic-ish, Times New Roman, bold everywhere
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif", "serif"],
    "font.size": 12,
    "font.weight": "bold",
})


def load_json(path: Path) -> Dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def collect_arch_distribution(data: Dict[str, Any]) -> Counter:
    c: Counter[str] = Counter()
    for entry in data.values():
        arch = entry.get("elf_header", {}).get("machine")
        if arch:
            c[arch] += 1
    return c


def collect_label_frequencies(data: Dict[str, Any]) -> Counter:
    """Count occurrences across suggested_threat_label, threat_category, threat_name."""
    c: Counter[str] = Counter()
    for entry in data.values():
        lbl = entry.get("suggested_threat_label")
        if lbl:
            c[lbl] += 1

        for cat in entry.get("threat_category") or []:
            if cat:
                c[cat] += 1

        for name in entry.get("threat_name") or []:
            if name:
                c[name] += 1
    return c


def top_with_other(counter: Counter, top_n: int) -> Tuple[list[str], list[int]]:
    most = counter.most_common(top_n)
    labels = [lbl for lbl, _ in most]
    sizes = [cnt for _, cnt in most]
    other = sum(counter.values()) - sum(sizes)
    if other > 0:
        labels.append("Other")
        sizes.append(other)
    return labels, sizes


def prettify_label(label: str, max_len: int = 20) -> str:
    """Shorten and clean labels for nicer pie rendering."""
    # Specific tidy-up rules
    replacements = {
        "trojan.kaiji/chaos": "Kaiji (chaos)",
        "advancedmireco devices x86-64": "adv.mireco x86-64",
        "advanced micro devices x86-64": "AMD x86-64",
        "Advanced Micro Devices X86-64": "AMD x86-64",
    }
    label = replacements.get(label, label)

    if len(label) > max_len:
        return label[: max_len - 1] + "…"
    return label


def parse_datetime(entry: Dict[str, Any]) -> Optional[datetime]:
    fs = entry.get("first_seen_itw") or {}
    ts = fs.get("timestamp")
    if ts is not None:
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass

    t = fs.get("utc_time")
    if t:
        # Try multiple ISO-like formats
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(t, fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None


def collect_time_span(data: Dict[str, Any]) -> Optional[Tuple[datetime, datetime]]:
    times: list[datetime] = []
    for entry in data.values():
        dt = parse_datetime(entry)
        if dt:
            times.append(dt)
    if not times:
        return None
    return min(times), max(times)


def plot_pies(arch_counter: Counter, label_counter: Counter, top_n: int, out_path: Path) -> None:
    labels_arch_raw, sizes_arch = top_with_other(arch_counter, top_n)
    labels_label_raw, sizes_label = top_with_other(label_counter, top_n)

    labels_arch = [prettify_label(l, max_len=22) for l in labels_arch_raw]
    labels_label = [prettify_label(l, max_len=22) for l in labels_label_raw]

    fig, axes = plt.subplots(1, 2, figsize=(12, 6))

    textprops = {"fontsize": 11}

    # Architecture pie
    wedges, texts, autotexts = axes[0].pie(
        sizes_arch,
        labels=labels_arch,
        autopct="%1.1f%%",
        startangle=140,
        textprops=textprops,
    )
    axes[0].set_title("Architecture Distribution", fontsize=13)

    # Threat labels/categories/names pie
    wedges2, texts2, autotexts2 = axes[1].pie(
        sizes_label,
        labels=labels_label,
        autopct="%1.1f%%",
        startangle=140,
        textprops=textprops,
    )
    axes[1].set_title(f"Top {top_n} Threat Tags (label/category/name)", fontsize=13)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"Saved pie charts -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize ELF_samples VT metadata with pies and time span")
    parser.add_argument("--json", type=Path, default=Path("all_samples.json"), help="Path to all_samples.json")
    parser.add_argument("--out", type=Path, default=Path("vt_pies.png"), help="Output PNG for pie charts")
    parser.add_argument("--top", type=int, default=8, help="Top N labels to show before grouping into Other")
    args = parser.parse_args()

    data = load_json(args.json)
    print(f"Loaded {len(data)} entries from {args.json}")

    arch_counter = collect_arch_distribution(data)
    label_counter = collect_label_frequencies(data)

    if not arch_counter:
        print("[WARN] No architecture data found.")
    if not label_counter:
        print("[WARN] No threat label/category/name data found.")

    plot_pies(arch_counter, label_counter, args.top, args.out)

    span = collect_time_span(data)
    if span:
        earliest, latest = span
        print("Time span (first_seen_itw):")
        print(f"  Earliest: {earliest.isoformat()}")
        print(f"  Latest:   {latest.isoformat()}")
        delta = latest - earliest
        print(f"  Span:     {delta.days} days ({delta})")
    else:
        print("[WARN] Could not compute time span (no valid timestamps).")

    # Print a quick top list for reference
    print("\nTop threat tags (combined):")
    for lbl, cnt in label_counter.most_common(10):
        print(f"  {prettify_label(lbl, max_len=30):<30} {cnt}")

    print("\nArchitecture distribution:")
    for arch, cnt in arch_counter.most_common():
        print(f"  {prettify_label(arch, max_len=40):<40} {cnt}")


if __name__ == "__main__":
    main()
