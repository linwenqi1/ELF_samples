#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import shutil
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Randomly select N ELF files per folder, split into two parts, "
            "and delete unselected files."
        )
    )
    parser.add_argument(
        "--base",
        type=Path,
        default=Path(__file__).resolve().parent / "benign",
        help="Base benign directory (default: ./benign)",
    )
    parser.add_argument(
        "--folders",
        nargs="+",
        default=["armv7l-eabihf", "armv8-aarch64", "x86-i686"],
        help="Folder names under base to process",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=130,
        help="Number of files to select per folder",
    )
    parser.add_argument(
        "--subdir",
        default="sampled_130_split",
        help="Name of the new subfolder to store selected splits",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without moving/deleting files",
    )
    return parser.parse_args()


def split_indices(total: int) -> int:
    return total // 2


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)

    base = args.base
    if not base.exists() or not base.is_dir():
        raise SystemExit(f"Base directory not found: {base}")

    for folder_name in args.folders:
        folder = base / folder_name
        if not folder.exists() or not folder.is_dir():
            raise SystemExit(f"Folder not found: {folder}")

        files = sorted([p for p in folder.iterdir() if p.is_file()])
        if len(files) < args.sample_size:
            raise SystemExit(
                f"Not enough files in {folder} (found {len(files)}, "
                f"need {args.sample_size})."
            )

        selected = rng.sample(files, args.sample_size)
        selected_set = set(selected)

        split_at = split_indices(args.sample_size)
        part1 = selected[:split_at]
        part2 = selected[split_at:]

        target_root = folder / args.subdir
        part1_dir = target_root / "part1"
        part2_dir = target_root / "part2"

        if args.dry_run:
            print(f"[DRY RUN] {folder} -> {target_root}")
            print(f"  select: {len(selected)} | delete: {len(files) - len(selected)}")
        else:
            part1_dir.mkdir(parents=True, exist_ok=True)
            part2_dir.mkdir(parents=True, exist_ok=True)

        for idx, src in enumerate(selected):
            dest_dir = part1_dir if idx < split_at else part2_dir
            dest = dest_dir / src.name
            if args.dry_run:
                print(f"  move: {src.name} -> {dest}")
            else:
                shutil.move(str(src), str(dest))

        for src in files:
            if src in selected_set:
                continue
            if args.dry_run:
                print(f"  delete: {src.name}")
            else:
                src.unlink(missing_ok=True)

        print(
            f"Done: {folder_name} | kept {len(selected)} in {target_root} "
            f"(part1={len(part1)}, part2={len(part2)})"
        )


if __name__ == "__main__":
    main()
