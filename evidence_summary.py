from __future__ import annotations

from pathlib import Path
import re
import json
import argparse
from typing import Dict, List, Tuple
from collections import defaultdict, Counter
import pandas as pd

ROOT = Path("/home/zzh/Compass-Proj1/MirrorShield/ELF_samples")
MALWARE_FAMILIES = ["CoinMiner", "Gafgyt", "Hailbot", "Kaiji", "Mirai", "Mozi", "Ransomware", "Tsunami", "XorDDoS","DockerExploit"]

# 定义 syscall 到 log event 的映射表
SYSCALL_MAPPING = {
    # 进程创建
    "fork": ["TRACK_FORK", "CLONE", "SYS_FORK", "FORK"],
    "vfork": ["TRACK_FORK", "CLONE", "SYS_VFORK", "VFORK"],
    "clone": ["CLONE", "TRACK_FORK", "SYS_CLONE", "CLONE3"],
    "clone3": ["CLONE3", "CLONE", "TRACK_FORK"],
    "track_fork": ["TRACK_FORK", "CLONE", "SYS_CLONE", "SYS_FORK", "CLONE3"],
    "thread": ["CLONE"],
    "pthread": ["CLONE"],

    # 进程执行
    "exec": ["EXEC", "EXECVE"],
    "execve": ["EXEC", "EXECVE"],
    "system": ["EXEC"],

    # 网络连接
    "socket": ["SOCKET"],
    "connect": ["CONNECT"],
    "bind": ["SOCKET"],
    "listen": ["SOCKET"],
    "accept": ["SOCKET"],
    "send": ["SENDTO", "WRITE"],
    "sendto": ["SENDTO"],
    "recv": ["RECVFROM", "READ"],
    "recvfrom": ["RECVFROM"],

    # 文件操作
    "open": ["ACCESS", "OPEN"],
    "access": ["ACCESS"],
    "read": ["READ"],
    "write": ["WRITE"],

    # 内存与信号
    "mmap": ["MMAP_SUM"],
    "mprotect": ["MPROTECT"],
    "exit": ["WAIT4_EXITED"],
    "kill": ["SIGNAL_GENERATE"],
    "signal": ["SIGNAL_GENERATE"],
}

KEYWORD_PATTERN = re.compile(r"[A-Z_]{3,}|/[^\s]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def build_raw_index(raw_dir: Path) -> Dict[str, List[Path]]:
    index: Dict[str, List[Path]] = {}
    if not raw_dir.is_dir():
        print(f"[WARN] raw 目录不存在: {raw_dir}")
        return index
    for p in raw_dir.glob("*.jsonl"):
        m = re.match(r"([0-9a-f]{64})\.elf_", p.name)
        if not m:
            continue
        sha = m.group(1)
        index.setdefault(sha, []).append(p)
    return index


def list_report_files(report_root: Path) -> List[Path]:
    if not report_root.is_dir():
        print(f"[WARN] report 目录不存在: {report_root}")
        return []
    files: List[Path] = []
    for bucket in sorted(p for p in report_root.iterdir() if p.is_dir()):
        for rpt in bucket.glob("*_deepseek_report.txt"):
            files.append(rpt)
    return files


def parse_report_text(path: Path) -> Tuple[str, str]:
    text = path.read_text(errors="ignore")
    m = re.search(r"Target:\s*`([0-9a-fA-F]{64})(?:\.elf)?`", text)
    sha = m.group(1).lower() if m else ""
    if not sha:
        m2 = re.search(r"([0-9a-fA-F]{64})", text)
        sha = m2.group(1).lower() if m2 else ""
    return sha, text


def extract_key_evidence(text: str) -> List[str]:
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if "Key Evidence" in ln:
            start = i + 1
            break
    if start is None:
        return []

    evidences: List[str] = []
    for ln in lines[start:]:
        if ln.startswith("### ") or ln.startswith("## "):
            break
        ln = ln.strip()
        if ln.startswith("-"):
            ln = ln.lstrip("- ")
            if not ln:
                continue
            upper_ln = ln.upper()
            if "TRACK_QEMU" in upper_ln:
                continue
            if "EXECUTION FROM /TMP" in upper_ln:
                continue
            evidences.append(ln)
    return evidences


def extract_keywords_enhanced(evidence: str) -> List[str]:
    kws = KEYWORD_PATTERN.findall(evidence)
    ips = IPV4_RE.findall(evidence)
    kws.extend(ips)

    ev_lower = evidence.lower()
    if "clone/track_fork" in ev_lower or "track_fork" in ev_lower:
        kws.extend(["clone", "fork", "vfork", "clone3", "track_fork"])

    if not kws:
        kws = re.findall(r"[a-zA-Z]{4,}", evidence)

    norm = []
    for k in kws:
        if k.startswith("/"):
            norm.append(k)
        else:
            norm.append(k.lower())
    return list(dict.fromkeys(norm))


def extract_encoded_ips_from_line(line: str) -> List[str]:
    ips = []
    hex_patterns = [
        r"0x([0-9a-fA-F]{8})",
        r"\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})",
        r"([0-9a-fA-F]{8})",
    ]

    for pattern in hex_patterns:
        matches = re.findall(pattern, line)
        for match in matches:
            if isinstance(match, tuple):
                hex_str = "".join(match)
            else:
                hex_str = match
            try:
                val = int(hex_str, 16)
                ip_be = _int_to_ipv4(val)
                if ip_be:
                    ips.append(f"{ip_be} (BE:0x{hex_str})")
            except Exception:
                pass
            try:
                val = int(hex_str, 16)
                ip_le = _int_to_ipv4_le(val)
                if ip_le:
                    ips.append(f"{ip_le} (LE:0x{hex_str})")
            except Exception:
                pass
    return ips


def _int_to_ipv4(val: int) -> str | None:
    if val < 0 or val > 0xFFFFFFFF:
        return None
    b1 = (val >> 24) & 0xFF
    b2 = (val >> 16) & 0xFF
    b3 = (val >> 8) & 0xFF
    b4 = val & 0xFF
    ip = f"{b1}.{b2}.{b3}.{b4}"
    if ip in ["0.0.0.0", "255.255.255.255"] or ip.startswith("0."):
        return None
    return ip


def _int_to_ipv4_le(val: int) -> str | None:
    if val < 0 or val > 0xFFFFFFFF:
        return None
    b1 = val & 0xFF
    b2 = (val >> 8) & 0xFF
    b3 = (val >> 16) & 0xFF
    b4 = (val >> 24) & 0xFF
    ip = f"{b1}.{b2}.{b3}.{b4}"
    if ip in ["0.0.0.0", "255.255.255.255"] or ip.startswith("0."):
        return None
    return ip


def search_jsonl_smart(jsonl_path: Path, keywords: List[str], limit: int = 5) -> List[str]:
    matches: List[str] = []
    if not jsonl_path.is_file() or not keywords:
        return matches

    expanded_keywords = set(keywords)
    for k in keywords:
        k_lower = k.lower()
        if k_lower in SYSCALL_MAPPING:
            expanded_keywords.update(SYSCALL_MAPPING[k_lower])

    search_keywords = list(expanded_keywords)

    ip_keywords = [k for k in search_keywords if re.match(r"^\d+\.\d+\.\d+\.\d+$", k)]
    text_keywords = [k for k in search_keywords if k not in ip_keywords]

    check_list = []
    for k in text_keywords:
        if k.isupper() and "_" in k:
            check_list.append((k, True))
        elif k.startswith("/"):
            check_list.append((k, True))
        else:
            check_list.append((k.lower(), False))

    try:
        with jsonl_path.open() as f:
            for line in f:
                line_matched = False
                low_line = line.lower()

                for k, case_sensitive in check_list:
                    if case_sensitive:
                        if k in line:
                            line_matched = True
                            break
                    else:
                        if k in low_line:
                            line_matched = True
                            break

                if not line_matched and ip_keywords:
                    if any(ip in line for ip in ip_keywords):
                        line_matched = True
                    else:
                        decoded_ips = extract_encoded_ips_from_line(line)
                        if decoded_ips:
                            clean_decoded = [d.split(" ")[0] for d in decoded_ips]
                            if any(ip in clean_decoded for ip in ip_keywords):
                                line_matched = True

                if line_matched:
                    matches.append(line.strip())
                    if len(matches) >= limit:
                        break
    except Exception as exc:
        print(f"[WARN] 读取失败 {jsonl_path}: {exc}")
    return matches


def find_raw_files_for_sha(sha: str, index: Dict[str, List[Path]]) -> List[Path]:
    return index.get(sha, [])


def analyze_single_report_detailed(report_path: Path, raw_index: Dict[str, List[Path]]):
    sha, text = parse_report_text(report_path)
    if not sha:
        return None

    evidences = extract_key_evidence(text)
    if not evidences:
        return None

    raw_files = find_raw_files_for_sha(sha, raw_index)
    if not raw_files:
        return {
            "sha": sha,
            "report": report_path.name,
            "total_evidence": len(evidences),
            "supported_evidence": 0,
            "unsupported_evidence": len(evidences),
            "support_rate": 0.0,
            "has_raw": False,
        }

    supported_count = 0
    unsupported_evidences: List[str] = []
    for ev in evidences:
        kws = extract_keywords_enhanced(ev)
        lines = search_jsonl_smart(raw_files[0], kws, limit=3)
        if len(lines) > 0:
            supported_count += 1
        else:
            unsupported_evidences.append(ev)

    unsupported_count = len(evidences) - supported_count
    support_rate = supported_count / len(evidences) if len(evidences) > 0 else 0.0

    return {
        "sha": sha,
        "report": report_path.name,
        "total_evidence": len(evidences),
        "supported_evidence": supported_count,
        "unsupported_evidence": unsupported_count,
        "support_rate": support_rate,
        "has_raw": True,
        "unsupported_evidences": unsupported_evidences,
    }


def analyze_family(family_name: str):
    family_raw_dir = ROOT / "malware_report" / family_name / "raw"
    family_report_root = ROOT / "malware_report" / family_name / "analysis_reports_comparison"

    raw_idx = build_raw_index(family_raw_dir)
    report_files = list_report_files(family_report_root)
    if not report_files:
        print(f"[WARN] 家族 {family_name} 没有报告文件")
        return None

    all_results = []
    for rpt in report_files:
        result = analyze_single_report_detailed(rpt, raw_idx)
        if result:
            all_results.append(result)

    return {
        "family": family_name,
        "total_reports": len(report_files),
        "all_results": all_results,
    }


def resolve_families_to_run(run_family: str) -> List[str]:
    if not run_family:
        return MALWARE_FAMILIES
    if run_family.lower() == "all":
        return MALWARE_FAMILIES
    if run_family not in MALWARE_FAMILIES:
        print(f"[WARN] 未知家族: {run_family}，将使用 all")
        return MALWARE_FAMILIES
    return [run_family]


def summarize_by_family(all_family_results: List[dict]) -> pd.DataFrame:
    rows = []
    for fam in all_family_results:
        results = fam["all_results"]
        if not results:
            continue
        df = pd.DataFrame(results)
        rows.append({
            "family": fam["family"],
            "report_count": len(df),
            "avg_total_evidence": df["total_evidence"].mean(),
            "avg_supported": df["supported_evidence"].mean(),
            "avg_unsupported": df["unsupported_evidence"].mean(),
            "avg_support_rate": df["support_rate"].mean(),
        })
    return pd.DataFrame(rows)


def summarize_overall(all_family_results: List[dict]) -> pd.DataFrame:
    all_rows = []
    for fam in all_family_results:
        all_rows.extend(fam["all_results"])
    if not all_rows:
        return pd.DataFrame()
    df = pd.DataFrame(all_rows)
    return pd.DataFrame([
        {
            "family": "ALL",
            "report_count": len(df),
            "avg_total_evidence": df["total_evidence"].mean(),
            "avg_supported": df["supported_evidence"].mean(),
            "avg_unsupported": df["unsupported_evidence"].mean(),
            "avg_support_rate": df["support_rate"].mean(),
        }
    ])


def summarize_topk_unsupported(all_family_results: List[dict], top_k: int) -> pd.DataFrame:
    counter: Counter[str] = Counter()
    for fam in all_family_results:
        for res in fam["all_results"]:
            for ev in res.get("unsupported_evidences", []):
                counter[ev] += 1
    if not counter:
        return pd.DataFrame()
    top_items = counter.most_common(top_k)
    return pd.DataFrame(top_items, columns=["evidence", "count"])


def main():
    parser = argparse.ArgumentParser(description="Evidence summary by family and overall")
    parser.add_argument("--family", default="all", help="family name or 'all'")
    parser.add_argument("--out", default=str(ROOT / "analysis_outputs" / "family_avg_summary.csv"))
    parser.add_argument("--top-k", type=int, default=20, help="top-k unsupported evidence to show")
    parser.add_argument("--top-k-out", default=str(ROOT / "analysis_outputs" / "topk_unsupported_evidence.csv"))
    args = parser.parse_args()

    families_to_run = resolve_families_to_run(args.family)
    print("本次运行家族:", families_to_run)

    all_family_results = []
    for family in families_to_run:
        result = analyze_family(family)
        if result:
            all_family_results.append(result)

    family_df = summarize_by_family(all_family_results)
    overall_df = summarize_overall(all_family_results)

    print("\n各家族平均值:")
    if not family_df.empty:
        print(family_df.to_string(index=False, formatters={"avg_support_rate": "{:.1%}".format}))
    else:
        print("[WARN] 无家族数据")

    print("\n总体平均值:")
    if not overall_df.empty:
        print(overall_df.to_string(index=False, formatters={"avg_support_rate": "{:.1%}".format}))
    else:
        print("[WARN] 无总体数据")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    merged = pd.concat([family_df, overall_df], ignore_index=True)
    merged.to_csv(out_path, index=False)
    print(f"\n已导出: {out_path}")

    topk_df = summarize_topk_unsupported(all_family_results, args.top_k)
    print(f"\nTop-{args.top_k} 未匹配 Evidence:")
    if not topk_df.empty:
        print(topk_df.to_string(index=False))
        topk_out_path = Path(args.top_k_out)
        topk_out_path.parent.mkdir(parents=True, exist_ok=True)
        topk_df.to_csv(topk_out_path, index=False)
        print(f"已导出: {topk_out_path}")
    else:
        print("[WARN] 无未匹配 Evidence 数据")


if __name__ == "__main__":
    main()
