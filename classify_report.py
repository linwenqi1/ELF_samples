#!/usr/bin/env python3
"""
DeepSeek Report Organizer (自动分类归档)

功能：
1. 扫描 DeepSeek 分析报告 (.txt)
2. 提取 'Risk Score' 并分类
3. (可选) 自动创建文件夹并将报告移动到对应的分类目录中
"""

import os
import sys
import re
import shutil  # 用于移动文件
import argparse
from pathlib import Path
from typing import Dict, Tuple

# 定义颜色代码
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'

# 定义分类映射和文件夹名称 (带数字前缀以便排序)
CATEGORY_MAP = {
    "MALICIOUS": "01_MALICIOUS",
    "SUSPICIOUS": "02_SUSPICIOUS",
    "SECURITY_TOOL": "03_SECURITY_TOOL",
    "BENIGN": "04_BENIGN",
    "PARSE_ERROR": "00_UNCATEGORIZED"
}

def parse_report_file(path: Path) -> Dict:
    """读取 .txt 报告文件，提取分数"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        score_match = re.search(r"- \*\*Risk Score:\*\* (\d+)/100", content)
        score = int(score_match.group(1)) if score_match else -1
        
        target_match = re.search(r"\*\*Target:\*\* `(.+?)`", content)
        target = target_match.group(1) if target_match else path.stem

        verdict_match = re.search(r"- \*\*Verdict:\*\* \*\*(.+?)\*\*", content)
        verdict = verdict_match.group(1) if verdict_match else "Unknown"

        return {
            "file": path.name,
            "target": target,
            "score": score,
            "verdict": verdict,
            "path": path  # 保留原始 Path 对象以便移动
        }
    except Exception as e:
        return {"file": path.name, "score": -1, "path": path, "error": str(e)}

def categorize_score(score: int) -> Tuple[str, str]:
    """根据分数返回分类 Key 和颜色"""
    if score == -1: return "PARSE_ERROR", Colors.RESET
    if 80 <= score <= 100: return "MALICIOUS", Colors.RED
    if 50 <= score <= 79: return "SUSPICIOUS", Colors.YELLOW
    if 10 <= score <= 49: return "SECURITY_TOOL", Colors.BLUE
    if 0 <= score <= 9: return "BENIGN", Colors.GREEN
    return "PARSE_ERROR", Colors.RESET

def main():
    parser = argparse.ArgumentParser(description='Organize DeepSeek reports into folders.')
    parser.add_argument('-d', '--dir', default='deepseek_analysis', help='Directory to scan')
    parser.add_argument('-m', '--move', action='store_true', help='🔥 EXECUTE MOVE: Automatically create folders and move files')
    parser.add_argument('-o', '--output', default=None, help='Save JSON summary')
    args = parser.parse_args()

    scan_dir = Path(args.dir)
    if not scan_dir.exists() or not scan_dir.is_dir():
        print(f"{Colors.RED}[ERROR] Directory not found: {scan_dir}{Colors.RESET}")
        sys.exit(1)

    print(f"Scanning directory: {scan_dir} ...")
    if args.move:
        print(f"{Colors.RED}[WARNING] Move mode enabled. Files will be reorganized!{Colors.RESET}")

    # 统计数据
    stats = {key: 0 for key in CATEGORY_MAP.keys()}
    moved_count = 0
    results_list = []

    # 扫描文件 (排除已经是目录的)
    files = [f for f in scan_dir.glob('*_deepseek_report.txt') if f.is_file()]
    
    if not files:
        print("No report files found.")
        sys.exit(0)

    print(f"Found {len(files)} reports.\n")

    for p in sorted(files):
        data = parse_report_file(p)
        cat_key, color = categorize_score(data['score'])
        
        # 更新统计
        stats[cat_key] += 1
        
        # 打印信息
        icon = "📂" if args.move else "📄"
        print(f"{color}[{cat_key}] {data['target']:<20} (Score: {data['score']}) -> {icon} {CATEGORY_MAP[cat_key]}{Colors.RESET}")

        # --- 移动逻辑 ---
        final_path = str(p)
        if args.move:
            try:
                # 1. 确定目标文件夹
                target_folder_name = CATEGORY_MAP[cat_key]
                target_dir = scan_dir / target_folder_name
                
                # 2. 如果不存在则创建
                if not target_dir.exists():
                    target_dir.mkdir(mode=0o755)
                    print(f"{Colors.CYAN}   └── Created directory: {target_folder_name}{Colors.RESET}")

                # 3. 移动文件
                destination = target_dir / p.name
                shutil.move(str(p), str(destination))
                
                final_path = str(destination)
                moved_count += 1
                
            except Exception as e:
                print(f"{Colors.RED}   └── Failed to move: {e}{Colors.RESET}")

        # 记录结果供 JSON 输出
        results_list.append({
            "target": data.get('target'),
            "score": data.get('score'),
            "category": cat_key,
            "old_path": str(p),
            "new_path": final_path
        })

    # --- 总结 ---
    print("\n" + "="*50)
    print("📊 Summary:")
    for key, count in stats.items():
        if count > 0:
            _, color = categorize_score(80 if key == "MALICIOUS" else 50 if key == "SUSPICIOUS" else 10 if key == "SECURITY_TOOL" else 0)
            if key == "PARSE_ERROR": color = Colors.RESET
            print(f"  {color}{key:<15}: {count}{Colors.RESET}")
    
    if args.move:
        print(f"\n✅ Automatically organized {moved_count} files into subdirectories.")
    else:
        print(f"\nℹ️  Dry Run Mode. Use {Colors.BOLD}-m{Colors.RESET} or {Colors.BOLD}--move{Colors.RESET} to actually move files.")

    # 保存 JSON
    if args.output:
        import json
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump({"timestamp": "now", "stats": stats, "details": results_list}, f, indent=2)
        print(f"JSON summary saved to: {args.output}")

if __name__ == '__main__':
    main()