import os
import hashlib
from pathlib import Path

def get_sha256(file_path):
    """计算文件的 SHA256 哈希值"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # 分块读取，防止大文件撑爆内存
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def rename_files_in_dir(directory):
    target_dir = Path(directory)
    
    if not target_dir.exists():
        print(f"错误: 目录 '{directory}' 不存在")
        return

    print(f"正在处理目录: {directory} ...")
    
    for file_path in target_dir.iterdir():
        # 跳过目录，只处理文件
        if file_path.is_file():
            try:
                # 1. 计算哈希
                file_hash = get_sha256(file_path)
                
                # 2. 获取原扩展名 (例如 .jpg, .elf)
                file_ext = file_path.suffix
                
                # 3. 构建新文件名
                new_name = f"{file_hash}{file_ext}"
                new_path = target_dir / new_name
                
                # 4. 如果文件名已经是哈希值，跳过
                if new_path == file_path:
                    continue
                
                # 5. 处理重名冲突 (如果两个文件内容完全一样，哈希也会一样)
                if new_path.exists():
                    print(f"[跳过] 重复内容: {file_path.name} -> {new_name} (目标已存在)")
                    # 可选：这里可以选择删除旧文件，实现去重
                    # os.remove(file_path) 
                    continue
                
                # 6. 重命名
                file_path.rename(new_path)
                print(f"[成功] {file_path.name} -> {new_name}")
                
            except Exception as e:
                print(f"[错误] 无法处理 {file_path.name}: {e}")

if __name__ == "__main__":
    # 修改这里的路径为你想要处理的文件夹
    target_folder = "./benign-x86" 
    rename_files_in_dir(target_folder)