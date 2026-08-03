#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 备份管理
"""
import os
import sys
import json
import time
import shutil
from typing import Dict, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import PROJECT_ROOT
from engine.logger import logger


class BackupManager:
    """备份管理器"""

    def __init__(self):
        self.backup_dir = PROJECT_ROOT / 'backups'
        os.makedirs(self.backup_dir, exist_ok=True)

    def backup_file(self, filepath: str) -> Optional[str]:
        """备份文件"""
        if not os.path.exists(filepath):
            return None

        try:
            timestamp = int(time.time())
            fname = os.path.basename(filepath)
            backup_name = f"{timestamp}_{fname}.backup"
            backup_path = os.path.join(self.backup_dir, backup_name)
            shutil.copy2(filepath, backup_path)
            logger.info(f"文件已备份: {filepath} -> {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"备份文件失败: {e}")
            return None

    def restore_backup(self, backup_path: str, target_path: str) -> bool:
        """从备份还原"""
        if not os.path.exists(backup_path):
            return False

        try:
            shutil.copy2(backup_path, target_path)
            logger.info(f"文件已还原: {backup_path} -> {target_path}")
            return True
        except Exception as e:
            logger.error(f"还原备份失败: {e}")
            return False

    def clean_old_backups(self, max_age_days: int = 30):
        """清理过期备份"""
        now = time.time()
        cleaned = 0
        for f in os.listdir(self.backup_dir):
            fpath = os.path.join(self.backup_dir, f)
            if os.path.isfile(fpath):
                age = now - os.path.getmtime(fpath)
                if age > max_age_days * 86400:
                    try:
                        os.remove(fpath)
                        cleaned += 1
                    except Exception:
                        pass
        if cleaned > 0:
            logger.info(f"清理了 {cleaned} 个过期备份")

    def get_backups(self) -> list:
        """获取备份列表"""
        backups = []
        for f in os.listdir(self.backup_dir):
            fpath = os.path.join(self.backup_dir, f)
            if os.path.isfile(fpath) and f.endswith('.backup'):
                backups.append({
                    'name': f,
                    'size': os.path.getsize(fpath),
                    'time': os.path.getmtime(fpath),
                    'path': fpath,
                })
        return sorted(backups, key=lambda x: x['time'], reverse=True)


# ============================================================
# 全局备份管理器
# ============================================================
backup_manager = BackupManager()