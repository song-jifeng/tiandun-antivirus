#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 隔离管理
"""
import os
import sys
import json
import time
import shutil
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import PROJECT_ROOT, ThreatInfo, HashUtil
from engine.logger import logger
from engine.config import config


class QuarantineManager:
    """隔离区管理器"""

    def __init__(self):
        self.quarantine_dir = PROJECT_ROOT / 'quarantine'
        self.index_file = self.quarantine_dir / 'index.json'
        self._index: Dict[str, Dict] = {}
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self._load_index()

    def _load_index(self):
        """加载隔离索引"""
        try:
            if self.index_file.exists():
                with open(self.index_file, 'r', encoding='utf-8') as f:
                    self._index = json.load(f)
        except Exception as e:
            logger.error(f"加载隔离索引失败: {e}")
            self._index = {}

    def _save_index(self):
        """保存隔离索引"""
        try:
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(self._index, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存隔离索引失败: {e}")

    def quarantine(self, filepath: str, threat_info: Optional[ThreatInfo] = None) -> bool:
        """将文件移动到隔离区"""
        if not os.path.exists(filepath):
            logger.error(f"隔离文件不存在: {filepath}")
            return False

        try:
            # 生成唯一隔离文件名
            file_hash = HashUtil.md5_file(filepath)
            timestamp = int(time.time())
            ext = os.path.splitext(filepath)[1]
            quar_name = f"{timestamp}_{file_hash[:16]}{ext}"
            quar_path = os.path.join(self.quarantine_dir, quar_name)

            # 复制文件到隔离区
            shutil.copy2(filepath, quar_path)

            # 记录隔离信息
            info = {
                'id': quar_name,
                'original_path': os.path.abspath(filepath),
                'file_name': os.path.basename(filepath),
                'file_size': os.path.getsize(filepath),
                'md5': file_hash,
                'sha256': HashUtil.sha256_file(filepath),
                'quarantine_time': time.time(),
                'quarantine_path': quar_path,
                'threat_name': threat_info.threat_name if threat_info else '',
                'threat_type': threat_info.threat_type if threat_info else '',
                'threat_level': threat_info.threat_level if threat_info else 0,
                'scan_engine': threat_info.scan_engine if threat_info else '',
                'restored': False,
                'deleted': False,
            }

            self._index[quar_name] = info
            self._save_index()

            # 删除原文件
            try:
                os.remove(filepath)
            except Exception as e:
                logger.warning(f"删除原文件失败: {filepath} - {e}")

            logger.info(f"文件已隔离: {filepath} -> {quar_path}")
            return True

        except Exception as e:
            logger.error(f"隔离文件失败: {filepath} - {e}")
            return False

    def restore(self, quarantine_id: str, restore_path: Optional[str] = None) -> bool:
        """从隔离区还原文件"""
        if quarantine_id not in self._index:
            logger.error(f"隔离记录不存在: {quarantine_id}")
            return False

        try:
            info = self._index[quarantine_id]
            quar_path = info['quarantine_path']

            if not os.path.exists(quar_path):
                logger.error(f"隔离文件不存在: {quar_path}")
                return False

            # 还原到原路径或指定路径
            target = restore_path or info['original_path']
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(quar_path, target)

            # 更新记录
            info['restored'] = True
            info['restore_time'] = time.time()
            info['restore_path'] = target
            self._save_index()

            logger.info(f"文件已还原: {quar_path} -> {target}")
            return True

        except Exception as e:
            logger.error(f"还原文件失败: {e}")
            return False

    def delete(self, quarantine_id: str) -> bool:
        """从隔离区删除文件"""
        if quarantine_id not in self._index:
            return False

        try:
            info = self._index[quarantine_id]
            quar_path = info['quarantine_path']

            if os.path.exists(quar_path):
                os.remove(quar_path)

            info['deleted'] = True
            info['delete_time'] = time.time()
            self._save_index()

            logger.info(f"隔离文件已删除: {quar_path}")
            return True

        except Exception as e:
            logger.error(f"删除隔离文件失败: {e}")
            return False

    def clean_expired(self):
        """清理过期隔离文件"""
        max_days = config.get('cleanup.quarantine_retention_days', 30)
        now = time.time()
        expired = []

        for qid, info in self._index.items():
            if info.get('deleted'):
                continue
            quar_time = info.get('quarantine_time', 0)
            if (now - quar_time) > max_days * 86400:
                expired.append(qid)

        for qid in expired:
            self.delete(qid)

        if expired:
            logger.info(f"清理了 {len(expired)} 个过期隔离文件")

    def get_all(self) -> List[Dict]:
        """获取所有隔离记录"""
        return [v for v in self._index.values() if not v.get('deleted')]

    def get_stats(self) -> Dict:
        """获取隔离区统计"""
        items = self.get_all()
        total_size = sum(i.get('file_size', 0) for i in items)
        return {
            'total_items': len(items),
            'total_size': total_size,
            'max_size_mb': config.get('cleanup.max_quarantine_size_mb', 1024),
        }


# ============================================================
# 全局隔离区管理器
# ============================================================
quarantine = QuarantineManager()