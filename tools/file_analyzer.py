#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 文件分析工具
"""
import os
import sys
import hashlib
import json
from typing import Dict, Any, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import HashUtil, FileTypeDetector


class FileAnalyzer:
    """文件分析器"""

    @staticmethod
    def analyze(filepath: str) -> Dict[str, Any]:
        """分析文件"""
        if not os.path.exists(filepath):
            return {'error': '文件不存在'}

        result = {
            'path': os.path.abspath(filepath),
            'name': os.path.basename(filepath),
            'extension': os.path.splitext(filepath)[1].lower(),
            'size': os.path.getsize(filepath),
            'size_str': FileAnalyzer._format_size(os.path.getsize(filepath)),
            'created': datetime.fromtimestamp(os.path.getctime(filepath)).isoformat(),
            'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat(),
            'type': FileTypeDetector.detect(filepath),
            'hashes': {
                'md5': HashUtil.md5_file(filepath),
                'sha1': HashUtil.sha1_file(filepath),
                'sha256': HashUtil.sha256_file(filepath),
            },
        }

        # 检查是否为二进制
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
            result['header_hex'] = header.hex()
        except Exception:
            pass

        # 熵值
        try:
            with open(filepath, 'rb') as f:
                data = f.read(min(os.path.getsize(filepath), 65536))
            from collections import Counter
            counter = Counter(data)
            from math import log2
            entropy = 0.0
            for count in counter.values():
                p = count / len(data)
                if p > 0:
                    entropy -= p * log2(p)
            result['entropy'] = round(entropy, 2)
        except Exception:
            pass

        return result

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def export_report(result: Dict, fmt: str = 'json') -> str:
        """导出分析报告"""
        if fmt == 'json':
            return json.dumps(result, ensure_ascii=False, indent=2)
        elif fmt == 'txt':
            lines = [
                f"文件分析报告",
                "=" * 50,
                f"文件: {result.get('name', '')}",
                f"路径: {result.get('path', '')}",
                f"大小: {result.get('size_str', '')}",
                f"类型: {result.get('type', '')}",
                f"MD5: {result.get('hashes', {}).get('md5', '')}",
                f"SHA1: {result.get('hashes', {}).get('sha1', '')}",
                f"SHA256: {result.get('hashes', {}).get('sha256', '')}",
            ]
            return '\n'.join(lines)
        return ''