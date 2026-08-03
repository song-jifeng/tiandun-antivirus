#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 通用文件启发式分析器
文件熵分析、结构异常检测、文件头/尾不匹配检测、可疑字符串检测
实现 20+ 检测规则
"""

import os
import re
import struct
import math
from typing import Tuple, List, Dict, Optional, Any
from collections import Counter


# ============================================================
# 文件魔数签名
# ============================================================
FILE_MAGIC_SIGNATURES = {
    b'MZ': 'PE',
    b'\x7fELF': 'ELF',
    b'\x89PNG': 'PNG',
    b'\xff\xd8\xff': 'JPEG',
    b'GIF8': 'GIF',
    b'%PDF': 'PDF',
    b'PK\x03\x04': 'ZIP/OOXML',
    b'Rar!\x1a\x07': 'RAR',
    b'\x1f\x8b': 'GZIP',
    b'BZh': 'BZ2',
    b'\xfd7zXZ': '7Z',
    b'RIFF': 'RIFF',
    b'BM': 'BMP',
    b'\x00\x01\x00\x00': 'ICO',
    b'%!PS': 'PostScript',
    b'\xca\xfe\xba\xbe': 'Java Class',
    b'\x1a\x45\xdf\xa3': 'WebM/MKV',
    b'{\\rtf': 'RTF',
    b'<!DOCTYPE': 'HTML',
    b'<html': 'HTML',
    b'<svg': 'SVG',
    b'SCE': 'PSP',
    b'\xff\xfb': 'MP3',
    b'\xff\xf3': 'MP3',
    b'\xff\xf2': 'MP3',
    b'ID3': 'MP3',
    b'ftyp': 'MP4',
    b'\x00\x00\x00\x18ftyp': 'MP4',
    b'OggS': 'OGG',
    b'\x00\x00\x01\x00': 'TrueType',
    b'OTTO': 'OpenType',
    b'wOFF': 'WOFF',
    b'wOF2': 'WOFF2',
    b'Cr24': 'Chrome Extension',
    b'MSCF': 'CAB',
    b'ISc(': 'InstallShield',
    b'\x37\x7a\xbc\xaf\x27\x1c': 'LZMA',
    b'\x04\x22\x4d\x18': 'LZ4',
    b'\x28\xb5\x2f\xfd': 'Zstandard',
    b'\x8f\x11\xc0\xb9': 'Zstd',
    b'\x06\x0e\x2b\x34': 'GSS',
}

# 文件尾签名
FILE_FOOTER_SIGNATURES = {
    b'MZ': b'PE\x00\x00',
    b'\x89PNG': b'IEND\xae\x42\x60\x82',
    b'GIF8': b'\x00\x3b',
    b'\xff\xd8\xff': b'\xff\xd9',
    b'PK\x03\x04': b'PK\x05\x06',
    b'RIFF': b'',
}

# 可疑字符串模式
SUSPICIOUS_STRING_PATTERNS = [
    (re.compile(rb'https?://[^\s\'"<>]{5,}'), 'URL'),
    (re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'IP地址'),
    (re.compile(rb'[A-Za-z0-9+/=]{50,}'), 'Base64'),
    (re.compile(rb'[0-9a-fA-F]{32,}'), 'MD5/SHA哈希'),
    (re.compile(rb'[0-9a-fA-F]{40,}'), 'SHA1哈希'),
    (re.compile(rb'[0-9a-fA-F]{64,}'), 'SHA256哈希'),
    (re.compile(rb'\\\\(?:[^\s\\]+\\?)+'), 'UNC路径'),
    (re.compile(rb'[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]*'), 'Windows路径'),
    (re.compile(rb'/usr/|/etc/|/var/|/tmp/|/home/|/root/'), 'Linux路径'),
    (re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), '邮箱地址'),
    (re.compile(rb'HKEY_[A-Z_]+|HK[A-Z]{2,4}\\'), '注册表路径'),
    (re.compile(rb'powershell|cmd\.exe|sh\s+-c|bash\s+-c', re.IGNORECASE), '命令执行'),
    (re.compile(rb'CreateObject|WScript|Shell\.Run|Exec\s*\(', re.IGNORECASE), '脚本执行'),
    (re.compile(rb'encrypt|decrypt|crypt|ransom|bitcoin|wallet|miner', re.IGNORECASE), '加密/勒索'),
    (re.compile(rb'password|credential|token|secret|keylog', re.IGNORECASE), '敏感信息'),
    (re.compile(rb'inject|hook|thread|inject|shellcode|payload', re.IGNORECASE), '恶意代码'),
    (re.compile(rb'VirtualAlloc|WriteProcessMemory|CreateRemoteThread', re.IGNORECASE), '进程注入'),
    (re.compile(rb'IsDebuggerPresent|AntiDebug|Sandbox|VMware|VBox', re.IGNORECASE), '反调试'),
    (re.compile(rb'DownloadFile|URLDownloadToFile|WebClient', re.IGNORECASE), '下载'),
    (re.compile(rb'RegSetValue|RegCreateKey|SetValueEx', re.IGNORECASE), '注册表'),
    (re.compile(rb'CreateService|StartService|OpenSCManager', re.IGNORECASE), '服务'),
    (re.compile(rb'ScheduledTask|SchTasks|schtasks', re.IGNORECASE), '计划任务'),
    (re.compile(rb'net\s+user|net\s+localgroup|net\s+share', re.IGNORECASE), '网络管理'),
    (re.compile(rb'vssadmin|wmic\s+shadowcopy|bcdedit', re.IGNORECASE), '系统管理'),
    (re.compile(rb'MZ\s*PE|PE\s*L|This program', re.IGNORECASE), 'PE特征'),
    (re.compile(rb'\x00{100,}'), '大量空字节'),
]


class GenericAnalyzer:
    """
    通用文件分析器

    对所有文件类型进行通用特征分析：
    - 文件熵分析
    - 文件结构异常检测
    - 文件头/尾不匹配检测
    - 可疑字符串检测
    - 20+ 检测规则
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._max_scan_size = config.get('max_scan_size', 50 * 1024 * 1024)  # 50MB

    def analyze(self, filepath: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        通用文件分析

        Args:
            filepath: 文件路径

        Returns:
            (风险分数0-100, 检测原因列表, 详细分析数据)
        """
        score = 0.0
        reasons = []
        details = {}

        try:
            # 获取文件信息
            stat = os.stat(filepath)
            file_size = stat.st_size
            details['file_size'] = file_size

            # ============================================================
            # 规则 1: 文件大小检测
            # ============================================================
            size_result = self._check_file_size(filepath, file_size)
            if size_result:
                score += size_result['score']
                for reason in size_result['reasons']:
                    reasons.append(reason)
                details['file_size_check'] = size_result['data']

            # 对于超大文件，只分析前部分
            if file_size > self._max_scan_size:
                details['truncated'] = True

            # 读取文件头部
            with open(filepath, 'rb') as f:
                header = f.read(64)

            # ============================================================
            # 规则 2: 文件类型检测（魔数）
            # ============================================================
            magic_result = self._detect_magic(header, filepath)
            if magic_result:
                score += magic_result['score']
                for reason in magic_result['reasons']:
                    reasons.append(reason)
                details['magic'] = magic_result['data']

            # ============================================================
            # 规则 3: 文件头尾不匹配检测
            # ============================================================
            # 读取文件尾部
            with open(filepath, 'rb') as f:
                f.seek(-min(64, file_size), 2)
                footer = f.read(64)

            matching_result = self._check_header_footer(header, footer, file_size)
            if matching_result:
                score += matching_result['score']
                for reason in matching_result['reasons']:
                    reasons.append(reason)
                details['header_footer'] = matching_result['data']

            # ============================================================
            # 规则 4: 文件扩展名与魔数不匹配
            # ============================================================
            ext_mismatch = self._check_extension_magic(header, filepath)
            if ext_mismatch:
                score += ext_mismatch['score']
                for reason in ext_mismatch['reasons']:
                    reasons.append(reason)
                details['extension_mismatch'] = ext_mismatch['data']

            # 读取更多内容用于分析
            with open(filepath, 'rb') as f:
                sample = f.read(min(file_size, 1024 * 1024))  # 最多1MB

            # ============================================================
            # 规则 5: 熵值分析
            # ============================================================
            entropy_result = self._analyze_entropy(sample, file_size)
            if entropy_result:
                score += entropy_result['score']
                for reason in entropy_result['reasons']:
                    reasons.append(reason)
                details['entropy'] = entropy_result['data']

            # ============================================================
            # 规则 6: 空字节比例
            # ============================================================
            null_result = self._check_null_bytes(sample, file_size)
            if null_result:
                score += null_result['score']
                for reason in null_result['reasons']:
                    reasons.append(reason)
                details['null_bytes'] = null_result['data']

            # ============================================================
            # 规则 7: 可疑字符串检测
            # ============================================================
            string_result = self._check_suspicious_strings(sample)
            if string_result:
                score += string_result['score']
                for reason in string_result['reasons']:
                    reasons.append(reason)
                details['suspicious_strings'] = string_result['data']

            # ============================================================
            # 规则 8: 可打印字符比例
            # ============================================================
            printable_result = self._check_printable_ratio(sample, file_size)
            if printable_result:
                score += printable_result['score']
                for reason in printable_result['reasons']:
                    reasons.append(reason)
                details['printable'] = printable_result['data']

            # ============================================================
            # 规则 9: 重复字节检测
            # ============================================================
            repeat_result = self._check_repeated_bytes(sample, file_size)
            if repeat_result:
                score += repeat_result['score']
                for reason in repeat_result['reasons']:
                    reasons.append(reason)
                details['repeated_bytes'] = repeat_result['data']

            # ============================================================
            # 规则 10: 文件时间戳检测
            # ============================================================
            time_result = self._check_file_timestamps(filepath, stat)
            if time_result:
                score += time_result['score']
                for reason in time_result['reasons']:
                    reasons.append(reason)
                details['timestamps'] = time_result['data']

            # ============================================================
            # 规则 11: 文件属性检测
            # ============================================================
            attr_result = self._check_file_attributes(filepath, stat)
            if attr_result:
                score += attr_result['score']
                for reason in attr_result['reasons']:
                    reasons.append(reason)
                details['attributes'] = attr_result['data']

            # ============================================================
            # 规则 12: 文件名检测
            # ============================================================
            name_result = self._check_file_name(filepath)
            if name_result:
                score += name_result['score']
                for reason in name_result['reasons']:
                    reasons.append(reason)
                details['file_name'] = name_result['data']

            # ============================================================
            # 规则 13: 文件结构检测
            # ============================================================
            struct_result = self._check_file_structure(sample, file_size)
            if struct_result:
                score += struct_result['score']
                for reason in struct_result['reasons']:
                    reasons.append(reason)
                details['structure'] = struct_result['data']

            # ============================================================
            # 规则 14: 字节分布分析
            # ============================================================
            distribution_result = self._check_byte_distribution(sample, file_size)
            if distribution_result:
                score += distribution_result['score']
                for reason in distribution_result['reasons']:
                    reasons.append(reason)
                details['byte_distribution'] = distribution_result['data']

            # ============================================================
            # 规则 15: 多部分文件检测
            # ============================================================
            multipart_result = self._check_multipart(filepath, header, sample)
            if multipart_result:
                score += multipart_result['score']
                for reason in multipart_result['reasons']:
                    reasons.append(reason)
                details['multipart'] = multipart_result['data']

        except Exception as e:
            score += 5
            reasons.append(f'通用分析异常: {str(e)}')
            details['error'] = str(e)

        score = min(score, 100.0)
        return score, reasons, details

    # ============================================================
    # 检测规则实现
    # ============================================================

    def _check_file_size(self, filepath: str, size: int) -> Optional[Dict]:
        """检查文件大小"""
        score = 0.0
        reasons = []
        data = {}
        ext = os.path.splitext(filepath)[1].lower()

        # 小文件检测
        if size < 64:
            score += 5
            reasons.append(f'规则1a: 文件大小异常小: {size}字节')
            data['too_small'] = True
        elif size < 1024 and ext in ('.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx'):
            score += 5
            reasons.append(f'规则1b: 可执行文件大小异常小: {size}字节')
            data['small_executable'] = True

        # 大文件检测
        if size > 500 * 1024 * 1024:  # > 500MB
            score += 3
            reasons.append(f'规则1c: 文件异常大: {size/(1024*1024):.1f}MB')
            data['very_large'] = True

        # 空文件检测
        if size == 0:
            score += 3
            reasons.append('规则1d: 空文件')
            data['empty'] = True

        if score > 0:
            return {'score': min(score, 8.0), 'reasons': reasons, 'data': data}
        return None

    def _detect_magic(self, header: bytes, filepath: str) -> Optional[Dict]:
        """检测文件魔数"""
        score = 0.0
        reasons = []
        data = {}

        detected_type = None
        for magic, ftype in FILE_MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                detected_type = ftype
                break

        if detected_type:
            data['detected_type'] = detected_type
        else:
            # 尝试检测是否为文本文件
            text_chars = sum(1 for b in header[:32] if 32 <= b < 127 or b in (9, 10, 13))
            if text_chars > 20:
                data['detected_type'] = 'text'
            else:
                # 未知类型
                data['detected_type'] = 'unknown'
                if len(header) > 4:
                    # 提取前4字节作为特征
                    magic_hex = header[:4].hex()
                    data['magic_hex'] = magic_hex

        # 检查文件是否包含多个MZ头（可能拼接了多个PE文件）
        if b'MZ' in header[2:]:
            score += 8
            reasons.append('规则2a: 文件头包含多个MZ签名')
            data['multiple_mz'] = True

        if score > 0:
            return {'score': min(score, 8.0), 'reasons': reasons, 'data': data}
        return None

    def _check_header_footer(self, header: bytes, footer: bytes,
                             file_size: int) -> Optional[Dict]:
        """检查文件头尾匹配"""
        score = 0.0
        reasons = []
        data = {}

        if file_size < 32:
            return None

        for magic, expected_end in FILE_FOOTER_SIGNATURES.items():
            if header.startswith(magic):
                if expected_end:
                    if expected_end not in footer:
                        score += 5
                        reasons.append(f'规则3: 文件头尾不匹配 (头: {magic[:4].hex()})')
                        data['mismatch'] = True
                break

        if score > 0:
            return {'score': min(score, 5.0), 'reasons': reasons, 'data': data}
        return None

    def _check_extension_magic(self, header: bytes, filepath: str) -> Optional[Dict]:
        """检查文件扩展名与魔数是否匹配"""
        score = 0.0
        reasons = []
        data = {}
        ext = os.path.splitext(filepath)[1].lower()

        # 定义扩展名与魔数的映射
        ext_magic_map = {
            '.exe': [b'MZ'],
            '.dll': [b'MZ'],
            '.sys': [b'MZ'],
            '.scr': [b'MZ'],
            '.cpl': [b'MZ'],
            '.ocx': [b'MZ'],
            '.drv': [b'MZ'],
            '.pdf': [b'%PDF'],
            '.zip': [b'PK\x03\x04'],
            '.rar': [b'Rar!'],
            '.7z': [b'\xfd7z'],
            '.gz': [b'\x1f\x8b'],
            '.bz2': [b'BZh'],
            '.png': [b'\x89PNG'],
            '.jpg': [b'\xff\xd8'],
            '.jpeg': [b'\xff\xd8'],
            '.gif': [b'GIF8'],
            '.bmp': [b'BM'],
            '.ico': [b'\x00\x00\x01\x00'],
            '.mp3': [b'\xff\xfb', b'\xff\xf3', b'ID3'],
            '.mp4': [b'\x00\x00\x00\x18ftyp', b'ftyp'],
            '.doc': [b'\xd0\xcf\x11\xe0'],
            '.xls': [b'\xd0\xcf\x11\xe0'],
            '.ppt': [b'\xd0\xcf\x11\xe0'],
            '.docx': [b'PK\x03\x04'],
            '.xlsx': [b'PK\x03\x04'],
            '.pptx': [b'PK\x03\x04'],
            '.rtf': [b'{\\rtf'],
            '.html': [b'<html', b'<!DOCTYPE'],
            '.htm': [b'<html', b'<!DOCTYPE'],
            '.class': [b'\xca\xfe\xba\xbe'],
            '.ttf': [b'\x00\x00\x01\x00'],
            '.woff': [b'wOFF'],
            '.woff2': [b'wOF2'],
        }

        if ext in ext_magic_map:
            expected_magics = ext_magic_map[ext]
            if not any(header.startswith(m) for m in expected_magics):
                # 检查实际类型
                actual_type = '未知'
                for magic, ftype in FILE_MAGIC_SIGNATURES.items():
                    if header.startswith(magic):
                        actual_type = ftype
                        break
                score += 8
                reasons.append(f'规则4: 扩展名"{ext}"与魔数不匹配 (实际: {actual_type})')
                data['mismatch'] = True
                data['expected'] = ext
                data['actual'] = actual_type

        # 检查文本文件伪装成可执行文件
        if ext in ('.exe', '.dll', '.sys', '.scr') and not header.startswith(b'MZ'):
            # 检查是否为文本文件
            text_chars = sum(1 for b in header[:32] if 32 <= b < 127 or b in (9, 10, 13))
            if text_chars > 20:
                score += 10
                reasons.append(f'规则4: 扩展名为"{ext}"但实际是文本文件')
                data['fake_executable'] = True

        if score > 0:
            return {'score': min(score, 15.0), 'reasons': reasons, 'data': data}
        return None

    def _analyze_entropy(self, data: bytes, file_size: int) -> Optional[Dict]:
        """分析文件熵值"""
        score = 0.0
        reasons = []
        entropy_data = {}

        if len(data) < 64:
            return None

        # 整体熵值
        overall_entropy = self._calculate_entropy(data)
        entropy_data['overall_entropy'] = round(overall_entropy, 2)

        if overall_entropy > 7.5:
            score += 10
            reasons.append(f'规则5a: 整体熵值异常高 (可能已加壳/加密): {overall_entropy:.2f}')
        elif overall_entropy > 6.5:
            score += 5
            reasons.append(f'规则5b: 整体熵值较高: {overall_entropy:.2f}')
        elif overall_entropy < 1.0:
            score += 3
            reasons.append(f'规则5c: 熵值异常低 (可能是空数据): {overall_entropy:.2f}')

        # 分块熵值分析
        if file_size > 4096:
            chunk_size = min(4096, len(data))
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            chunks = [c for c in chunks if len(c) >= 256]

            if chunks:
                high_entropy_chunks = 0
                low_entropy_chunks = 0
                chunk_entropies = []

                for chunk in chunks:
                    chunk_entropy = self._calculate_entropy(chunk)
                    chunk_entropies.append(chunk_entropy)
                    if chunk_entropy > 7.0:
                        high_entropy_chunks += 1
                    elif chunk_entropy < 1.0:
                        low_entropy_chunks += 1

                if chunk_entropies:
                    entropy_data['avg_chunk_entropy'] = round(sum(chunk_entropies) / len(chunk_entropies), 2)
                    entropy_data['max_chunk_entropy'] = round(max(chunk_entropies), 2)
                    entropy_data['min_chunk_entropy'] = round(min(chunk_entropies), 2)

                if high_entropy_chunks > len(chunks) * 0.5:
                    score += 5
                    reasons.append(f'规则5d: 超过50%的区块具有高熵值 ({high_entropy_chunks}/{len(chunks)})')
                    entropy_data['high_entropy_ratio'] = high_entropy_chunks / len(chunks)

                if low_entropy_chunks > len(chunks) * 0.3:
                    score += 3
                    reasons.append(f'规则5e: 超过30%的区块具有低熵值 ({low_entropy_chunks}/{len(chunks)})')
                    entropy_data['low_entropy_ratio'] = low_entropy_chunks / len(chunks)

        if score > 0:
            return {'score': min(score, 15.0), 'reasons': reasons, 'data': entropy_data}
        return None

    def _check_null_bytes(self, data: bytes, file_size: int) -> Optional[Dict]:
        """检查空字节比例"""
        score = 0.0
        reasons = []
        data_info = {}

        if len(data) < 64:
            return None

        total_bytes = len(data)
        null_count = data.count(b'\x00')
        null_ratio = null_count / total_bytes if total_bytes > 0 else 0
        data_info['null_ratio'] = round(null_ratio, 4)

        if null_ratio > 0.3:
            score += 5
            reasons.append(f'规则6a: 空字节比例过高: {null_ratio:.1%}')
            data_info['high_null'] = True
        elif null_ratio > 0.1 and null_ratio <= 0.3:
            score += 2
            reasons.append(f'规则6b: 空字节比例较高: {null_ratio:.1%}')

        # 检查文件前半部分 vs 后半部分空字节比例
        if file_size > 1024:
            with open(data if isinstance(data, str) else '', 'rb') as f:
                pass  # 使用已读取的data

        if score > 0:
            return {'score': min(score, 8.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_suspicious_strings(self, data: bytes) -> Optional[Dict]:
        """检测可疑字符串"""
        score = 0.0
        reasons = []
        data_info = {}

        if len(data) < 32:
            return None

        # 提取可打印字符串
        strings = self._extract_strings(data, min_len=4)
        data_info['total_strings'] = len(strings)
        data_info['string_ratio'] = round(sum(len(s) for s in strings) / len(data), 4) if data else 0

        # 检查各种模式
        found_patterns = []
        for pattern, name in SUSPICIOUS_STRING_PATTERNS:
            matches = pattern.findall(data)
            if matches:
                unique_count = len(set(matches))
                if unique_count > 0:
                    found_patterns.append((name, unique_count))

        # 评分
        if found_patterns:
            category_map = {}
            for name, count in found_patterns:
                category_map[name] = count

            # 恶意类别加重
            high_risk_categories = ['进程注入', '加密/勒索', '反调试', '漏洞利用', 'Shellcode']
            medium_risk_categories = ['下载', '命令执行', '脚本执行', '服务', '计划任务']

            for cat, count in category_map.items():
                if cat in high_risk_categories:
                    score += 5 * min(count, 3)
                elif cat in medium_risk_categories:
                    score += 3 * min(count, 3)
                else:
                    score += 2 * min(count, 2)

            # 汇总
            categories_desc = [f'{name}({count})' for name, count in list(category_map.items())[:8]]
            reasons.append(f'规则7: 检测到可疑字符串: {", ".join(categories_desc)}')
            data_info['found_categories'] = {k: v for k, v in list(category_map.items())[:10]}

        # 检查特殊嵌入数据
        if b'MZ' in data[2:] and b'PE\x00\x00' in data:
            score += 5
            reasons.append('规则7: 文件包含嵌入式PE文件')
            data_info['embedded_pe'] = True

        if score > 0:
            return {'score': min(score, 20.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_printable_ratio(self, data: bytes, file_size: int) -> Optional[Dict]:
        """检查可打印字符比例"""
        score = 0.0
        reasons = []
        data_info = {}

        if len(data) < 64:
            return None

        total = len(data)
        printable = sum(1 for b in data if 32 <= b < 127)
        printable_ratio = printable / total if total > 0 else 0
        data_info['printable_ratio'] = round(printable_ratio, 4)

        # 高可打印字符比例可能表示脚本或文本
        if printable_ratio > 0.9:
            data_info['is_text_like'] = True
        elif printable_ratio < 0.1:
            data_info['is_binary_like'] = True

        if score > 0:
            return {'score': min(score, 3.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_repeated_bytes(self, data: bytes, file_size: int) -> Optional[Dict]:
        """检测重复字节模式"""
        score = 0.0
        reasons = []
        data_info = {}

        if len(data) < 256:
            return None

        # 检查常见填充字节
        fill_patterns = {
            b'\x00': '空字节',
            b'\x90': 'NOP',
            b'\xcc': 'INT3',
            b'\xff': '0xFF',
            b'\xcd': '0xCD',
            b'\x20': '空格',
            b'\x41': 'A',
            b'\x55': 'U',
            b'\x00' * 16: '空填充',
            b'\x90' * 16: 'NOP填充',
            b'\xcc' * 16: 'INT3填充',
        }

        for pattern, name in fill_patterns.items():
            if len(pattern) == 1:
                count = data.count(pattern)
                ratio = count / len(data)
                if ratio > 0.3:
                    score += 3
                    reasons.append(f'规则9a: 大量重复字节({name}): {ratio:.1%}')
                    data_info[f'{name}_ratio'] = round(ratio, 4)
            else:
                # 多字节模式
                count = data.count(pattern)
                if count > 5:
                    score += 5
                    reasons.append(f'规则9b: 检测到{name} ({count}次)')
                    data_info[f'{name}_count'] = count

        if score > 0:
            return {'score': min(score, 10.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_file_timestamps(self, filepath: str, stat: os.stat_result) -> Optional[Dict]:
        """检查文件时间戳"""
        score = 0.0
        reasons = []
        data_info = {}

        import time
        now = time.time()
        created = stat.st_ctime
        modified = stat.st_mtime
        accessed = stat.st_atime

        data_info['created'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created))
        data_info['modified'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modified))
        data_info['accessed'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(accessed))

        # 未来时间戳
        if created > now + 86400:
            score += 5
            reasons.append('规则10a: 创建时间在未来')
            data_info['future_created'] = True

        if modified > now + 86400:
            score += 5
            reasons.append('规则10b: 修改时间在未来')
            data_info['future_modified'] = True

        # 时间戳为0
        if created == 0 or modified == 0:
            score += 3
            reasons.append('规则10c: 时间戳为0')
            data_info['zero_timestamp'] = True

        # 创建时间等于修改时间（可能被修改）
        if abs(created - modified) < 1 and file_size > 1024:
            score += 2
            reasons.append('规则10d: 创建时间和修改时间相同')
            data_info['same_timestamps'] = True

        if score > 0:
            return {'score': min(score, 8.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_file_attributes(self, filepath: str, stat: os.stat_result) -> Optional[Dict]:
        """检查文件属性"""
        score = 0.0
        reasons = []
        data_info = {}
        ext = os.path.splitext(filepath)[1].lower()

        try:
            # 检查隐藏属性
            if hasattr(stat, 'st_file_attributes'):
                attrs = stat.st_file_attributes
                if attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                    data_info['hidden'] = True
                if attrs & 4:  # FILE_ATTRIBUTE_SYSTEM
                    score += 3
                    reasons.append('规则11: 文件标记为系统文件')
                    data_info['system'] = True
                if attrs & 32:  # FILE_ATTRIBUTE_ARCHIVE
                    pass
        except Exception:
            pass

        # 检查文件所在目录
        dir_name = os.path.basename(os.path.dirname(filepath)).lower()
        suspicious_dirs = ['temp', 'tmp', 'appdata', 'cache', 'downloads', 'recycle']
        if dir_name in suspicious_dirs:
            score += 3
            reasons.append(f'规则11: 文件位于可疑目录: {dir_name}')
            data_info['suspicious_dir'] = dir_name

        if score > 0:
            return {'score': min(score, 5.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_file_name(self, filepath: str) -> Optional[Dict]:
        """检查文件名"""
        score = 0.0
        reasons = []
        data_info = {}
        filename = os.path.basename(filepath)
        name_without_ext = os.path.splitext(filename)[0].lower()

        # 可疑文件名模式
        suspicious_patterns = [
            (r'^(?:readme|document|file|info|help|setup|install|update|patch|crack|keygen|license)(?:\d*)$', '常见恶意文件名', 5),
            (r'^[a-f0-9]{16,}$', '哈希文件名', 4),
            (r'^[a-z]{1,3}\d{1,3}[a-z]{0,3}\.exe$', '自动生成文件名', 3),
            (r'^(?:new|copy|backup|temp|tmp)\d*$', '临时文件名', 2),
            (r'^(?:document|scan|report|invoice|payment|shipping|notice|alert|urgent|important)', '钓鱼文件名', 6),
            (r'^(?:photo|pic|image|img|video|movie|song|music|audio)', '媒体伪装', 5),
            (r'^(?:resume|cv|application|job|salary|bonus)', '求职相关钓鱼', 6),
            (r'^(?:order|receipt|purchase|bill|invoice|payment|refund|transaction)', '交易相关钓鱼', 6),
        ]

        for pattern, desc, pts in suspicious_patterns:
            if re.match(pattern, name_without_ext):
                score += pts
                reasons.append(f'规则12: 可疑文件名: {desc} ({filename})')
                data_info['suspicious_name'] = desc
                break

        # 双扩展名
        if filename.count('.') > 1:
            extensions = filename.split('.')[1:]
            if any(ext in ('.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1') for ext in extensions):
                score += 8
                reasons.append(f'规则12: 双扩展名文件: {filename}')
                data_info['double_extension'] = True

        # Unicode伪装
        for ch in filename:
            if ord(ch) > 127:
                score += 5
                reasons.append(f'规则12: 文件名包含Unicode字符')
                data_info['unicode_name'] = True
                break

        if score > 0:
            return {'score': min(score, 10.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_file_structure(self, data: bytes, file_size: int) -> Optional[Dict]:
        """检查文件结构异常"""
        score = 0.0
        reasons = []
        data_info = {}

        if len(data) < 64:
            return None

        # 检查PE结构
        if data[:2] == b'MZ':
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if pe_offset + 4 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                # 计算实际大小与声明大小的差异
                try:
                    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
                    if num_sections > 0 and num_sections < 100:
                        # 计算最后一个节区的末尾
                        optional_header_offset = pe_offset + 24
                        magic = struct.unpack_from('<H', data, optional_header_offset)[0]
                        header_size = 240 if magic == 0x20b else 224
                        section_table_offset = optional_header_offset + header_size

                        last_section_end = 0
                        for i in range(min(num_sections, 50)):
                            sec_offset = section_table_offset + i * 40
                            if sec_offset + 40 > len(data):
                                break
                            raw_size = struct.unpack_from('<I', data, sec_offset + 16)[0]
                            raw_offset = struct.unpack_from('<I', data, sec_offset + 20)[0]
                            sec_end = raw_offset + raw_size
                            if sec_end > last_section_end:
                                last_section_end = sec_end

                        if last_section_end > 0 and last_section_end < file_size:
                            overlay = file_size - last_section_end
                            if overlay > 1000:
                                score += 5
                                reasons.append(f'规则13: 文件包含大量叠加数据 ({overlay}字节)')
                                data_info['large_overlay'] = overlay
                except Exception:
                    pass

        # 检查ZIP结构
        if data[:2] == b'PK':
            # 检查ZIP注释
            if b'PK\x05\x06' in data:
                score += 2
                reasons.append('规则13: 检测到ZIP结构')
                data_info['zip_structure'] = True

        if score > 0:
            return {'score': min(score, 8.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_byte_distribution(self, data: bytes, file_size: int) -> Optional[Dict]:
        """检查字节分布"""
        score = 0.0
        reasons = []
        data_info = {}

        if len(data) < 256:
            return None

        # 统计字节值分布
        counter = Counter(data)
        unique_bytes = len(counter)
        data_info['unique_bytes'] = unique_bytes
        data_info['byte_coverage'] = round(unique_bytes / 256 * 100, 1)

        # 字节覆盖度
        if unique_bytes < 30:
            score += 3
            reasons.append(f'规则14a: 字节覆盖度低 ({unique_bytes}/256)')
            data_info['low_coverage'] = True

        # 最常见的字节值
        most_common = counter.most_common(3)
        if most_common:
            top_byte, top_count = most_common[0]
            top_ratio = top_count / len(data)
            if top_ratio > 0.4:
                score += 3
                reasons.append(f'规则14b: 字节分布不均，单一字节占比 {top_ratio:.1%}')
                data_info['unbalanced'] = True

        if score > 0:
            return {'score': min(score, 5.0), 'reasons': reasons, 'data': data_info}
        return None

    def _check_multipart(self, filepath: str, header: bytes, data: bytes) -> Optional[Dict]:
        """检测多部分/拼接文件"""
        score = 0.0
        reasons = []
        data_info = {}

        if len(data) < 1024:
            return None

        # 检测多个MZ头
        mz_positions = []
        pos = 0
        while True:
            pos = data.find(b'MZ', pos)
            if pos == -1:
                break
            if pos % 0x200 == 0 or pos % 0x1000 == 0:  # 对齐位置
                mz_positions.append(pos)
            pos += 1

        if len(mz_positions) > 1:
            score += 8
            reasons.append(f'规则15: 检测到多个PE文件拼接 ({len(mz_positions)}个)')
            data_info['multiple_pe'] = len(mz_positions)

        # 检测多个PDF头
        pdf_positions = []
        pos = 0
        while True:
            pos = data.find(b'%PDF-', pos)
            if pos == -1:
                break
            pdf_positions.append(pos)
            pos += 1

        if len(pdf_positions) > 1:
            score += 8
            reasons.append(f'规则15: 检测到多个PDF文件拼接 ({len(pdf_positions)}个)')
            data_info['multiple_pdf'] = len(pdf_positions)

        # 检测ZIP + PE 拼接
        if data[:2] == b'PK' and b'MZ' in data[100:]:
            score += 10
            reasons.append('规则15: 检测到ZIP+PE拼接文件')
            data_info['zip_pe_joined'] = True

        if score > 0:
            return {'score': min(score, 12.0), 'reasons': reasons, 'data': data_info}
        return None

    # ============================================================
    # 辅助方法
    # ============================================================

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """提取可打印字符串"""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_len:
            strings.append(''.join(current))
        return strings

    def _calculate_entropy(self, data: bytes) -> float:
        """计算香农熵"""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counter = Counter(data)
        for count in counter.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy