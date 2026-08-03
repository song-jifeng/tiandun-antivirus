#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 文件元数据分析工具
"""
import os
import sys
import json
import time
import struct
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FileMetadata:
    """文件元数据"""

    @staticmethod
    def get_all(filepath: str) -> Dict[str, Any]:
        """获取完整文件元数据"""
        metadata = {
            'basic': FileMetadata.get_basic(filepath),
            'timestamps': FileMetadata.get_timestamps(filepath),
            'permissions': FileMetadata.get_permissions(filepath),
            'hashes': FileMetadata.get_hashes(filepath),
            'type': FileMetadata.get_type(filepath),
        }
        # 根据文件类型获取额外信息
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ('.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx'):
            metadata['pe'] = FileMetadata.get_pe_info(filepath)
        elif ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp'):
            metadata['image'] = FileMetadata.get_image_info(filepath)
        elif ext in ('.zip', '.rar', '.7z', '.tar', '.gz'):
            metadata['archive'] = FileMetadata.get_archive_info(filepath)
        elif ext in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'):
            metadata['office'] = FileMetadata.get_office_info(filepath)
        elif ext == '.pdf':
            metadata['pdf'] = FileMetadata.get_pdf_info(filepath)
        return metadata

    @staticmethod
    def get_basic(filepath: str) -> Dict:
        """获取基本信息"""
        try:
            stat = os.stat(filepath)
            return {
                'file_name': os.path.basename(filepath),
                'file_path': os.path.abspath(filepath),
                'file_size': stat.st_size,
                'file_size_str': FileMetadata._format_size(stat.st_size),
                'extension': os.path.splitext(filepath)[1].lower(),
                'is_directory': os.path.isdir(filepath),
                'is_file': os.path.isfile(filepath),
                'is_symlink': os.path.islink(filepath),
                'is_hidden': FileMetadata._is_hidden(filepath),
            }
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_timestamps(filepath: str) -> Dict:
        """获取时间戳"""
        try:
            stat = os.stat(filepath)
            return {
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'created_timestamp': stat.st_ctime,
                'modified_timestamp': stat.st_mtime,
                'accessed_timestamp': stat.st_atime,
            }
        except Exception:
            return {}

    @staticmethod
    def get_permissions(filepath: str) -> Dict:
        """获取权限信息"""
        try:
            stat = os.stat(filepath)
            mode = stat.st_mode
            if sys.platform == 'win32':
                attrs = stat.st_file_attributes
                return {
                    'readonly': bool(attrs & 1),
                    'hidden': bool(attrs & 2),
                    'system': bool(attrs & 4),
                    'archive': bool(attrs & 32),
                    'compressed': bool(attrs & 2048),
                    'encrypted': bool(attrs & 16384),
                    'mode': oct(mode),
                    'owner': stat.st_uid,
                }
            else:
                return {
                    'mode': oct(mode),
                    'owner': stat.st_uid,
                    'group': stat.st_gid,
                    'permissions': {
                        'owner_read': bool(mode & 0o400),
                        'owner_write': bool(mode & 0o200),
                        'owner_execute': bool(mode & 0o100),
                        'group_read': bool(mode & 0o40),
                        'group_write': bool(mode & 0o20),
                        'group_execute': bool(mode & 0o10),
                        'other_read': bool(mode & 0o4),
                        'other_write': bool(mode & 0o2),
                        'other_execute': bool(mode & 0o1),
                    },
                }
        except Exception:
            return {}

    @staticmethod
    def get_hashes(filepath: str) -> Dict:
        """获取哈希值"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            return {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
                'sha512': hashlib.sha512(data).hexdigest(),
                'blake2b': hashlib.blake2b(data).hexdigest(),
            }
        except Exception:
            return {}

    @staticmethod
    def get_type(filepath: str) -> Dict:
        """获取文件类型信息"""
        ext = os.path.splitext(filepath)[1].lower()
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(8)
            # 文件类型检测
            type_map = {
                b'MZ': 'PE (Portable Executable)',
                b'\x89PNG': 'PNG Image',
                b'\xff\xd8\xff': 'JPEG Image',
                b'GIF8': 'GIF Image',
                b'%PDF': 'PDF Document',
                b'PK\x03\x04': 'ZIP Archive',
                b'Rar!\x1a\x07': 'RAR Archive',
                b'\x1f\x8b': 'GZIP Archive',
                b'BZh': 'BZIP2 Archive',
                b'\xfd7zXZ': '7z Archive',
                b'RIFF': 'RIFF (AVI/WAV)',
                b'BM': 'BMP Image',
                b'\xca\xfe\xba\xbe': 'Java Class',
                b'\x1a\x45\xdf\xa3': 'WebM/MKV Video',
                b'{\\rtf': 'RTF Document',
                b'<!DOCTYPE': 'HTML Document',
                b'<html': 'HTML Document',
                b'<svg': 'SVG Image',
            }
            for sig, desc in type_map.items():
                if magic.startswith(sig):
                    return {
                        'mime_type': desc,
                        'magic_hex': magic[:8].hex(),
                        'extension': ext,
                    }
            return {'mime_type': 'Unknown', 'magic_hex': magic[:8].hex(), 'extension': ext}
        except Exception:
            return {'mime_type': 'Unknown', 'extension': ext}

    @staticmethod
    def get_pe_info(filepath: str) -> Dict:
        """获取PE文件信息"""
        info = {}
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            if len(data) < 64 or data[:2] != b'MZ':
                return {'error': 'Not a valid PE file'}
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return {'error': 'Not a valid PE file'}
            # 解析文件头
            machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
            characteristics = struct.unpack_from('<H', data, pe_offset + 22)[0]
            machine_names = {
                0x14c: 'x86 (I386)', 0x8664: 'x64 (AMD64)',
                0x1c0: 'ARM', 0xaa64: 'ARM64', 0x200: 'IA64',
            }
            info['machine'] = machine_names.get(machine, f'Unknown (0x{machine:x})')
            info['sections'] = num_sections
            info['is_dll'] = bool(characteristics & 0x2000)
            info['is_system'] = bool(characteristics & 0x1000)
            # 解析可选头
            magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
            info['pe_type'] = 'PE32' if magic == 0x10b else 'PE32+' if magic == 0x20b else 'Unknown'
            # 解析节区
            header_size = 224 if magic == 0x10b else 240
            section_table = pe_offset + 24 + header_size
            sections = []
            for i in range(min(num_sections, 20)):
                sec = section_table + i * 40
                if sec + 40 > len(data):
                    break
                name = data[sec:sec+8].rstrip(b'\x00').decode('ascii', errors='replace')
                vsize = struct.unpack_from('<I', data, sec + 8)[0]
                vaddr = struct.unpack_from('<I', data, sec + 12)[0]
                rsize = struct.unpack_from('<I', data, sec + 16)[0]
                roff = struct.unpack_from('<I', data, sec + 20)[0]
                chars = struct.unpack_from('<I', data, sec + 36)[0]
                sections.append({
                    'name': name.strip(),
                    'virtual_size': vsize,
                    'virtual_address': f'0x{vaddr:08x}',
                    'raw_size': rsize,
                    'raw_offset': f'0x{roff:08x}',
                    'executable': bool(chars & 0x20000000),
                    'writeable': bool(chars & 0x80000000),
                    'readable': bool(chars & 0x40000000),
                    'has_code': bool(chars & 0x20),
                })
            info['section_details'] = sections
            # 获取导入表信息
            info['imports_count'] = 0
            try:
                import pefile
                pe = pefile.PE(filepath)
                info['imports_count'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
                info['exports_count'] = len(pe.DIRECTORY_ENTRY_EXPORT) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
                info['resources_count'] = len(pe.DIRECTORY_ENTRY_RESOURCE) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
                pe.close()
            except ImportError:
                pass
            except Exception:
                pass
        except Exception as e:
            info['error'] = str(e)
        return info

    @staticmethod
    def get_image_info(filepath: str) -> Dict:
        """获取图片信息"""
        info = {}
        try:
            from PIL import Image
            with Image.open(filepath) as img:
                info['width'] = img.width
                info['height'] = img.height
                info['format'] = img.format
                info['mode'] = img.mode
                info['size'] = f"{img.width}x{img.height}"
                info['aspect_ratio'] = round(img.width / img.height, 2) if img.height > 0 else 0
                info['dpi'] = img.info.get('dpi', (72, 72))
        except ImportError:
            # 不使用PIL，直接读取文件头
            try:
                with open(filepath, 'rb') as f:
                    header = f.read(24)
                if header[:2] == b'\xff\xd8':
                    # JPEG
                    info['format'] = 'JPEG'
                elif header[:8] == b'\x89PNG\r\n\x1a\n':
                    # PNG
                    width = struct.unpack_from('>I', header, 16)[0]
                    height = struct.unpack_from('>I', header, 20)[0]
                    info['width'] = width
                    info['height'] = height
                    info['size'] = f"{width}x{height}"
                    info['format'] = 'PNG'
                elif header[:6] == b'GIF87a' or header[:6] == b'GIF89a':
                    width = struct.unpack_from('<H', header, 6)[0]
                    height = struct.unpack_from('<H', header, 8)[0]
                    info['width'] = width
                    info['height'] = height
                    info['format'] = 'GIF'
            except Exception:
                pass
        return info

    @staticmethod
    def get_archive_info(filepath: str) -> Dict:
        """获取归档文件信息"""
        info = {}
        try:
            import zipfile
            if zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, 'r') as zf:
                    info['format'] = 'ZIP'
                    info['compressed_size'] = os.path.getsize(filepath)
                    info['uncompressed_size'] = sum(f.file_size for f in zf.infolist())
                    info['file_count'] = len(zf.infolist())
                    info['compression_ratio'] = round(info['uncompressed_size'] / info['compressed_size'], 1) if info['compressed_size'] > 0 else 0
                    info['files'] = [f.filename for f in zf.infolist()[:20]]
        except ImportError:
            pass
        except Exception:
            pass
        return info

    @staticmethod
    def get_office_info(filepath: str) -> Dict:
        """获取Office文档信息"""
        info = {}
        try:
            import zipfile
            if zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, 'r') as zf:
                    # 检查文档类型
                    names = zf.namelist()
                    if any('word/' in n for n in names):
                        info['type'] = 'Word Document'
                    elif any('xl/' in n for n in names):
                        info['type'] = 'Excel Workbook'
                    elif any('ppt/' in n for n in names):
                        info['type'] = 'PowerPoint Presentation'
                    # 检查宏
                    info['has_macros'] = any('vba' in n.lower() or 'macro' in n.lower() for n in names)
                    # 检查外部链接
                    info['has_external_links'] = any('external' in n.lower() for n in names)
                    info['content_types'] = [n for n in names if n.endswith('.xml')][:10]
        except Exception:
            pass
        return info

    @staticmethod
    def get_pdf_info(filepath: str) -> Dict:
        """获取PDF文档信息"""
        info = {}
        try:
            with open(filepath, 'rb') as f:
                data = f.read(4096)
            if data[:5] == b'%PDF-':
                info['version'] = data[5:8].decode('ascii', errors='replace')
                info['has_javascript'] = b'/JavaScript' in data or b'/JS' in data
                info['has_embedded_files'] = b'/EmbeddedFile' in data or b'/Embedded' in data
                info['has_launch_action'] = b'/Launch' in data
                info['has_open_action'] = b'/OpenAction' in data
                info['has_acro_form'] = b'/AcroForm' in data
                info['page_count'] = 0
                # 尝试获取页数
                import re
                pages = re.findall(rb'/Type\s*/Page[^s]', data)
                info['page_count'] = len(pages) if pages else 0
                # 加密状态
                info['encrypted'] = b'/Encrypt' in data
        except Exception:
            pass
        return info

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    @staticmethod
    def _is_hidden(filepath: str) -> bool:
        try:
            if sys.platform == 'win32':
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                return bool(attrs & 2) if attrs != -1 else False
            return os.path.basename(filepath).startswith('.')
        except Exception:
            return False


class MediaAnalyzer:
    """媒体文件分析器"""

    @staticmethod
    def analyze_audio(filepath: str) -> Dict:
        """分析音频文件"""
        info = {}
        ext = os.path.splitext(filepath)[1].lower()
        try:
            if ext == '.mp3':
                with open(filepath, 'rb') as f:
                    header = f.read(10)
                if header[:3] == b'ID3':
                    info['format'] = 'MP3 (ID3)'
                    info['has_id3v2'] = True
                    size = struct.unpack('>I', header[6:10])[0]
                    info['tag_size'] = size
            elif ext == '.wav':
                with open(filepath, 'rb') as f:
                    header = f.read(44)
                if header[:4] == b'RIFF' and header[8:12] == b'WAVE':
                    info['format'] = 'WAV'
                    channels = struct.unpack_from('<H', header, 22)[0]
                    sample_rate = struct.unpack_from('<I', header, 24)[0]
                    bits_per_sample = struct.unpack_from('<H', header, 34)[0]
                    info['channels'] = channels
                    info['sample_rate'] = sample_rate
                    info['bits_per_sample'] = bits_per_sample
                    duration = os.path.getsize(filepath) / (sample_rate * channels * bits_per_sample / 8)
                    info['duration_seconds'] = round(duration, 1)
        except Exception:
            pass
        return info

    @staticmethod
    def analyze_video(filepath: str) -> Dict:
        """分析视频文件"""
        info = {}
        try:
            with open(filepath, 'rb') as f:
                header = f.read(32)
            if header[:4] == b'RIFF' and header[8:12] == b'AVI ':
                info['format'] = 'AVI'
            elif header[:4] == b'\x1a\x45\xdf\xa3':
                info['format'] = 'MKV/WebM'
            elif header[:4] == b'ftyp':
                info['format'] = 'MP4'
        except Exception:
            pass
        return info


class TextAnalyzer:
    """文本分析器"""

    @staticmethod
    def analyze_text(filepath: str) -> Dict:
        """分析文本文件"""
        info = {}
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            info['encoding'] = 'utf-8'
            info['char_count'] = len(content)
            info['word_count'] = len(content.split())
            info['line_count'] = content.count('\n') + 1
            info['avg_line_length'] = round(len(content) / max(1, info['line_count']), 1)
            # 统计字符频率
            from collections import Counter
            char_freq = Counter(content.lower())
            info['most_common_chars'] = char_freq.most_common(10)
            # 检测语言
            chinese_chars = len([c for c in content if '一' <= c <= '鿿'])
            english_chars = len([c for c in content if c.isalpha()])
            info['chinese_ratio'] = round(chinese_chars / max(1, info['char_count']), 3)
            info['english_ratio'] = round(english_chars / max(1, info['char_count']), 3)
            info['is_chinese'] = chinese_chars > english_chars
        except Exception as e:
            info['error'] = str(e)
        return info


class BinaryAnalyzer:
    """二进制分析器"""

    @staticmethod
    def analyze_binary(filepath: str) -> Dict:
        """分析二进制文件"""
        info = {}
        try:
            size = os.path.getsize(filepath)
            with open(filepath, 'rb') as f:
                data = f.read(min(size, 65536))
            info['size'] = size
            info['entropy'] = BinaryAnalyzer._calculate_entropy(data)
            info['null_ratio'] = round(data.count(b'\x00') / len(data), 3) if data else 0
            info['printable_ratio'] = round(sum(1 for b in data if 32 <= b < 127) / len(data), 3) if data else 0
            # 提取字符串
            strings = []
            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= 4:
                        strings.append(''.join(current))
                    current = []
            if len(current) >= 4:
                strings.append(''.join(current))
            info['strings_found'] = len(strings)
            info['sample_strings'] = strings[:20]
        except Exception as e:
            info['error'] = str(e)
        return info

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        from collections import Counter
        import math
        counter = Counter(data)
        entropy = 0.0
        length = len(data)
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 2)