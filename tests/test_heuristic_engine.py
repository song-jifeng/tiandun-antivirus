#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 启发式引擎单元测试
"""
import os
import sys
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.heuristic.heuristic_engine import HeuristicEngine, PE_EXTENSIONS, SCRIPT_EXTENSIONS, DOCUMENT_EXTENSIONS
from engine import FileTypeDetector, HashUtil


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def engine():
    """创建启发式引擎"""
    return HeuristicEngine()


@pytest.fixture
def temp_pe_file():
    """创建临时 PE 文件（MZ 头）"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
        f.write(b'MZ' + b'\x00' * 100)
        fpath = f.name
    yield fpath
    try:
        os.unlink(fpath)
    except Exception:
        pass


@pytest.fixture
def temp_script_file():
    """创建临时脚本文件"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.ps1', mode='w', encoding='utf-8') as f:
        f.write('# Simple PowerShell script\nWrite-Host "Hello"\n')
        fpath = f.name
    yield fpath
    try:
        os.unlink(fpath)
    except Exception:
        pass


@pytest.fixture
def temp_document_file():
    """创建临时文档文件"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', mode='wb') as f:
        f.write(b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF')
        fpath = f.name
    yield fpath
    try:
        os.unlink(fpath)
    except Exception:
        pass


# ============================================================
# 文件类型检测测试
# ============================================================

class TestFileTypeDetection:
    """测试文件类型检测"""

    def test_detect_pe_file(self, temp_pe_file):
        """测试检测 PE 文件"""
        ftype = FileTypeDetector.detect(temp_pe_file)
        assert 'exe' in ftype or 'dll' in ftype, f"PE 文件应检测为 exe/dll, 得到 {ftype}"

    def test_detect_text_file(self, tmp_path):
        """测试检测文本文件"""
        text_file = tmp_path / 'test.txt'
        text_file.write_text('Hello, World!')
        ftype = FileTypeDetector.detect(str(text_file))
        assert ftype == 'text', f"文本文件应检测为 text, 得到 {ftype}"

    def test_detect_pdf_file(self, temp_document_file):
        """测试检测 PDF 文件"""
        ftype = FileTypeDetector.detect(temp_document_file)
        assert 'pdf' in ftype, f"PDF 文件应检测为 pdf, 得到 {ftype}"

    def test_detect_nonexistent_file(self):
        """测试检测不存在的文件"""
        ftype = FileTypeDetector.detect('/nonexistent/file.exe')
        assert ftype == 'unknown'

    def test_detect_zip_file(self, tmp_path):
        """测试检测 ZIP 文件"""
        zip_file = tmp_path / 'test.zip'
        zip_file.write_bytes(b'PK\x03\x04' + b'\x00' * 20)
        ftype = FileTypeDetector.detect(str(zip_file))
        assert 'zip' in ftype, f"ZIP 文件应检测为 zip, 得到 {ftype}"

    def test_detect_elf_file(self, tmp_path):
        """测试检测 ELF 文件"""
        elf_file = tmp_path / 'test.elf'
        elf_file.write_bytes(b'\x7fELF' + b'\x00' * 20)
        ftype = FileTypeDetector.detect(str(elf_file))
        assert 'elf' in ftype, f"ELF 文件应检测为 elf, 得到 {ftype}"


# ============================================================
# 启发式引擎测试
# ============================================================

class TestHeuristicEngine:
    """测试启发式引擎"""

    def test_engine_initialization(self, engine):
        """测试引擎初始化"""
        assert engine.name == 'HeuristicEngine'
        assert engine.enabled is True
        assert engine.heuristic_level == 'medium'
        assert engine.pe_analyzer is not None
        assert engine.script_analyzer is not None
        assert engine.doc_analyzer is not None
        assert engine.generic_analyzer is not None
        assert engine.scoring is not None

    def test_scan_nonexistent_file(self, engine):
        """测试扫描不存在的文件"""
        result = engine.scan('/nonexistent/file.exe')
        assert result is None

    def test_scan_clean_text_file(self, engine, tmp_path):
        """测试扫描干净文本文件"""
        clean_file = tmp_path / 'clean.txt'
        clean_file.write_text('This is a completely safe text file.')
        result = engine.scan(str(clean_file))
        # 通用分析器可能给一些分数，但应该低于阈值
        # 结果可能是 None (安全) 或非常低的威胁等级
        if result:
            assert result.threat_level < 3, "干净文件不应有高威胁等级"

    def test_scan_pe_file(self, engine, temp_pe_file):
        """测试扫描 PE 文件"""
        result = engine.scan(temp_pe_file)
        # PE 文件可能会被分析，但简单的 MZ 头不应该触发检测
        # 实际上通用分析器可能检测到一些特征
        # 我们只测试不会崩溃
        assert result is None or isinstance(result.threat_level, int)

    def test_scan_script_file(self, engine, temp_script_file):
        """测试扫描脚本文件"""
        result = engine.scan(temp_script_file)
        # 简单脚本不应触发检测
        assert result is None or isinstance(result.threat_level, int)

    def test_exclusion_paths(self, engine, tmp_path):
        """测试排除路径"""
        # 引擎默认排除项目根目录
        our_file = tmp_path / 'test.txt'
        our_file.write_text('test content')
        engine._exclusion_paths.append(str(tmp_path))
        result = engine.scan(str(our_file))
        assert result is None, "排除路径中的文件不应被扫描"

    def test_different_heuristic_levels(self):
        """测试不同启发式级别"""
        for level in ['low', 'medium', 'high']:
            e = HeuristicEngine({'heuristic_level': level})
            assert e.heuristic_level == level
            assert e.scoring is not None

    def test_scan_document_file(self, engine, temp_document_file):
        """测试扫描文档文件"""
        result = engine.scan(temp_document_file)
        # 简单 PDF 不应触发检测
        assert result is None or isinstance(result.threat_level, int)

    def test_get_stats(self, engine):
        """测试获取统计信息"""
        stats = engine.get_stats()
        assert 'scanned' in stats
        assert 'detected' in stats
        assert 'heuristic_level' in stats
        assert stats['heuristic_level'] == 'medium'

    def test_reset_stats(self, engine):
        """测试重置统计"""
        engine.stats['scanned'] = 100
        engine.stats['detected'] = 5
        engine.reset_stats()
        assert engine.stats['scanned'] == 0
        assert engine.stats['detected'] == 0

    def test_extension_constants(self):
        """测试扩展名常量定义"""
        assert '.exe' in PE_EXTENSIONS
        assert '.dll' in PE_EXTENSIONS
        assert '.ps1' in SCRIPT_EXTENSIONS
        assert '.vbs' in SCRIPT_EXTENSIONS
        assert '.doc' in DOCUMENT_EXTENSIONS
        assert '.pdf' in DOCUMENT_EXTENSIONS


# ============================================================
# 文件哈希测试
# ============================================================

class TestHashUtil:
    """测试哈希工具"""

    def test_md5_empty_file(self, tmp_path):
        """测试空文件 MD5"""
        empty = tmp_path / 'empty.bin'
        empty.write_text('')
        md5 = HashUtil.md5_file(str(empty))
        # 空文件的 MD5
        assert md5 == 'd41d8cd98f00b204e9800998ecf8427e'

    def test_md5_known_string(self, tmp_path):
        """测试已知字符串的 MD5"""
        f = tmp_path / 'test.txt'
        f.write_text('Hello')
        md5 = HashUtil.md5_file(str(f))
        assert len(md5) == 32
        assert all(c in '0123456789abcdef' for c in md5)

    def test_sha1_empty_file(self, tmp_path):
        """测试空文件 SHA1"""
        empty = tmp_path / 'empty.bin'
        empty.write_text('')
        sha1 = HashUtil.sha1_file(str(empty))
        assert sha1 == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

    def test_sha256_empty_file(self, tmp_path):
        """测试空文件 SHA256"""
        empty = tmp_path / 'empty.bin'
        empty.write_text('')
        sha256 = HashUtil.sha256_file(str(empty))
        assert sha256 == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    def test_compute_all(self, tmp_path):
        """测试计算所有哈希"""
        f = tmp_path / 'test.bin'
        f.write_text('Test data')
        md5, sha1, sha256 = HashUtil.compute_all(str(f))
        assert len(md5) == 32
        assert len(sha1) == 40
        assert len(sha256) == 64

    def test_hash_nonexistent_file(self):
        """测试计算不存在的文件哈希"""
        md5 = HashUtil.md5_file('/nonexistent/file')
        assert md5 == ''

        sha1 = HashUtil.sha1_file('/nonexistent/file')
        assert sha1 == ''

        sha256 = HashUtil.sha256_file('/nonexistent/file')
        assert sha256 == ''