#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 特征码引擎单元测试
"""
import os
import sys
import tempfile
import pytest
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.signatures.signature_engine import (
    SignatureEngine, BytePattern, YaraPattern
)
from engine.signatures import ALL_SIGNATURES
from engine.signatures.signatures import SIGNATURE_COUNT
from engine import ThreatInfo, ThreatType, ThreatLevel, ScanResult, HashUtil


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def engine():
    """创建空特征码引擎"""
    e = SignatureEngine('test_signature', enabled=True)
    e.clear_signatures()
    return e


@pytest.fixture
def eicar_file():
    """创建 EICAR 测试文件 - 可能被 Windows Defender 拦截"""
    eicar_str = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    f = tempfile.NamedTemporaryFile(delete=False, suffix='.com', mode='wb')
    f.write(eicar_str)
    fpath = f.name
    f.close()
    # 检查文件是否可读（可能被 Windows Defender 拦截）
    try:
        with open(fpath, 'rb') as f2:
            f2.read()
        yield fpath
    except OSError:
        # Windows Defender 拦截了 EICAR 文件，跳过测试
        yield None
    finally:
        try:
            os.unlink(fpath)
        except Exception:
            pass


# ============================================================
# BytePattern 测试
# ============================================================

class TestBytePattern:
    """测试 BytePattern 匹配"""

    def test_simple_hex_pattern(self):
        """测试简单十六进制模式匹配"""
        # 匹配 'ABC' 的十六进制模式
        pattern = BytePattern('41 42 43')
        data = b'...ABC...'
        result = pattern.match(data)
        assert result is not None
        assert data[result:result+3] == b'ABC'

    def test_pattern_with_wildcards(self):
        """测试带通配符的模式匹配"""
        pattern = BytePattern('41 ?? 43')
        data = b'...A?C...'
        # 'A' = 0x41, '?' = 0x3F, 'C' = 0x43
        # 所以模式 '41 ?? 43' 匹配 'A' + any + 'C'
        test_data = b'\x00\x00\x41\x42\x43\x00\x00'
        result = pattern.match(test_data)
        assert result is not None
        assert result == 2

    def test_pattern_no_match(self):
        """测试不匹配的情况"""
        pattern = BytePattern('DE AD BE EF')
        data = b'\x00\x01\x02\x03\x04\x05'
        result = pattern.match(data)
        assert result is None

    def test_pattern_with_offset(self):
        """测试带偏移的模式匹配"""
        pattern = BytePattern('FF', offset=5)
        data = b'\x00' * 5 + b'\xFF' + b'\x00' * 5
        result = pattern.match(data)
        assert result is not None

    def test_pattern_empty(self):
        """测试空模式"""
        pattern = BytePattern('')
        result = pattern.match(b'data')
        assert result is None

    def test_pattern_all_wildcards(self):
        """测试全通配符模式"""
        pattern = BytePattern('?? ?? ??')
        data = b'\x01\x02\x03'
        result = pattern.match(data)
        assert result is not None

    def test_pattern_hex_string_without_spaces(self):
        """测试无空格十六进制字符串"""
        pattern = BytePattern('909090')
        data = b'\x00\x90\x90\x90\x00'
        result = pattern.match(data)
        assert result is not None
        assert result == 1

    def test_repr(self):
        """测试 __repr__"""
        pattern = BytePattern('41 42', offset=10)
        rep = repr(pattern)
        assert '41 42' in rep
        assert 'offset=10' in rep


# ============================================================
# YaraPattern 测试
# ============================================================

class TestYaraPattern:
    """测试 YaraPattern"""

    def test_parse_hex_rule(self):
        """测试解析十六进制规则"""
        rule_source = 'rule test { strings: $a = { 41 42 43 } condition: $a }'
        yp = YaraPattern('test_rule', rule_source)
        assert len(yp.compiled_patterns) > 0

    def test_yara_match(self):
        """测试 YARA 规则匹配"""
        rule_source = 'rule test { strings: $a = { 41 42 43 } condition: $a }'
        yp = YaraPattern('test_rule', rule_source)
        result = yp.match(b'\x00\x41\x42\x43\x00')
        assert result is True

    def test_yara_no_match(self):
        """测试 YARA 规则不匹配"""
        rule_source = 'rule test { strings: $a = { DE AD BE EF } condition: $a }'
        yp = YaraPattern('test_rule', rule_source)
        result = yp.match(b'\x00\x01\x02\x03')
        assert result is False


# ============================================================
# SignatureEngine 测试
# ============================================================

class TestSignatureEngine:
    """测试特征码引擎"""

    def test_engine_initialization(self):
        """测试引擎初始化"""
        e = SignatureEngine('test', enabled=True)
        assert e.name == 'test'
        assert e.enabled is True
        assert len(e.md5_db) == 0
        assert len(e.sha1_db) == 0
        assert len(e.sha256_db) == 0

    def test_load_md5_signatures(self, engine):
        """测试加载 MD5 签名"""
        test_sigs = {
            'd41d8cd98f00b204e9800998ecf8427e': {
                'name': 'Test.Empty',
                'type': ThreatType.VIRUS,
                'level': ThreatLevel.MEDIUM,
            },
            'invalid_md5': {  # 无效 MD5 应该被跳过
                'name': 'Invalid',
                'type': ThreatType.UNKNOWN,
            }
        }
        count = engine.load_md5_signatures(test_sigs)
        assert count == 1, "应该只加载 1 个有效 MD5 签名"
        assert 'd41d8cd98f00b204e9800998ecf8427e' in engine.md5_db

    def test_load_sha1_signatures(self, engine):
        """测试加载 SHA1 签名"""
        test_sigs = {
            'da39a3ee5e6b4b0d3255bfef95601890afd80709': {
                'name': 'Test.SHA1',
                'type': ThreatType.TROJAN,
            },
            'short': {
                'name': 'Invalid',
            }
        }
        count = engine.load_sha1_signatures(test_sigs)
        assert count == 1, "应该只加载 1 个有效 SHA1 签名"

    def test_load_sha256_signatures(self, engine):
        """测试加载 SHA256 签名"""
        test_sigs = {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': {
                'name': 'Test.SHA256',
                'type': ThreatType.RANSOMWARE,
            },
        }
        count = engine.load_sha256_signatures(test_sigs)
        assert count == 1, "应该加载 1 个有效 SHA256 签名"

    def test_load_byte_patterns(self, engine):
        """测试加载字节序列特征"""
        patterns = [
            {
                'pattern': '41 42 43',
                'name': 'Test.ABC',
                'type': ThreatType.VIRUS,
                'level': ThreatLevel.MEDIUM,
                'offset': 0,
            },
            {
                'pattern': 'DE AD BE EF',
                'name': 'Test.DeadBeef',
                'type': ThreatType.BACKDOOR,
                'level': ThreatLevel.HIGH,
                'offset': -1,
            },
        ]
        count = engine.load_byte_patterns(patterns)
        assert count == 2
        assert len(engine.head_sigs) == 1  # offset=0 是头部
        assert len(engine.tail_sigs) == 1  # offset=-1 是尾部

    def test_load_yara_rules(self, engine):
        """测试加载 YARA 规则"""
        rules = [
            {
                'rule_id': 'test_rule_1',
                'rule_source': 'rule test { strings: $a = { 41 42 43 } condition: $a }',
                'name': 'Test.Rule',
                'type': ThreatType.HEURISTIC,
            }
        ]
        count = engine.load_yara_rules(rules)
        assert count == 1
        assert len(engine.yara_rules) == 1

    def test_clear_signatures(self, engine):
        """测试清除签名"""
        engine.load_md5_signatures({
            'd41d8cd98f00b204e9800998ecf8427e': {
                'name': 'Test',
                'type': ThreatType.VIRUS,
            }
        })
        assert len(engine.md5_db) == 1
        engine.clear_signatures()
        assert len(engine.md5_db) == 0
        assert len(engine.sha1_db) == 0
        assert len(engine.sha256_db) == 0

    def test_get_signature_count(self, engine):
        """测试获取签名数量统计"""
        stats = engine.get_signature_count()
        assert 'md5' in stats
        assert 'sha1' in stats
        assert 'sha256' in stats
        assert 'total' in stats
        assert stats['total'] == 0

    def test_scan_clean_file(self, engine, tmp_path):
        """测试扫描干净文件"""
        clean_file = tmp_path / 'clean.txt'
        clean_file.write_text('This is a clean file')
        result = engine.scan(str(clean_file))
        assert result is None, "干净文件不应被检测为威胁"

    def test_scan_nonexistent_file(self, engine):
        """测试扫描不存在的文件"""
        result = engine.scan('C:/nonexistent_file_12345.exe')
        assert result is None

    def test_md5_validation(self, engine):
        """测试 MD5 哈希验证逻辑"""
        # 有效 MD5 应被加载
        engine.load_md5_signatures({
            'd41d8cd98f00b204e9800998ecf8427e': {'name': 'Valid', 'type': ThreatType.VIRUS}
        })
        assert 'd41d8cd98f00b204e9800998ecf8427e' in engine.md5_db

        # 无效 MD5 应被跳过
        engine.load_md5_signatures({
            'not_a_valid_md5_hash_value': {'name': 'Invalid', 'type': ThreatType.VIRUS}
        })
        assert 'not_a_valid_md5_hash_value' not in engine.md5_db

    def test_sha1_validation(self, engine):
        """测试 SHA1 哈希验证逻辑"""
        engine.load_sha1_signatures({
            'da39a3ee5e6b4b0d3255bfef95601890afd80709': {'name': 'Valid', 'type': ThreatType.TROJAN}
        })
        assert 'da39a3ee5e6b4b0d3255bfef95601890afd80709' in engine.sha1_db

        engine.load_sha1_signatures({
            'short': {'name': 'Invalid', 'type': ThreatType.TROJAN}
        })
        assert 'short' not in engine.sha1_db

    def test_sha256_validation(self, engine):
        """测试 SHA256 哈希验证逻辑"""
        valid = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        engine.load_sha256_signatures({
            valid: {'name': 'Valid', 'type': ThreatType.RANSOMWARE}
        })
        assert valid in engine.sha256_db

        engine.load_sha256_signatures({
            'too_short': {'name': 'Invalid', 'type': ThreatType.RANSOMWARE}
        })
        assert 'too_short' not in engine.sha256_db


# ============================================================
# EICAR 检测测试
# ============================================================

class TestEICARDetection:
    """测试 EICAR 测试文件检测

    注意: EICAR 文件可能被 Windows Defender 拦截，
    这种情况下测试会自动跳过。
    """

    def test_eicar_md5_detection(self, engine, eicar_file):
        """通过 MD5 签名检测 EICAR"""
        if eicar_file is None:
            pytest.skip("EICAR 文件被 Windows Defender 拦截")

        # EICAR 测试文件的 MD5
        md5 = HashUtil.md5_file(eicar_file)
        assert md5, "应能计算 MD5"

        # 加载 EICAR 签名到引擎
        engine.load_md5_signatures({
            md5: {
                'name': 'EICAR-Test-File',
                'type': ThreatType.VIRUS,
                'level': ThreatLevel.MEDIUM,
            }
        })

        # 扫描
        result = engine.scan(eicar_file)
        assert result is not None, "EICAR 文件应被检出"
        assert result.threat_name == 'EICAR-Test-File'

    def test_eicar_hash_util(self, eicar_file):
        """测试 HashUtil 能正确计算 EICAR 文件哈希"""
        if eicar_file is None:
            pytest.skip("EICAR 文件被 Windows Defender 拦截")

        md5 = HashUtil.md5_file(eicar_file)
        sha1 = HashUtil.sha1_file(eicar_file)
        sha256 = HashUtil.sha256_file(eicar_file)

        assert len(md5) == 32, f"MD5 应为 32 位十六进制, 得到 {len(md5)}"
        assert len(sha1) == 40, f"SHA1 应为 40 位十六进制"
        assert len(sha256) == 64, f"SHA256 应为 64 位十六进制"

    def test_eicar_byte_pattern(self, engine, eicar_file):
        """通过字节模式检测 EICAR"""
        if eicar_file is None:
            pytest.skip("EICAR 文件被 Windows Defender 拦截")

        # EICAR 文件包含 'X5O' 开头
        patterns = [
            {
                'pattern': '5835 4F21 50',
                'name': 'EICAR.BytePattern',
                'type': ThreatType.VIRUS,
                'level': ThreatLevel.MEDIUM,
                'offset': 0,
            }
        ]
        engine.load_byte_patterns(patterns)
        result = engine.scan(eicar_file)
        assert result is not None, "EICAR 字节模式应被检出"

    def test_scan_empty_file(self, engine, tmp_path):
        """测试扫描空文件（应跳过）"""
        empty = tmp_path / 'empty.txt'
        empty.write_text('')
        result = engine.scan(str(empty))
        assert result is None, "空文件不应被检测"


# ============================================================
# 签名数据库加载测试
# ============================================================

class TestSignatureDatabase:
    """测试签名数据库加载"""

    def test_signatures_module_has_expected_data(self):
        """测试签名模块包含预期数据"""
        # 检查主要签名模块是否存在
        assert isinstance(ALL_SIGNATURES, dict)
        assert len(ALL_SIGNATURES) > 0

    def test_signature_count(self):
        """测试签名计数"""
        assert SIGNATURE_COUNT > 0

    def test_all_signatures_have_names(self):
        """测试所有签名都有名称"""
        unnamed = [k for k, v in ALL_SIGNATURES.items() if not v.get('name')]
        assert len(unnamed) == 0, f"发现 {len(unnamed)} 个未命名签名"

    def test_all_signatures_have_types(self):
        """测试所有签名都有类型"""
        untyped = [k for k, v in ALL_SIGNATURES.items() if not v.get('type')]
        assert len(untyped) == 0, f"发现 {len(untyped)} 个无类型签名"