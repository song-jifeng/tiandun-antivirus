#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 扫描器单元测试
"""
import os
import sys
import time
import tempfile
import threading
import pytest
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import FileDiscoverer, Scanner, ScanReport
from engine import ScanMode, ScanCallback, ThreatInfo, ThreatType, ThreatLevel, ScanResult


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def discoverer():
    """创建文件发现器"""
    return FileDiscoverer(max_size_mb=10)


@pytest.fixture
def temp_dir_with_files(tmp_path):
    """创建包含测试文件的临时目录"""
    # 创建一些可扫描文件
    for i in range(5):
        f = tmp_path / f'test_file_{i}.exe'
        f.write_bytes(b'MZ' + b'\x00' * 100)

    # 创建一些不可扫描文件（超大）
    large_file = tmp_path / 'large_file.bin'
    large_file.write_bytes(b'\x00' * (11 * 1024 * 1024))  # 11MB > 10MB limit

    # 创建空文件
    empty_file = tmp_path / 'empty.txt'
    empty_file.write_text('')

    # 创建子目录
    sub_dir = tmp_path / 'subdir'
    sub_dir.mkdir()
    for i in range(3):
        f = sub_dir / f'sub_file_{i}.dll'
        f.write_bytes(b'MZ' + b'\x00' * 50)

    return tmp_path


# ============================================================
# FileDiscoverer 测试
# ============================================================

class TestFileDiscoverer:
    """测试文件发现器"""

    def test_discover_single_file(self, discoverer, tmp_path):
        """测试发现单个文件"""
        f = tmp_path / 'test.exe'
        f.write_bytes(b'MZ' + b'\x00' * 100)
        files = discoverer.discover([str(f)])
        assert len(files) == 1
        assert files[0] == str(f)

    def test_discover_directory(self, discoverer, temp_dir_with_files):
        """测试发现目录中的文件"""
        files = discoverer.discover([str(temp_dir_with_files)])
        # 5 个 .exe + 3 个 .dll = 8 个可扫描文件
        # 超大文件和空文件应被跳过
        assert len(files) == 8, f"应发现 8 个文件, 发现 {len(files)}"

    def test_discover_with_extension_filter(self, discoverer, temp_dir_with_files):
        """测试使用扩展名过滤"""
        files = discoverer.discover(
            [str(temp_dir_with_files)],
            extensions={'.dll'}
        )
        assert len(files) == 3, f"应发现 3 个 .dll 文件, 发现 {len(files)}"
        for f in files:
            assert f.endswith('.dll')

    def test_discover_nonexistent_path(self, discoverer):
        """测试发现不存在的路径"""
        files = discoverer.discover(['/nonexistent/path'])
        assert len(files) == 0

    def test_discover_with_callback(self, discoverer, temp_dir_with_files):
        """测试发现文件时回调"""
        discovered = []

        def callback(filepath):
            discovered.append(filepath)

        files = discoverer.discover(
            [str(temp_dir_with_files)],
            file_callback=callback
        )
        assert len(discovered) == len(files)
        assert discovered == files

    def test_discover_iter(self, discoverer, temp_dir_with_files):
        """测试迭代器模式发现文件"""
        count = 0
        for filepath in discoverer.discover_iter([str(temp_dir_with_files)]):
            count += 1
            assert os.path.isfile(filepath)
        assert count == 8, f"迭代器应产出 8 个文件, 产出 {count}"

    def test_cancel_discovery(self, discoverer, tmp_path):
        """测试取消发现"""
        # 创建大量文件，确保发现不会瞬间完成
        for i in range(500):
            f = tmp_path / f'file_{i}.exe'
            f.write_bytes(b'MZ' + b'\x00' * 10)

        # 启动发现，立即取消
        discoverer.cancel()
        files = discoverer.discover([str(tmp_path)])

        # 取消后应发现 0 个文件
        assert len(files) == 0, "取消后不应发现任何文件"

    def test_discover_count(self, discoverer, temp_dir_with_files):
        """测试已发现文件计数"""
        assert discoverer.discovered_count == 0
        discoverer.discover([str(temp_dir_with_files)])
        assert discoverer.discovered_count == 8

    def test_should_scan(self, discoverer, tmp_path):
        """测试 _should_scan 方法"""
        # 可扫描文件
        f = tmp_path / 'test.exe'
        f.write_bytes(b'MZ' + b'\x00' * 100)
        assert discoverer._should_scan(str(f), discoverer.SCAN_EXTENSIONS) is True

        # 超大文件
        large = tmp_path / 'large.bin'
        large.write_bytes(b'\x00' * (11 * 1024 * 1024))
        assert discoverer._should_scan(str(large), discoverer.SCAN_EXTENSIONS) is False

        # 空文件
        empty = tmp_path / 'empty.txt'
        empty.write_text('')
        # 空文件，size==0，应返回 False
        assert discoverer._should_scan(str(empty), discoverer.SCAN_EXTENSIONS) is False

        # 无扩展名文件
        no_ext = tmp_path / 'no_extension'
        no_ext.write_text('content')
        assert discoverer._should_scan(str(no_ext), discoverer.SCAN_EXTENSIONS) is True

    def test_discover_non_recursive(self, discoverer, temp_dir_with_files):
        """测试非递归发现"""
        files = discoverer.discover([str(temp_dir_with_files)], recursive=False)
        # 非递归只发现顶层文件（5个 .exe）
        assert len(files) == 5, f"非递归应发现 5 个文件, 发现 {len(files)}"


# ============================================================
# ScanReport 测试
# ============================================================

class TestScanReport:
    """测试扫描报告"""

    def test_report_initialization(self):
        """测试报告初始化"""
        report = ScanReport(ScanMode.QUICK)
        assert report.scan_mode == ScanMode.QUICK
        assert report.total_files == 0
        assert report.scanned_files == 0
        assert report.threat_count == 0
        assert len(report.errors) == 0

    def test_report_add_threat(self):
        """测试添加威胁"""
        report = ScanReport()
        threat = ThreatInfo('/path/to/malware.exe', ThreatType.VIRUS, 'Test.Virus')
        report.add_threat(threat)
        assert report.threat_count == 1
        assert len(report.threats_found) == 1

    def test_report_add_error(self):
        """测试添加错误"""
        report = ScanReport()
        report.add_error('/path/to/file.exe', 'Permission denied')
        assert len(report.errors) == 1
        assert report.errors[0]['file'] == '/path/to/file.exe'

    def test_report_finish(self):
        """测试完成报告"""
        report = ScanReport()
        time.sleep(0.01)
        report.finish()
        assert report.end_time > 0
        assert report.duration > 0

    def test_report_duration(self):
        """测试报告持续时间"""
        report = ScanReport()
        start = report.start_time
        time.sleep(0.05)
        report.finish()
        assert report.duration >= 0.05

    def test_report_clean_files(self):
        """测试干净文件计数"""
        report = ScanReport()
        report.scanned_files = 10
        report.add_threat(ThreatInfo('/test.exe', ThreatType.VIRUS, 'Test'))
        report.add_threat(ThreatInfo('/test2.exe', ThreatType.VIRUS, 'Test'))
        assert report.clean_files == 8

    def test_report_to_dict(self):
        """测试转换为字典"""
        report = ScanReport(ScanMode.FULL)
        report.total_files = 100
        report.scanned_files = 80
        report.add_threat(ThreatInfo('/test.exe', ThreatType.VIRUS, 'Test.Virus'))
        report.finish()

        d = report.to_dict()
        assert d['scan_mode'] == ScanMode.FULL
        assert d['total_files'] == 100
        assert d['scanned_files'] == 80
        assert d['threats_found'] == 1
        assert len(d['threats']) == 1

    def test_report_to_json(self):
        """测试转换为 JSON"""
        report = ScanReport()
        report.total_files = 50
        report.finish()
        json_str = report.to_json()
        assert '"total_files": 50' in json_str

    def test_report_summary(self):
        """测试摘要生成"""
        report = ScanReport(ScanMode.QUICK)
        report.total_files = 10
        report.scanned_files = 10
        report.add_threat(ThreatInfo('/test.exe', ThreatType.VIRUS, 'Test.Virus'))
        report.finish()

        summary = report.summary()
        assert '天盾 Antivirus' in summary
        assert 'Test.Virus' in summary
        assert '1' in summary  # threat count


# ============================================================
# Scanner 基本功能测试
# ============================================================

class TestScanner:
    """测试扫描器基本功能"""

    def test_scanner_initialization(self):
        """测试扫描器初始化"""
        s = Scanner()
        assert len(s.engines) > 0, "扫描器应加载至少一个引擎"

    def test_scanner_engines_loaded(self):
        """测试引擎加载"""
        s = Scanner()
        engine_names = [e.name for e in s.engines]
        assert 'signature' in engine_names, "签名引擎应被加载"
        assert 'HeuristicEngine' in engine_names, "启发式引擎应被加载"

    def test_scan_file_nonexistent(self):
        """测试扫描不存在的文件"""
        s = Scanner()
        threats = s.scan_file('/nonexistent/file.exe')
        assert len(threats) == 0

    def test_scan_file_clean(self, tmp_path):
        """测试扫描干净文件"""
        s = Scanner()
        clean_file = tmp_path / 'clean.txt'
        clean_file.write_text('This is a clean file')
        threats = s.scan_file(str(clean_file))
        assert len(threats) == 0

    def test_scan_cancelled(self, tmp_path):
        """测试取消扫描"""
        s = Scanner()
        callback = ScanCallback()
        callback.cancel()

        f = tmp_path / 'test.exe'
        f.write_bytes(b'MZ' + b'\x00' * 100)
        threats = s.scan_file(str(f), callback)
        assert len(threats) == 0

    def test_get_engine_stats(self):
        """测试获取引擎统计"""
        s = Scanner()
        stats = s.get_engine_stats()
        assert len(stats) > 0
        for stat in stats:
            assert 'name' in stat
            assert 'enabled' in stat
            assert 'stats' in stat


# ============================================================
# ScanCallback 测试
# ============================================================

class TestScanCallback:
    """测试扫描回调"""

    def test_callback_initialization(self):
        """测试回调初始化"""
        cb = ScanCallback()
        assert cb.on_file_start is None
        assert cb.on_file_complete is None
        assert cb.on_threat_found is None
        assert cb.on_progress is None
        assert cb.on_error is None
        assert cb.is_cancelled() is False

    def test_callback_cancel(self):
        """测试取消回调"""
        cb = ScanCallback()
        cb.cancel()
        assert cb.is_cancelled() is True

    def test_callback_custom_handlers(self):
        """测试自定义处理器"""
        cb = ScanCallback()
        results = []

        def on_file_start(path):
            results.append(('start', path))

        def on_threat_found(threat):
            results.append(('threat', threat.threat_name))

        cb.on_file_start = on_file_start
        cb.on_threat_found = on_threat_found

        cb.on_file_start('/test.exe')
        cb.on_threat_found(ThreatInfo('/test.exe', ThreatType.VIRUS, 'Test.Virus'))

        assert len(results) == 2
        assert results[0] == ('start', '/test.exe')
        assert results[1] == ('threat', 'Test.Virus')