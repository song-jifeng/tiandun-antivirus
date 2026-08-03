#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 扩展测试套件
包含更多详细的测试用例，覆盖所有模块
"""
import os
import sys
import time
import json
import unittest
from typing import Dict, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestConstants(unittest.TestCase):
    """测试常量定义"""

    def test_scan_result_values(self):
        from engine import ScanResult
        self.assertEqual(ScanResult.CLEAN, 0)
        self.assertEqual(ScanResult.SUSPICIOUS, 1)
        self.assertEqual(ScanResult.MALICIOUS, 2)
        self.assertEqual(ScanResult.ERROR, -1)
        self.assertEqual(ScanResult.UNKNOWN, -2)

    def test_threat_level_values(self):
        from engine import ThreatLevel
        self.assertEqual(ThreatLevel.CRITICAL, 5)
        self.assertEqual(ThreatLevel.HIGH, 4)
        self.assertEqual(ThreatLevel.MEDIUM, 3)
        self.assertEqual(ThreatLevel.LOW, 2)
        self.assertEqual(ThreatLevel.INFO, 1)
        self.assertEqual(ThreatLevel.NONE, 0)

    def test_threat_type_values(self):
        from engine import ThreatType
        self.assertEqual(ThreatType.VIRUS, 'virus')
        self.assertEqual(ThreatType.WORM, 'worm')
        self.assertEqual(ThreatType.TROJAN, 'trojan')
        self.assertEqual(ThreatType.RANSOMWARE, 'ransomware')
        self.assertEqual(ThreatType.SPYWARE, 'spyware')
        self.assertEqual(ThreatType.ROOTKIT, 'rootkit')
        self.assertEqual(ThreatType.KEYLOGGER, 'keylogger')
        self.assertEqual(ThreatType.MINER, 'miner')
        self.assertEqual(ThreatType.HEURISTIC, 'heuristic')
        self.assertEqual(ThreatType.BEHAVIOR, 'behavior')

    def test_scan_mode_values(self):
        from engine import ScanMode
        self.assertEqual(ScanMode.QUICK, 'quick')
        self.assertEqual(ScanMode.FULL, 'full')
        self.assertEqual(ScanMode.CUSTOM, 'custom')
        self.assertEqual(ScanMode.MEMORY, 'memory')
        self.assertEqual(ScanMode.BOOT, 'boot')


class TestThreatInfoExtended(unittest.TestCase):
    """测试ThreatInfo扩展功能"""

    def setUp(self):
        from engine import ThreatInfo, ThreatType, ThreatLevel, ScanResult
        self.threat = ThreatInfo(
            'C:\\test\\malware.exe',
            ThreatType.TROJAN,
            'Test.Trojan.Generic',
            'test_engine',
            ThreatLevel.HIGH,
            ScanResult.MALICIOUS
        )

    def test_initialization(self):
        self.assertEqual(self.threat.file_path, 'C:\\test\\malware.exe')
        self.assertEqual(self.threat.file_name, 'malware.exe')
        self.assertEqual(self.threat.threat_name, 'Test.Trojan.Generic')
        self.assertEqual(self.threat.scan_engine, 'test_engine')
        self.assertEqual(self.threat.threat_level, 4)
        self.assertEqual(self.threat.result, 2)
        self.assertFalse(self.threat.processed)

    def test_serialization_roundtrip(self):
        data = self.threat.to_dict()
        from engine import ThreatInfo
        restored = ThreatInfo.from_dict(data)
        self.assertEqual(restored.file_path, self.threat.file_path)
        self.assertEqual(restored.threat_name, self.threat.threat_name)
        self.assertEqual(restored.threat_level, self.threat.threat_level)
        self.assertEqual(restored.scan_engine, self.threat.scan_engine)
        self.assertEqual(restored.result, self.threat.result)

    def test_dict_output(self):
        data = self.threat.to_dict()
        self.assertIn('file_path', data)
        self.assertIn('file_name', data)
        self.assertIn('threat_name', data)
        self.assertIn('threat_type', data)
        self.assertIn('threat_level', data)
        self.assertIn('result', data)
        self.assertIn('timestamp', data)
        self.assertIn('scan_engine', data)

    def test_details_storage(self):
        self.threat.details = {'key': 'value', 'score': 95}
        data = self.threat.to_dict()
        self.assertEqual(data['details']['key'], 'value')
        self.assertEqual(data['details']['score'], 95)


class TestHashUtilExtended(unittest.TestCase):
    """测试哈希工具扩展"""

    def test_empty_file(self):
        import tempfile
        from engine import HashUtil
        with tempfile.NamedTemporaryFile(delete=False) as f:
            fpath = f.name
        try:
            md5 = HashUtil.md5_file(fpath)
            sha1 = HashUtil.sha1_file(fpath)
            sha256 = HashUtil.sha256_file(fpath)
            # 空文件的MD5
            self.assertEqual(md5, 'd41d8cd98f00b204e9800998ecf8427e')
            self.assertEqual(len(sha1), 40)
            self.assertEqual(len(sha256), 64)
        finally:
            os.unlink(fpath)

    def test_small_file(self):
        import tempfile
        from engine import HashUtil
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'Hello, World!')
            fpath = f.name
        try:
            md5 = HashUtil.md5_file(fpath)
            self.assertEqual(md5, '65a8e27d8879283831b664bd8b7f0ad4')
        finally:
            os.unlink(fpath)

    def test_binary_file(self):
        import tempfile
        from engine import HashUtil
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(os.urandom(1024))
            fpath = f.name
        try:
            md5 = HashUtil.md5_file(fpath)
            self.assertEqual(len(md5), 32)
            self.assertTrue(all(c in '0123456789abcdef' for c in md5))
        finally:
            os.unlink(fpath)

    def test_large_file(self):
        import tempfile
        from engine import HashUtil
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(os.urandom(1024 * 1024))
            fpath = f.name
        try:
            md5 = HashUtil.md5_file(fpath)
            self.assertEqual(len(md5), 32)
        finally:
            os.unlink(fpath)

    def test_compute_all(self):
        import tempfile
        from engine import HashUtil
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test data')
            fpath = f.name
        try:
            md5, sha1, sha256 = HashUtil.compute_all(fpath)
            self.assertEqual(len(md5), 32)
            self.assertEqual(len(sha1), 40)
            self.assertEqual(len(sha256), 64)
        finally:
            os.unlink(fpath)


class TestConfigManagerExtended(unittest.TestCase):
    """测试配置管理器扩展"""

    def setUp(self):
        from engine.config import ConfigManager
        self.config = ConfigManager()

    def test_default_values(self):
        self.assertEqual(self.config.get('general.language'), 'zh_CN')
        self.assertFalse(self.config.get('general.auto_start'))
        self.assertTrue(self.config.get('general.show_notifications'))
        self.assertTrue(self.config.get('realtime.enabled'))
        self.assertTrue(self.config.get('realtime.file_monitor'))
        self.assertEqual(self.config.get('scan.thread_count'), 4)
        self.assertEqual(self.config.get('scan.max_file_size_mb'), 200)
        self.assertEqual(self.config.get('cloud.cache_size'), 50000)

    def test_nested_set_get(self):
        self.config.set('test.nested.deep.value', 42)
        self.assertEqual(self.config.get('test.nested.deep.value'), 42)

    def test_list_config(self):
        quick_paths = self.config.get('scan.quick_paths')
        self.assertIsInstance(quick_paths, list)
        self.assertTrue(len(quick_paths) > 0)

    def test_boolean_config(self):
        self.config.set('test.bool', True)
        self.assertTrue(self.config.get('test.bool'))
        self.config.set('test.bool', False)
        self.assertFalse(self.config.get('test.bool'))

    def test_integer_config(self):
        self.config.set('test.int', 123)
        self.assertEqual(self.config.get('test.int'), 123)

    def test_string_config(self):
        self.config.set('test.str', 'hello')
        self.assertEqual(self.config.get('test.str'), 'hello')

    def test_get_all(self):
        all_config = self.config.get_all()
        self.assertIn('general', all_config)
        self.assertIn('realtime', all_config)
        self.assertIn('scan', all_config)
        self.assertIn('cloud', all_config)
        self.assertIn('hips', all_config)
        self.assertIn('self_protection', all_config)
        self.assertIn('cleanup', all_config)
        self.assertIn('firewall', all_config)
        self.assertIn('logging', all_config)


class TestStringUtilExtended(unittest.TestCase):
    """测试字符串工具扩展"""

    def setUp(self):
        from engine.common import StringUtil
        self.util = StringUtil

    def test_hexdump(self):
        result = self.util.hexdump(b'Hello World!')
        self.assertIn('48 65 6c 6c 6f', result)
        self.assertIn('Hello World', result)

    def test_extract_strings(self):
        data = b'hello\x00world\x00test\x00\x00\x00abc'
        strings = self.util.extract_strings(data, min_length=3)
        self.assertIn('hello', strings)
        self.assertIn('world', strings)
        self.assertIn('test', strings)
        self.assertIn('abc', strings)

    def test_extract_strings_min_length(self):
        data = b'ab\x00cd\x00efg\x00hijk'
        strings = self.util.extract_strings(data, min_length=4)
        self.assertNotIn('ab', strings)
        self.assertIn('hijk', strings)

    def test_mask_sensitive(self):
        self.assertEqual(self.util.mask_sensitive('password123'), 'pass*******')
        self.assertEqual(self.util.mask_sensitive('ab', 1), 'a*')
        self.assertEqual(self.util.mask_sensitive('a', 1), '*')

    def test_truncate(self):
        text = '这是一段很长的文本，需要被截断'
        result = self.util.truncate(text, max_length=10)
        self.assertEqual(len(result), 10)
        self.assertTrue(result.endswith('...'))

        short = '短文本'
        self.assertEqual(self.util.truncate(short, max_length=10), short)


class TestTimeUtilExtended(unittest.TestCase):
    """测试时间工具扩展"""

    def setUp(self):
        from engine.common import TimeUtil
        self.util = TimeUtil

    def test_now(self):
        now = self.util.now()
        self.assertGreater(now, 1700000000)

    def test_now_str(self):
        now_str = self.util.now_str()
        self.assertIn('2026', now_str)
        self.assertIn('-', now_str)
        self.assertIn(':', now_str)

    def test_format_duration(self):
        self.assertIn('秒', self.util.format_duration(30))
        self.assertIn('分钟', self.util.format_duration(120))
        self.assertIn('小时', self.util.format_duration(7200))
        self.assertIn('天', self.util.format_duration(172800))

    def test_time_ago(self):
        now = time.time()
        self.assertEqual(self.util.time_ago(now), '刚刚')
        self.assertIn('分钟前', self.util.time_ago(now - 300))
        self.assertIn('小时前', self.util.time_ago(now - 7200))
        self.assertIn('天前', self.util.time_ago(now - 172800))
        self.assertIn('个月前', self.util.time_ago(now - 7776000))
        self.assertIn('年前', self.util.time_ago(now - 31536000))


class TestPathUtilExtended(unittest.TestCase):
    """测试路径工具扩展"""

    def setUp(self):
        from engine.common import PathUtil
        self.util = PathUtil

    def test_normalize(self):
        path = self.util.normalize('C:/Windows\\System32')
        self.assertIn('Windows', path)
        self.assertIn('System32', path)

    def test_get_drives(self):
        drives = self.util.get_drives()
        self.assertTrue(len(drives) > 0)
        if sys.platform == 'win32':
            self.assertIn('C:\\', drives)

    def test_get_common_dirs(self):
        dirs = self.util.get_common_dirs()
        self.assertIsInstance(dirs, list)

    def test_get_desktop_path(self):
        desktop = self.util.get_desktop_path()
        self.assertTrue('Desktop' in desktop or '桌面' in desktop)

    def test_get_startup_paths(self):
        paths = self.util.get_startup_paths()
        self.assertTrue(len(paths) > 0)


class TestFileUtilExtended(unittest.TestCase):
    """测试文件工具扩展"""

    def setUp(self):
        from engine.common import FileUtil
        self.util = FileUtil

    def test_get_size_str(self):
        self.assertEqual(self.util.get_size_str(0), '0.0 B')
        self.assertEqual(self.util.get_size_str(1024), '1.0 KB')
        self.assertEqual(self.util.get_size_str(1048576), '1.0 MB')
        self.assertEqual(self.util.get_size_str(1073741824), '1.0 GB')

    def test_get_time_str(self):
        from datetime import datetime
        now = time.time()
        time_str = self.util.get_time_str(now)
        self.assertIn('2026', time_str)

    def test_is_binary(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('This is a text file')
            fpath = f.name
        try:
            self.assertFalse(self.util.is_binary(fpath))
        finally:
            os.unlink(fpath)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'\x00\x01\x02\x03')
            fpath = f.name
        try:
            self.assertTrue(self.util.is_binary(fpath))
        finally:
            os.unlink(fpath)


class TestVersionUtil(unittest.TestCase):
    """测试版本工具"""

    def test_version_parse(self):
        from engine.common import Version
        v = Version.parse('1.2.3.4')
        self.assertEqual(v, (1, 2, 3, 4))
        v = Version.parse('2.0.1')
        self.assertEqual(v, (2, 0, 1))

    def test_version_compare(self):
        from engine.common import Version
        self.assertEqual(Version.compare('1.0.0', '1.0.0'), 0)
        self.assertEqual(Version.compare('2.0.0', '1.0.0'), 1)
        self.assertEqual(Version.compare('1.0.0', '2.0.0'), -1)
        self.assertEqual(Version.compare('1.1.0', '1.0.9'), 1)
        self.assertEqual(Version.compare('1.0.0.1', '1.0.0'), 1)


class TestSystemInfo(unittest.TestCase):
    """测试系统信息"""

    def test_get_all(self):
        from engine.common import SystemInfo
        info = SystemInfo.get_all()
        self.assertIn('os', info)
        self.assertIn('cpu', info)
        self.assertIn('memory', info)
        self.assertIn('disk', info)

    def test_get_os_info(self):
        from engine.common import SystemInfo
        os_info = SystemInfo.get_os_info()
        self.assertIn('system', os_info)
        self.assertIn('release', os_info)

    def test_get_memory_info(self):
        from engine.common import SystemInfo
        mem = SystemInfo.get_memory_info()
        self.assertIn('total', mem)
        self.assertGreater(mem['total'], 0)


class TestScanReport(unittest.TestCase):
    """测试扫描报告"""

    def test_create_report(self):
        from scanner import ScanReport
        from engine import ScanMode
        report = ScanReport(ScanMode.QUICK)
        self.assertEqual(report.scan_mode, 'quick')
        self.assertGreater(report.start_time, 0)

    def test_add_threat(self):
        from scanner import ScanReport
        from engine import ThreatInfo, ThreatType, ThreatLevel, ScanResult
        report = ScanReport()
        threat = ThreatInfo('test.txt', ThreatType.TROJAN, 'Test.Trojan',
                          'test', ThreatLevel.HIGH, ScanResult.MALICIOUS)
        report.add_threat(threat)
        self.assertEqual(len(report.threats_found), 1)
        self.assertEqual(report.threat_count, 1)

    def test_report_duration(self):
        from scanner import ScanReport
        report = ScanReport()
        time.sleep(0.1)
        report.finish()
        self.assertGreater(report.duration, 0.05)

    def test_report_to_dict(self):
        from scanner import ScanReport
        from engine import ThreatInfo, ThreatType, ThreatLevel, ScanResult
        report = ScanReport()
        threat = ThreatInfo('test.txt', ThreatType.TROJAN, 'Test.Trojan',
                          'test', ThreatLevel.HIGH, ScanResult.MALICIOUS)
        report.add_threat(threat)
        report.finish()
        data = report.to_dict()
        self.assertIn('scan_mode', data)
        self.assertIn('threats_found', data)
        self.assertIn('duration_seconds', data)
        self.assertEqual(data['threats_found'], 1)


class TestQuarantineExtended(unittest.TestCase):
    """测试隔离区扩展功能"""

    def test_quarantine_structure(self):
        try:
            from cleanup.quarantine import QuarantineManager
            qm = QuarantineManager()
            stats = qm.get_stats()
            self.assertIn('total_items', stats)
            self.assertIn('total_size', stats)
            self.assertIn('max_size_mb', stats)
        except ImportError:
            self.skipTest("QuarantineManager not available")


class TestNetworkUtil(unittest.TestCase):
    """测试网络工具"""

    def test_get_interfaces(self):
        from engine.common import NetworkUtil
        interfaces = NetworkUtil.get_interfaces()
        self.assertIsInstance(interfaces, list)


class TestServiceUtil(unittest.TestCase):
    """测试服务工具"""

    def test_get_services(self):
        from engine.common import ServiceUtil
        services = ServiceUtil.get_services()
        self.assertIsInstance(services, list)


class TestRegistryUtilExtended(unittest.TestCase):
    """测试注册表工具扩展"""

    def test_parse_key(self):
        from engine.common import RegistryUtil
        hive, subkey = RegistryUtil.parse_key(r'HKCU\Software\Test')
        self.assertEqual(hive, 0x80000001)
        self.assertEqual(subkey, r'Software\Test')

        hive, subkey = RegistryUtil.parse_key(r'HKLM\SOFTWARE\Microsoft\Windows')
        self.assertEqual(hive, 0x80000002)
        self.assertEqual(subkey, r'SOFTWARE\Microsoft\Windows')


class TestIntervalTimer(unittest.TestCase):
    """测试定时器"""

    def test_timer_creation(self):
        from engine.common import IntervalTimer
        timer = IntervalTimer(1.0, lambda: None, name='test')
        self.assertEqual(timer.interval, 1.0)
        self.assertEqual(timer.name, 'test')
        timer.stop()

    def test_timer_start_stop(self):
        from engine.common import IntervalTimer
        timer = IntervalTimer(1.0, lambda: None, name='test')
        timer.start()
        self.assertTrue(timer._running)
        timer.stop()
        self.assertFalse(timer._running)


class TestFirewallExtended(unittest.TestCase):
    """测试防火墙扩展"""

    def test_firewall_rule_creation(self):
        try:
            from firewall.firewall_engine import FirewallRule
            rule = FirewallRule('TEST001', '测试规则', 'in', 'block',
                              'tcp', local_port=80)
            self.assertEqual(rule.id, 'TEST001')
            self.assertEqual(rule.name, '测试规则')
            self.assertEqual(rule.action, 'block')
            self.assertEqual(rule.local_port, 80)
            self.assertTrue(rule.enabled)
        except ImportError:
            self.skipTest("FirewallRule not available")

    def test_firewall_rule_to_dict(self):
        try:
            from firewall.firewall_engine import FirewallRule
            rule = FirewallRule('TEST002', 'Test Rule', 'out', 'allow')
            data = rule.to_dict()
            self.assertEqual(data['id'], 'TEST002')
            self.assertEqual(data['name'], 'Test Rule')
            self.assertEqual(data['direction'], 'out')
            self.assertEqual(data['action'], 'allow')
        except ImportError:
            self.skipTest("FirewallRule not available")


class TestHoneypotExtended(unittest.TestCase):
    """测试蜜罐扩展"""

    def test_honeypot_stats(self):
        try:
            from firewall.honeypot import Honeypot
            hp = Honeypot()
            stats = hp.get_stats()
            self.assertIn('honeypot_files', stats)
            self.assertIn('alerts', stats)
            self.assertEqual(stats['alerts'], 0)
        except ImportError:
            self.skipTest("Honeypot not available")


class TestNotifier(unittest.TestCase):
    """测试通知器"""

    def test_notifier_creation(self):
        try:
            from notifier import Notifier
            n = Notifier()
            self.assertIsNotNone(n)
        except ImportError:
            self.skipTest("Notifier not available")


class TestScheduler(unittest.TestCase):
    """测试调度器"""

    def test_scheduler_creation(self):
        try:
            from scheduler import Scheduler
            s = Scheduler()
            self.assertIsNotNone(s)
        except ImportError:
            self.skipTest("Scheduler not available")


class TestFileTypeDetectorExtended(unittest.TestCase):
    """测试文件类型检测扩展"""

    def setUp(self):
        import tempfile
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_exe(self):
        from engine import FileTypeDetector
        ftype = FileTypeDetector.detect('C:\\Windows\\System32\\notepad.exe')
        if os.path.exists('C:\\Windows\\System32\\notepad.exe'):
            self.assertEqual(ftype, 'exe/dll')

    def test_detect_python(self):
        from engine import FileTypeDetector
        ftype = FileTypeDetector.detect(__file__)
        self.assertEqual(ftype, 'text')

    def test_detect_magic_numbers(self):
        from engine import FileTypeDetector
        # 创建带 MZ 魔数的临时文件测试 exe 检测
        exe_path = os.path.join(self.temp_dir, 'test.exe')
        with open(exe_path, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)
        self.assertIn('exe/dll', FileTypeDetector.detect(exe_path))

        zip_path = os.path.join(self.temp_dir, 'test.zip')
        with open(zip_path, 'wb') as f:
            f.write(b'PK\x03\x04' + b'\x00' * 100)
        self.assertIn('zip', FileTypeDetector.detect(zip_path))

        pdf_path = os.path.join(self.temp_dir, 'test.pdf')
        with open(pdf_path, 'wb') as f:
            f.write(b'%PDF' + b'\x00' * 100)
        self.assertIn('pdf', FileTypeDetector.detect(pdf_path))


class TestLoggerExtended(unittest.TestCase):
    """测试日志扩展"""

    def test_logger_singleton(self):
        from engine.logger import Logger
        log1 = Logger('test_singleton')
        log2 = Logger('test_singleton')
        self.assertIs(log1, log2)

    def test_logger_different_names(self):
        from engine.logger import Logger
        log1 = Logger('test_unique_1')
        log2 = Logger('test_unique_2')
        self.assertIsNot(log1, log2)


class TestProcessUtilExtended(unittest.TestCase):
    """测试进程工具扩展"""

    def test_get_process_list(self):
        from engine.common import ProcessUtil
        processes = ProcessUtil.get_process_list()
        self.assertIsInstance(processes, list)
        if processes:
            self.assertIn('pid', processes[0])


class TestSecurityTools(unittest.TestCase):
    """测试安全工具"""

    def test_check_password_strength(self):
        try:
            from tools.security_tools import SecurityTools
            result = SecurityTools.check_password_strength('weak')
            self.assertLess(result['score'], 40)
            self.assertEqual(result['level'], 'very_weak')

            result = SecurityTools.check_password_strength('Str0ng!Pass#2026')
            self.assertGreaterEqual(result['score'], 80)
            self.assertIn(result['level'], ['strong', 'very_strong'])
        except ImportError:
            self.skipTest("SecurityTools not available")


class TestSystemCleanerExtended(unittest.TestCase):
    """测试系统清理扩展"""

    def test_clean_temp_files(self):
        try:
            from tools.system_cleaner import SystemCleaner
            result = SystemCleaner.clean_temp_files(dry_run=True, max_files=50)
            self.assertIn('success', result)
            self.assertIn('cleaned', result)
            self.assertIn('freed_bytes', result)
        except ImportError:
            self.skipTest("SystemCleaner not available")


class TestFileAnalyzerExtended(unittest.TestCase):
    """测试文件分析扩展"""

    def test_analyze_current_file(self):
        try:
            from tools.file_analyzer import FileAnalyzer
            import hashlib
            result = FileAnalyzer.analyze(__file__)
            self.assertIn('name', result)
            self.assertIn('extension', result)
            self.assertIn('size', result)
            self.assertIn('hashes', result)
            self.assertGreater(result['size'], 0)
            self.assertEqual(result['hashes']['md5'],
                           hashlib.md5(open(__file__, 'rb').read()).hexdigest())
        except ImportError:
            self.skipTest("FileAnalyzer not available")


class TestStartupManagerExtended(unittest.TestCase):
    """测试启动项管理扩展"""

    def test_get_startup_items(self):
        try:
            from tools.startup_manager import StartupManager
            items = StartupManager.get_startup_items()
            self.assertIsInstance(items, list)
        except ImportError:
            self.skipTest("StartupManager not available")


class TestProcessExplorerExtended(unittest.TestCase):
    """测试进程浏览器扩展"""

    def test_get_processes(self):
        try:
            from tools.process_explorer import ProcessExplorer
            procs = ProcessExplorer.get_processes()
            self.assertIsInstance(procs, list)
            if procs:
                self.assertIn('pid', procs[0])
                self.assertIn('name', procs[0])
        except ImportError:
            self.skipTest("ProcessExplorer not available")


class TestSystemRepairExtended(unittest.TestCase):
    """测试系统修复扩展"""

    def test_repair_hosts(self):
        try:
            from cleanup.system_repair import SystemRepair
            result = SystemRepair.repair_hosts()
            self.assertIn('success', result)
            self.assertIn('message', result)
        except ImportError:
            self.skipTest("SystemRepair not available")


class TestMalwareRemoverExtended(unittest.TestCase):
    """测试恶意软件清除扩展"""

    def test_remove_structure(self):
        try:
            from cleanup.malware_remover import MalwareRemover
            from engine import ThreatInfo, ThreatType, ThreatLevel, ScanResult
            remover = MalwareRemover()
            threat = ThreatInfo('test.txt', ThreatType.TROJAN, 'Test.Trojan',
                              'test', ThreatLevel.HIGH, ScanResult.MALICIOUS)
            result = remover.remove(threat)
            self.assertIn('success', result)
            self.assertIn('actions', result)
            self.assertIn('errors', result)
        except ImportError:
            self.skipTest("MalwareRemover not available")


class TestUpdaterExtended(unittest.TestCase):
    """测试更新器扩展"""

    def test_updater_creation(self):
        try:
            from updater import Updater
            u = Updater()
            self.assertIsNotNone(u)
        except ImportError:
            self.skipTest("Updater not available")


class TestDocAnalyzer(unittest.TestCase):
    """测试文档分析器"""

    def test_analyze_pdf(self):
        try:
            from engine.heuristic.heuristic_engine import DocumentAnalyzer
            analyzer = DocumentAnalyzer()
            # 测试PDF文件
            score, reasons = analyzer.analyze('test.pdf')
            self.assertIsInstance(score, float)
            self.assertIsInstance(reasons, list)
        except ImportError:
            self.skipTest("DocumentAnalyzer not available")


class TestScriptAnalyzer(unittest.TestCase):
    """测试脚本分析器"""

    def test_analyze_ps1(self):
        try:
            from engine.heuristic.heuristic_engine import ScriptAnalyzer
            analyzer = ScriptAnalyzer()
            # 测试PowerShell脚本
            result = analyzer.analyze('test.ps1')
            if isinstance(result, tuple) and len(result) == 3:
                score, reasons, details = result
            else:
                score, reasons = result
            self.assertIsInstance(score, float)
            self.assertIsInstance(reasons, list)
        except ImportError:
            self.skipTest("ScriptAnalyzer not available")


class TestGenericAnalyzer(unittest.TestCase):
    """测试通用分析器"""

    def test_analyze(self):
        try:
            from engine.heuristic.heuristic_engine import GenericAnalyzer
            analyzer = GenericAnalyzer()
            result = analyzer.analyze(__file__)
            if isinstance(result, tuple) and len(result) == 3:
                score, reasons, details = result
            else:
                score, reasons = result
            self.assertIsInstance(score, float)
            self.assertIsInstance(reasons, list)
        except ImportError:
            self.skipTest("GenericAnalyzer not available")


class TestScoringSystem(unittest.TestCase):
    """测试评分系统"""

    def test_calculate(self):
        try:
            from engine.heuristic.heuristic_engine import ScoringSystem
            from engine import ThreatLevel
            scoring = ScoringSystem()
            scores = {'pe_analysis': 10, 'script_analysis': 0,
                     'document_analysis': 0, 'generic_analysis': 5,
                     'entropy': 3, 'strings': 2}
            result = scoring.calculate(scores)
            if isinstance(result, tuple) and len(result) == 3:
                total, level, report = result
            else:
                total, level = result
            self.assertGreater(total, 0)
            self.assertLessEqual(total, 100)
            self.assertIsInstance(level, int)
        except ImportError:
            self.skipTest("ScoringSystem not available")


class TestServiceManager(unittest.TestCase):
    """测试服务管理器"""

    def test_service_manager_creation(self):
        try:
            from service import ServiceManager
            sm = ServiceManager()
            self.assertIsNotNone(sm)
            status = sm.get_status()
            self.assertIn('running', status)
            self.assertIn('components', status)
        except ImportError:
            self.skipTest("ServiceManager not available")


if __name__ == '__main__':
    # 修复编码
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    unittest.main(verbosity=2)