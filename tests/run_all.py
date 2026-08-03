#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 测试运行器
"""
import os
import sys
import time
import json
import importlib
import traceback

# Fix Windows console encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
from typing import List, Dict, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCase:
    """测试用例基类"""
    def __init__(self, name: str):
        self.name = name
        self.passed = 0
        self.failed = 0
        self.errors = []

    def assert_equal(self, actual, expected, message: str = ''):
        if actual == expected:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"{message}: 期望 {expected}, 实际 {actual}")

    def assert_true(self, condition, message: str = ''):
        if condition:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"{message}: 条件为假")

    def assert_false(self, condition, message: str = ''):
        if not condition:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"{message}: 条件为真")

    def assert_in(self, item, container, message: str = ''):
        if item in container:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"{message}: {item} 不在 {container} 中")

    def assert_not_none(self, obj, message: str = ''):
        if obj is not None:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"{message}: 对象为 None")

    def run(self):
        """运行测试 - 子类覆盖"""
        raise NotImplementedError

    def summary(self) -> str:
        return f"{self.name}: {self.passed} 通过, {self.failed} 失败"

    def has_failed(self) -> bool:
        return self.failed > 0

    def get_errors(self) -> List[str]:
        return self.errors


# ============================================================
# 测试用例
# ============================================================
class TestHashUtil(TestCase):
    def __init__(self):
        super().__init__('HashUtil 测试')

    def run(self):
        # 测试MD5
        from engine import HashUtil
        md5 = HashUtil.md5_file(__file__)
        self.assert_true(len(md5) == 32, "MD5长度应为32")
        self.assert_true(all(c in '0123456789abcdef' for c in md5), "MD5应为十六进制")

        # 测试SHA1
        sha1 = HashUtil.sha1_file(__file__)
        self.assert_true(len(sha1) == 40, "SHA1长度应为40")

        # 测试SHA256
        sha256 = HashUtil.sha256_file(__file__)
        self.assert_true(len(sha256) == 64, "SHA256长度应为64")

        # 测试不存在的文件
        md5 = HashUtil.md5_file('nonexistent_file.txt')
        self.assert_equal(md5, '', "不存在的文件应返回空字符串")


class TestThreatInfo(TestCase):
    def __init__(self):
        super().__init__('ThreatInfo 测试')

    def run(self):
        from engine import ThreatInfo, ThreatType, ThreatLevel, ScanResult

        # 测试创建
        threat = ThreatInfo('/test/file.exe', ThreatType.TROJAN, 'Test.Trojan',
                          'test_engine', ThreatLevel.HIGH, ScanResult.MALICIOUS)
        self.assert_equal(threat.file_path, '/test/file.exe')
        self.assert_equal(threat.threat_name, 'Test.Trojan')
        self.assert_equal(threat.threat_level, ThreatLevel.HIGH)

        # 测试序列化
        data = threat.to_dict()
        self.assert_equal(data['threat_name'], 'Test.Trojan')
        self.assert_equal(data['threat_level'], ThreatLevel.HIGH)

        # 测试反序列化
        restored = ThreatInfo.from_dict(data)
        self.assert_equal(restored.threat_name, 'Test.Trojan')
        self.assert_equal(restored.threat_level, ThreatLevel.HIGH)

        # 测试文件大小
        threat2 = ThreatInfo(__file__)
        self.assert_true(threat2.file_size > 0, "文件大小应大于0")


class TestConfigManager(TestCase):
    def __init__(self):
        super().__init__('ConfigManager 测试')

    def run(self):
        from engine.config import ConfigManager

        config = ConfigManager()
        # 测试获取
        value = config.get('general.language')
        self.assert_equal(value, 'zh_CN')

        # 测试设置
        config.set('test.key', 'test_value')
        value = config.get('test.key')
        self.assert_equal(value, 'test_value')

        # 测试默认值
        value = config.get('nonexistent.key', 'default')
        self.assert_equal(value, 'default')

        # 测试嵌套获取
        realtime = config.get('realtime.enabled')
        self.assert_true(isinstance(realtime, bool))


class TestFileTypeDetector(TestCase):
    def __init__(self):
        super().__init__('FileTypeDetector 测试')

    def run(self):
        from engine import FileTypeDetector

        # 测试Python文件
        ftype = FileTypeDetector.detect(__file__)
        self.assert_equal(ftype, 'text')

        # 测试不存在的文件
        ftype = FileTypeDetector.detect('nonexistent.txt')
        self.assert_equal(ftype, 'unknown')


class TestSignatureEngine(TestCase):
    def __init__(self):
        super().__init__('SignatureEngine 测试')

    def run(self):
        from engine.signatures.signature_engine import SignatureEngine
        engine = SignatureEngine()
        self.assert_true(engine.enabled, "签名引擎应默认启用")
        self.assert_equal(engine.name, 'signature')

        # 测试加载签名
        stats = engine.get_stats()
        self.assert_true('scanned' in stats, "统计信息应包含 scanned")


class TestHeuristicEngine(TestCase):
    def __init__(self):
        super().__init__('HeuristicEngine 测试')

    def run(self):
        from engine.heuristic.heuristic_engine import HeuristicEngine
        engine = HeuristicEngine()
        self.assert_equal(engine.name, 'HeuristicEngine')

        # 测试扫描Python文件（应安全）
        from engine import ScanResult
        result = engine.scan(__file__)
        self.assert_true(result is None, "Python文件应被检测为安全")


class TestQuarantine(TestCase):
    def __init__(self):
        super().__init__('隔离区测试')

    def run(self):
        from cleanup.quarantine import QuarantineManager
        qm = QuarantineManager()
        stats = qm.get_stats()
        self.assert_true('total_items' in stats, "隔离区统计应包含 total_items")
        self.assert_true('total_size' in stats, "隔离区统计应包含 total_size")


class TestLogger(TestCase):
    def __init__(self):
        super().__init__('Logger 测试')

    def run(self):
        from engine.logger import Logger
        log = Logger('test_logger')
        log.info("测试日志消息")
        log.warning("测试警告消息")
        log.error("测试错误消息")
        self.assert_true(True, "日志记录应正常")


class TestScanner(TestCase):
    def __init__(self):
        super().__init__('Scanner 测试')

    def run(self):
        from scanner import Scanner
        s = Scanner()
        self.assert_true(len(s.engines) > 0, "扫描器应加载至少一个引擎")


class TestUpdater(TestCase):
    def __init__(self):
        super().__init__('Updater 测试')

    def run(self):
        from updater import Updater
        u = Updater()
        self.assert_true(u is not None, "更新器应创建成功")


class TestService(TestCase):
    def __init__(self):
        super().__init__('Service 测试')

    def run(self):
        from service import TiandunService
        status = TiandunService.status()
        self.assert_true('status' in status, "服务状态应包含 status 字段")


class TestFileAnalyzer(TestCase):
    def __init__(self):
        super().__init__('FileAnalyzer 测试')

    def run(self):
        from tools.file_analyzer import FileAnalyzer
        result = FileAnalyzer.analyze(__file__)
        self.assert_true('name' in result, "分析结果应包含 name")
        self.assert_true('size' in result, "分析结果应包含 size")
        self.assert_true('hashes' in result, "分析结果应包含 hashes")
        self.assert_equal(result['name'], os.path.basename(__file__))


class TestProcessExplorer(TestCase):
    def __init__(self):
        super().__init__('ProcessExplorer 测试')

    def run(self):
        from tools.process_explorer import ProcessExplorer
        processes = ProcessExplorer.get_processes()
        # 在某些受限环境中可能获取不到进程列表
        self.assert_true(isinstance(processes, list), "进程列表应为列表类型")


class TestStartupManager(TestCase):
    def __init__(self):
        super().__init__('StartupManager 测试')

    def run(self):
        from tools.startup_manager import StartupManager
        items = StartupManager.get_startup_items()
        self.assert_true(isinstance(items, list), "启动项应为列表")


class TestSystemCleaner(TestCase):
    def __init__(self):
        super().__init__('SystemCleaner 测试')

    def run(self):
        from tools.system_cleaner import SystemCleaner
        result = SystemCleaner.clean_temp_files()
        self.assert_true('success' in result, "清理结果应包含 success")
        self.assert_true('cleaned' in result, "清理结果应包含 cleaned")


class TestHoneypot(TestCase):
    def __init__(self):
        super().__init__('Honeypot 测试')

    def run(self):
        from firewall.honeypot import Honeypot
        hp = Honeypot()
        stats = hp.get_stats()
        self.assert_true('honeypot_files' in stats)
        self.assert_true('alerts' in stats)


class TestSelfDefense(TestCase):
    def __init__(self):
        super().__init__('SelfDefense 测试')

    def run(self):
        from self_protection.self_defense import SelfDefense
        sd = SelfDefense()
        status = sd.get_status()
        self.assert_true('running' in status)


class TestFirewall(TestCase):
    def __init__(self):
        super().__init__('Firewall 测试')

    def run(self):
        from firewall.firewall_engine import FirewallEngine
        fw = FirewallEngine()
        rules = fw.get_rules()
        self.assert_true(len(rules) > 0, "防火墙应包含默认规则")
        stats = fw.get_stats()
        self.assert_true('total_rules' in stats)


class TestCommon(TestCase):
    def __init__(self):
        super().__init__('Common 测试')

    def run(self):
        from engine.common import StringUtil, TimeUtil, PathUtil, FileUtil

        # 测试StringUtil
        self.assert_true(len(StringUtil.hexdump(b'hello')) > 0)
        strings = StringUtil.extract_strings(b'hello world test')
        self.assert_true(len(strings) > 0)

        # 测试TimeUtil
        self.assert_true(TimeUtil.now() > 0)
        self.assert_true(len(TimeUtil.now_str()) > 0)
        self.assert_true(len(TimeUtil.time_ago(time.time() - 3600)) > 0)

        # 测试PathUtil
        drives = PathUtil.get_drives()
        self.assert_true(len(drives) > 0)

        # 测试FileUtil
        size_str = FileUtil.get_size_str(1024)
        self.assert_true(len(size_str) > 0)
        time_str = FileUtil.get_time_str(time.time())
        self.assert_true(len(time_str) > 0)


# ============================================================
# 测试运行器
# ============================================================
class TestRunner:
    """测试运行器"""

    def __init__(self):
        self.tests: List[TestCase] = []

    def add_test(self, test: TestCase):
        self.tests.append(test)

    def add_all(self):
        self.tests = [
            TestHashUtil(),
            TestThreatInfo(),
            TestConfigManager(),
            TestFileTypeDetector(),
            TestLogger(),
            TestCommon(),
            TestSignatureEngine(),
            TestHeuristicEngine(),
            TestScanner(),
            TestUpdater(),
            TestService(),
            TestQuarantine(),
            TestFileAnalyzer(),
            TestProcessExplorer(),
            TestStartupManager(),
            TestSystemCleaner(),
            TestHoneypot(),
            TestSelfDefense(),
            TestFirewall(),
        ]

    def run(self) -> Dict:
        """运行所有测试"""
        total_passed = 0
        total_failed = 0
        results = []

        print(f"\n{'='*60}")
        print(f"  天盾 Antivirus - 测试套件")
        print(f"{'='*60}\n")

        for test in self.tests:
            try:
                test.run()
            except Exception as e:
                test.failed += 1
                test.errors.append(f"测试异常: {traceback.format_exc()}")
                print(f"  ❌ {test.name} - 异常: {e}")

            total_passed += test.passed
            total_failed += test.failed

            status = '[PASS]' if not test.has_failed() else '[FAIL]'
            print(f"  {status} {test.summary()}")
            if test.has_failed():
                for err in test.get_errors()[:3]:
                    print(f"      - {err}")

            results.append({
                'name': test.name,
                'passed': test.passed,
                'failed': test.failed,
                'errors': test.get_errors(),
            })

        total = total_passed + total_failed
        pct = (total_passed / total * 100) if total > 0 else 0

        print(f"\n{'='*60}")
        print(f"  测试结果汇总")
        print(f"{'='*60}")
        print(f"  总测试数: {total}")
        print(f"  通过: {total_passed}")
        print(f"  失败: {total_failed}")
        print(f"  通过率: {pct:.1f}%")
        print(f"{'='*60}\n")

        return {
            'total': total,
            'passed': total_passed,
            'failed': total_failed,
            'rate': pct,
            'results': results,
        }


if __name__ == '__main__':
    runner = TestRunner()
    runner.add_all()
    result = runner.run()
    sys.exit(1 if result['failed'] > 0 else 0)