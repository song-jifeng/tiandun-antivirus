#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 行为分析引擎单元测试
"""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.behavior.behavior_engine import BehaviorEvent, BehaviorRule, BehaviorRules
from engine import ThreatLevel


# ============================================================
# BehaviorEvent 测试
# ============================================================

class TestBehaviorEvent:
    """测试行为事件"""

    def test_event_creation(self):
        """测试事件创建"""
        event = BehaviorEvent(
            event_type='process',
            pid=1234,
            process_name='test.exe',
            action='CreateProcess',
            target='C:\\Windows\\System32\\cmd.exe',
            details={'command_line': 'cmd.exe /c dir'}
        )
        assert event.event_type == 'process'
        assert event.pid == 1234
        assert event.process_name == 'test.exe'
        assert event.action == 'CreateProcess'
        assert event.target == 'C:\\Windows\\System32\\cmd.exe'
        assert event.details['command_line'] == 'cmd.exe /c dir'
        assert event.timestamp > 0

    def test_event_default_details(self):
        """测试事件默认详细信息"""
        event = BehaviorEvent(
            event_type='file',
            pid=5678,
            process_name='explorer.exe',
            action='modify',
            target='C:\\test.txt'
        )
        assert event.details == {}

    def test_event_to_dict(self):
        """测试事件转换为字典"""
        event = BehaviorEvent(
            event_type='registry',
            pid=9999,
            process_name='regedit.exe',
            action='write',
            target='HKLM\\Software\\Test'
        )
        d = event.to_dict()
        assert d['type'] == 'registry'
        assert d['pid'] == 9999
        assert d['process'] == 'regedit.exe'
        assert d['action'] == 'write'
        assert d['target'] == 'HKLM\\Software\\Test'
        assert 'timestamp' in d

    def test_different_event_types(self):
        """测试不同事件类型"""
        for event_type in ['process', 'file', 'registry', 'network']:
            event = BehaviorEvent(
                event_type=event_type,
                pid=1000,
                process_name='test.exe',
                action='test',
                target='/test'
            )
            assert event.event_type == event_type


# ============================================================
# BehaviorRule 测试
# ============================================================

class TestBehaviorRule:
    """测试行为检测规则"""

    def test_rule_creation(self):
        """测试规则创建"""
        rule = BehaviorRule(
            rule_id='T001',
            name='Test Rule',
            description='A test rule',
            event_type='process',
            actions=['CreateProcess', 'TerminateProcess'],
            target_patterns=['cmd.exe', 'powershell.exe'],
            score=25,
            level=ThreatLevel.HIGH,
            min_count=3,
            time_window=120
        )
        assert rule.id == 'T001'
        assert rule.name == 'Test Rule'
        assert rule.description == 'A test rule'
        assert rule.event_type == 'process'
        assert rule.actions == ['CreateProcess', 'TerminateProcess']
        assert rule.target_patterns == ['cmd.exe', 'powershell.exe']
        assert rule.score == 25
        assert rule.level == ThreatLevel.HIGH
        assert rule.min_count == 3
        assert rule.time_window == 120

    def test_rule_matches_event(self):
        """测试规则匹配事件"""
        rule = BehaviorRule(
            rule_id='P001',
            name='Process Create',
            description='Detect process creation',
            event_type='process',
            actions=['CreateProcess'],
            target_patterns=['cmd.exe'],
            score=15,
            level=ThreatLevel.MEDIUM,
        )

        # 匹配事件
        event = BehaviorEvent(
            event_type='process',
            pid=100,
            process_name='test.exe',
            action='CreateProcess',
            target='C:\\Windows\\System32\\cmd.exe'
        )
        assert rule.matches(event) is True

    def test_rule_no_match_wrong_type(self):
        """测试规则不匹配错误类型"""
        rule = BehaviorRule(
            rule_id='P001',
            name='Process Rule',
            description='Only process events',
            event_type='process',
            actions=['CreateProcess'],
            target_patterns=[],
            score=10,
            level=ThreatLevel.LOW,
        )

        event = BehaviorEvent(
            event_type='file',
            pid=100,
            process_name='test.exe',
            action='CreateProcess',
            target='C:\\test.exe'
        )
        assert rule.matches(event) is False

    def test_rule_no_match_wrong_action(self):
        """测试规则不匹配错误动作"""
        rule = BehaviorRule(
            rule_id='P001',
            name='Process Create',
            description='Only CreateProcess',
            event_type='process',
            actions=['CreateProcess'],
            target_patterns=[],
            score=10,
            level=ThreatLevel.LOW,
        )

        event = BehaviorEvent(
            event_type='process',
            pid=100,
            process_name='test.exe',
            action='TerminateProcess',
            target='C:\\test.exe'
        )
        assert rule.matches(event) is False

    def test_rule_no_match_wrong_target(self):
        """测试规则不匹配错误目标"""
        rule = BehaviorRule(
            rule_id='P001',
            name='Process Create',
            description='Only cmd.exe',
            event_type='process',
            actions=['CreateProcess'],
            target_patterns=['cmd.exe'],
            score=10,
            level=ThreatLevel.LOW,
        )

        event = BehaviorEvent(
            event_type='process',
            pid=100,
            process_name='test.exe',
            action='CreateProcess',
            target='C:\\Windows\\notepad.exe'
        )
        assert rule.matches(event) is False

    def test_rule_matches_with_empty_actions(self):
        """测试规则匹配空动作列表"""
        rule = BehaviorRule(
            rule_id='T001',
            name='Any Action',
            description='Match any action',
            event_type='file',
            actions=[],
            target_patterns=[],
            score=5,
            level=ThreatLevel.LOW,
        )

        event = BehaviorEvent(
            event_type='file',
            pid=100,
            process_name='test.exe',
            action='modify',
            target='C:\\test.txt'
        )
        assert rule.matches(event) is True

    def test_rule_matches_target_pattern(self):
        """测试规则匹配目标模式"""
        rule = BehaviorRule(
            rule_id='F001',
            name='File Modify',
            description='Detect file modification',
            event_type='file',
            actions=['modify', 'delete'],
            target_patterns=['.exe', '.dll'],
            score=20,
            level=ThreatLevel.HIGH,
        )

        # 匹配 .exe 目标
        event = BehaviorEvent(
            event_type='file',
            pid=100,
            process_name='test.exe',
            action='modify',
            target='C:\\Windows\\System32\\kernel32.dll'
        )
        assert rule.matches(event) is True

        # 不应匹配 .txt 目标
        event2 = BehaviorEvent(
            event_type='file',
            pid=100,
            process_name='test.exe',
            action='modify',
            target='C:\\readme.txt'
        )
        assert rule.matches(event2) is False

    def test_rule_default_attributes(self):
        """测试规则默认属性"""
        rule = BehaviorRule(
            rule_id='D001',
            name='Default',
            description='Default values',
            event_type='network',
            actions=['connect'],
            target_patterns=[],
            score=10,
        )
        assert rule.level == ThreatLevel.MEDIUM  # 默认
        assert rule.min_count == 1  # 默认
        assert rule.time_window == 60  # 默认


# ============================================================
# BehaviorRules 测试
# ============================================================

class TestBehaviorRules:
    """测试行为规则集"""

    def test_get_rules_returns_list(self):
        """测试获取规则列表"""
        rules = BehaviorRules.get_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_get_rules_contains_process_rules(self):
        """测试规则包含进程规则"""
        rules = BehaviorRules.get_rules()
        process_rules = [r for r in rules if r.event_type == 'process']
        assert len(process_rules) > 0

    def test_get_rules_contains_file_rules(self):
        """测试规则包含文件规则"""
        rules = BehaviorRules.get_rules()
        file_rules = [r for r in rules if r.event_type == 'file']
        assert len(file_rules) > 0

    def test_get_rules_contains_network_rules(self):
        """测试规则包含网络规则"""
        rules = BehaviorRules.get_rules()
        network_rules = [r for r in rules if r.event_type == 'network']
        assert len(network_rules) > 0

    def test_rules_have_unique_ids(self):
        """测试规则 ID 唯一"""
        rules = BehaviorRules.get_rules()
        rule_ids = [r.id for r in rules]
        assert len(rule_ids) == len(set(rule_ids)), "规则 ID 应唯一"

    def test_rules_have_scores(self):
        """测试规则都有分数"""
        rules = BehaviorRules.get_rules()
        for rule in rules:
            assert rule.score > 0, f"规则 {rule.id} 的分数应为正数"

    def test_rules_have_levels(self):
        """测试规则都有等级"""
        rules = BehaviorRules.get_rules()
        for rule in rules:
            assert rule.level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH,
                                  ThreatLevel.MEDIUM, ThreatLevel.LOW, ThreatLevel.INFO]

    def test_rules_have_min_count(self):
        """测试规则都有最小计数"""
        rules = BehaviorRules.get_rules()
        for rule in rules:
            assert rule.min_count >= 1

    def test_rules_time_window(self):
        """测试规则都有时间窗口"""
        rules = BehaviorRules.get_rules()
        for rule in rules:
            assert rule.time_window > 0


# ============================================================
# 行为事件匹配综合测试
# ============================================================

class TestBehaviorEventMatching:
    """测试行为事件匹配"""

    def test_process_injection_detection(self):
        """测试进程注入检测"""
        # 获取进程注入规则
        rules = BehaviorRules.get_rules()
        injection_rules = [r for r in rules if r.id == 'P001']
        assert len(injection_rules) > 0
        rule = injection_rules[0]

        # 模拟注入事件
        event = BehaviorEvent(
            event_type='process',
            pid=1234,
            process_name='malware.exe',
            action='CreateRemoteThread',
            target='C:\\Windows\\System32\\svchost.exe',
            details={'target_pid': 5678}
        )
        assert rule.matches(event) is True

    def test_ransomware_file_behavior(self):
        """测试勒索软件文件行为检测"""
        # 获取批量文件修改规则
        rules = BehaviorRules.get_rules()
        ransomware_rules = [r for r in rules if r.id == 'F001']
        assert len(ransomware_rules) > 0
        rule = ransomware_rules[0]

        # 模拟勒索软件行为
        event = BehaviorEvent(
            event_type='file',
            pid=1234,
            process_name='ransomware.exe',
            action='modify',
            target='C:\\Users\\test\\Documents\\important.docx'
        )
        assert rule.matches(event) is True

    def test_network_connection_detection(self):
        """测试网络连接检测"""
        rules = BehaviorRules.get_rules()
        network_rules = [r for r in rules if r.event_type == 'network']
        assert len(network_rules) > 0

        # 模拟恶意网络连接
        event = BehaviorEvent(
            event_type='network',
            pid=1234,
            process_name='backdoor.exe',
            action='connect',
            target='185.234.72.1:4444',
            details={'remote_ip': '185.234.72.1', 'remote_port': 4444}
        )
        # 应该至少有一个网络规则匹配
        matches = [r for r in network_rules if r.matches(event)]
        assert len(matches) > 0