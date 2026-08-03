#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 隔离区管理器单元测试
"""
import os
import sys
import time
import tempfile
import shutil
import pytest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cleanup.quarantine import QuarantineManager
from engine import ThreatInfo, ThreatType, ThreatLevel, ScanResult


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def quarantine_manager(tmp_path):
    """创建使用临时目录的隔离管理器"""
    # 创建临时隔离目录
    q_dir = tmp_path / 'quarantine_test'
    q_dir.mkdir()

    # 创建临时管理器
    class TestQuarantineManager(QuarantineManager):
        """覆盖隔离目录的测试管理器"""
        def __init__(self, q_dir, index_file):
            self.quarantine_dir = q_dir
            self.index_file = index_file
            self._index = {}
            q_dir.mkdir(parents=True, exist_ok=True)
            self._load_index()

    manager = TestQuarantineManager(
        q_dir=q_dir,
        index_file=q_dir / 'index.json'
    )
    yield manager


@pytest.fixture
def sample_file(tmp_path):
    """创建用于测试的样本文件"""
    f = tmp_path / 'test_file.exe'
    f.write_bytes(b'MZ' + b'\x00' * 100 + b'This is a test file')
    yield str(f)


@pytest.fixture
def sample_threat():
    """创建样本威胁信息"""
    return ThreatInfo(
        file_path='/test/path/test_file.exe',
        threat_type=ThreatType.VIRUS,
        threat_name='Test.Virus',
        scan_engine='test_engine',
        threat_level=ThreatLevel.HIGH,
        result=ScanResult.MALICIOUS,
    )


# ============================================================
# QuarantineManager 测试
# ============================================================

class TestQuarantineManager:
    """测试隔离管理器"""

    def test_initialization(self, quarantine_manager):
        """测试初始化"""
        assert quarantine_manager.quarantine_dir.exists()
        assert quarantine_manager._index == {}

    def test_quarantine_file(self, quarantine_manager, sample_file, sample_threat):
        """测试隔离文件"""
        result = quarantine_manager.quarantine(sample_file, sample_threat)
        assert result is True, "文件隔离应成功"

        # 原文件应被删除
        assert os.path.exists(sample_file) is False

        # 隔离区应包含文件
        items = quarantine_manager.get_all()
        assert len(items) == 1, "隔离区应有 1 个文件"

        item = items[0]
        assert item['original_path'] == os.path.abspath(sample_file)
        assert item['threat_name'] == 'Test.Virus'
        assert item['threat_type'] == ThreatType.VIRUS
        assert item['restored'] is False
        assert item['deleted'] is False

    def test_quarantine_without_threat(self, quarantine_manager, sample_file):
        """测试无威胁信息隔离"""
        result = quarantine_manager.quarantine(sample_file)
        assert result is True

        items = quarantine_manager.get_all()
        assert len(items) == 1
        assert items[0]['threat_name'] == ''

    def test_quarantine_nonexistent_file(self, quarantine_manager):
        """测试隔离不存在的文件"""
        result = quarantine_manager.quarantine('/nonexistent/file.exe')
        assert result is False

    def test_restore_file(self, quarantine_manager, sample_file, sample_threat, tmp_path):
        """测试还原文件"""
        # 先隔离
        quarantine_manager.quarantine(sample_file, sample_threat)

        # 获取隔离 ID
        items = quarantine_manager.get_all()
        qid = items[0]['id']

        # 还原到指定路径
        restore_path = os.path.join(tmp_path, 'restored_file.exe')
        result = quarantine_manager.restore(qid, restore_path)
        assert result is True, "文件还原应成功"

        # 检查还原后的文件
        assert os.path.exists(restore_path)
        with open(restore_path, 'rb') as f:
            content = f.read()
        assert b'MZ' in content

        # 检查记录已更新
        items = quarantine_manager.get_all()
        assert items[0]['restored'] is True

    def test_restore_file_to_original(self, quarantine_manager, sample_file, sample_threat, tmp_path):
        """测试还原到原路径"""
        # 先隔离
        quarantine_manager.quarantine(sample_file, sample_threat)

        # 重新创建原文件路径（隔离时已删除）
        os.makedirs(os.path.dirname(sample_file) or '.', exist_ok=True)

        # 获取隔离 ID
        items = quarantine_manager.get_all()
        qid = items[0]['id']

        # 还原到原路径
        result = quarantine_manager.restore(qid)
        assert result is True

    def test_restore_nonexistent_id(self, quarantine_manager):
        """测试还原不存在的 ID"""
        result = quarantine_manager.restore('nonexistent_id')
        assert result is False

    def test_delete_file(self, quarantine_manager, sample_file, sample_threat):
        """测试删除隔离文件"""
        # 先隔离
        quarantine_manager.quarantine(sample_file, sample_threat)

        # 获取隔离 ID
        items = quarantine_manager.get_all()
        qid = items[0]['id']

        # 删除隔离文件
        result = quarantine_manager.delete(qid)
        assert result is True

        # 检查记录已更新
        items = quarantine_manager.get_all()
        assert len(items) == 0, "删除后不应有活跃项"

    def test_delete_nonexistent_id(self, quarantine_manager):
        """测试删除不存在的 ID"""
        result = quarantine_manager.delete('nonexistent_id')
        assert result is False

    def test_get_all_empty(self, quarantine_manager):
        """测试空隔离区"""
        items = quarantine_manager.get_all()
        assert len(items) == 0

    def test_get_all_multiple(self, quarantine_manager, tmp_path):
        """测试多个隔离文件"""
        for i in range(3):
            f = tmp_path / f'test_file_{i}.exe'
            # 使用不同内容确保不同 MD5 哈希
            f.write_bytes(b'MZ' + bytes([i] * 100))
            threat = ThreatInfo(
                str(f), ThreatType.TROJAN, f'Test.Trojan.{i}'
            )
            time.sleep(0.01)  # 确保时间戳不同
            quarantine_manager.quarantine(str(f), threat)

        items = quarantine_manager.get_all()
        assert len(items) == 3

    def test_get_stats(self, quarantine_manager, sample_file, sample_threat):
        """测试获取统计"""
        # 空隔离区统计
        stats = quarantine_manager.get_stats()
        assert stats['total_items'] == 0
        assert stats['total_size'] == 0

        # 隔离后统计
        quarantine_manager.quarantine(sample_file, sample_threat)
        stats = quarantine_manager.get_stats()
        assert stats['total_items'] == 1
        assert stats['total_size'] > 0

    def test_clean_expired(self, quarantine_manager, sample_file, sample_threat):
        """测试清理过期文件"""
        # 隔离文件
        quarantine_manager.quarantine(sample_file, sample_threat)

        # 修改隔离时间为过期
        qid = list(quarantine_manager._index.keys())[0]
        quarantine_manager._index[qid]['quarantine_time'] = time.time() - 31 * 86400

        # 清理过期
        quarantine_manager.clean_expired()

        # 检查是否已清理
        items = quarantine_manager.get_all()
        assert len(items) == 0, "过期文件应被清理"

    def test_quarantine_preserves_content(self, quarantine_manager, sample_file, sample_threat, tmp_path):
        """测试隔离后文件内容保持不变"""
        # 读取原始内容
        original_content = open(sample_file, 'rb').read()

        # 隔离
        quarantine_manager.quarantine(sample_file, sample_threat)

        # 获取隔离路径
        items = quarantine_manager.get_all()
        quar_path = items[0]['quarantine_path']

        # 比较内容
        with open(quar_path, 'rb') as f:
            quar_content = f.read()
        assert quar_content == original_content, "隔离文件内容应与原文件一致"

    def test_multiple_operations(self, quarantine_manager, tmp_path):
        """测试多次操作"""
        files = []
        for i in range(5):
            f = tmp_path / f'file_{i}.exe'
            f.write_bytes(b'MZ' + bytes([i] * 100))
            files.append(str(f))

        # 隔离所有文件
        for f in files:
            quarantine_manager.quarantine(f)
        assert len(quarantine_manager.get_all()) == 5

        # 删除 2 个
        all_items = quarantine_manager.get_all()
        for item in all_items[:2]:
            quarantine_manager.delete(item['id'])
        assert len(quarantine_manager.get_all()) == 3

        # 还原 1 个
        remaining = quarantine_manager.get_all()
        if remaining:
            quarantine_manager.restore(remaining[0]['id'])
        # 还原后仍然在列表中（但标记为 restored）
        assert len(quarantine_manager.get_all()) == 3


# ============================================================
# 隔离区持久化测试
# ============================================================

class TestQuarantinePersistence:
    """测试隔离区持久化"""

    def test_index_persistence(self, quarantine_manager, sample_file, tmp_path):
        """测试隔离索引持久化"""
        # 隔离文件
        threat = ThreatInfo(sample_file, ThreatType.VIRUS, 'Test.Virus')
        quarantine_manager.quarantine(sample_file, threat)

        # 创建新管理器加载同一个索引
        class TestQuarantineManager(QuarantineManager):
            def __init__(self, q_dir, index_file):
                self.quarantine_dir = q_dir
                self.index_file = index_file
                self._index = {}
                self._load_index()

        manager2 = TestQuarantineManager(
            quarantine_manager.quarantine_dir,
            quarantine_manager.index_file
        )

        # 检查索引是否加载
        assert len(manager2._index) > 0, "持久化索引应能加载"

    def test_index_after_restore(self, quarantine_manager, sample_file, tmp_path):
        """测试还原后索引更新"""
        # 隔离
        quarantine_manager.quarantine(sample_file)

        # 还原
        qid = list(quarantine_manager._index.keys())[0]
        restore_path = os.path.join(tmp_path, 'restored.exe')
        quarantine_manager.restore(qid, restore_path)

        # 重新加载索引
        class TestQuarantineManager(QuarantineManager):
            def __init__(self, q_dir, index_file):
                self.quarantine_dir = q_dir
                self.index_file = index_file
                self._index = {}
                self._load_index()

        manager2 = TestQuarantineManager(
            quarantine_manager.quarantine_dir,
            quarantine_manager.index_file
        )
        assert manager2._index[qid]['restored'] is True