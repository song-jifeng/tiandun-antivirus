#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 特征码检测引擎包
===================================

提供五大核心检测能力：
1. signature_engine - 特征码扫描引擎（MD5/SHA1/SHA256/字节序列/YARA规则）
2. signature_db    - 签名数据库管理（加载/保存/版本控制/增量更新）
3. yara_engine     - 纯 Python YARA 规则引擎
4. signatures      - 核心病毒签名数据库（5000+ 真实病毒签名）
5. heuristics      - 启发式检测规则集

架构说明：
    ScanEngine (基类)
        └── SignatureEngine (特征码扫描引擎)
        └── HeuristicEngine (启发式引擎, 在 heuristics.py 中)

    SignatureDatabase (签名数据库管理器)
    YaraEngine (YARA 规则引擎)

依赖关系：
    engine/__init__.py 提供：ScanEngine, ScanResult, ThreatInfo, ThreatType, ThreatLevel, HashUtil
"""

from .signature_engine import SignatureEngine
from .signature_db import SignatureDatabase
from .yara_engine import YaraEngine, YaraRule
from .heuristics import HeuristicRules
from .signatures import (
    VIRUS_SIGNATURES,
    WORM_SIGNATURES,
    TROJAN_SIGNATURES,
    RANSOMWARE_SIGNATURES,
    SPYWARE_SIGNATURES,
    ADWARE_SIGNATURES,
    ROOTKIT_SIGNATURES,
    MINER_SIGNATURES,
    DOWNLOADER_SIGNATURES,
    BACKDOOR_SIGNATURES,
    PUP_SIGNATURES,
    WORM_MACRO_SIGNATURES,
    HACKTOOL_SIGNATURES,
    SCAREWARE_SIGNATURES,
    ALL_SIGNATURES,
    KNOWN_VIRUS_FAMILIES,
    SIGNATURE_VERSION,
    SIGNATURE_COUNT,
)

__all__ = [
    'SignatureEngine',
    'SignatureDatabase',
    'YaraEngine',
    'YaraRule',
    'HeuristicRules',
    'VIRUS_SIGNATURES',
    'WORM_SIGNATURES',
    'TROJAN_SIGNATURES',
    'RANSOMWARE_SIGNATURES',
    'SPYWARE_SIGNATURES',
    'ADWARE_SIGNATURES',
    'ROOTKIT_SIGNATURES',
    'MINER_SIGNATURES',
    'DOWNLOADER_SIGNATURES',
    'BACKDOOR_SIGNATURES',
    'PUP_SIGNATURES',
    'WORM_MACRO_SIGNATURES',
    'HACKTOOL_SIGNATURES',
    'SCAREWARE_SIGNATURES',
    'ALL_SIGNATURES',
    'KNOWN_VIRUS_FAMILIES',
    'SIGNATURE_VERSION',
    'SIGNATURE_COUNT',
]