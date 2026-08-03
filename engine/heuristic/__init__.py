#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 启发式分析引擎包

提供不依赖病毒库的启发式检测能力，通过多维度分析文件特征识别未知威胁。

模块结构:
    heuristic_engine.py - 启发式分析引擎主类 (HeuristicEngine)
    pe_analyzer.py      - PE文件分析器 (PEAnalyzer, 50+检测规则)
    script_analyzer.py  - 脚本分析器 (ScriptAnalyzer, 30+检测规则)
    doc_analyzer.py     - 文档分析器 (DocAnalyzer, 20+检测规则)
    generic_analyzer.py - 通用文件分析器 (GenericAnalyzer, 20+检测规则)
    scoring.py          - 评分系统 (ScoringSystem, ScoreReport)
"""

from .heuristic_engine import HeuristicEngine
from .pe_analyzer import PEAnalyzer
from .script_analyzer import ScriptAnalyzer
from .doc_analyzer import DocAnalyzer
from .generic_analyzer import GenericAnalyzer
from .scoring import ScoringSystem, ScoreReport, ScoreDimension, ScoreAggregator

__all__ = [
    'HeuristicEngine',
    'PEAnalyzer',
    'ScriptAnalyzer',
    'DocAnalyzer',
    'GenericAnalyzer',
    'ScoringSystem',
    'ScoreReport',
    'ScoreDimension',
    'ScoreAggregator',
]

__version__ = '1.0.0'
__author__ = 'TianDun Security'