#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 启发式分析评分系统
多维度加权评分，可配置的权重和阈值，详细的评分报告
"""

import math
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict


# ============================================================
# 评分维度定义
# ============================================================
@dataclass
class ScoreDimension:
    """单个评分维度的结果"""
    name: str                           # 维度名称
    raw_score: float = 0.0              # 原始分数
    weight: float = 1.0                 # 权重系数
    weighted_score: float = 0.0         # 加权后分数
    max_score: float = 100.0            # 该维度最高分
    reasons: List[str] = field(default_factory=list)  # 扣分原因
    details: Dict[str, Any] = field(default_factory=dict)  # 详细分析数据

    def calculate_weighted(self) -> float:
        """计算加权分数"""
        self.weighted_score = min(self.raw_score, self.max_score) * self.weight
        return self.weighted_score


@dataclass
class ScoreReport:
    """完整的评分报告"""
    file_path: str
    file_name: str = ''
    file_size: int = 0
    file_type: str = ''
    timestamp: float = 0.0
    total_score: float = 0.0
    threat_level: int = 0
    threat_level_name: str = '无害'
    dimensions: List[ScoreDimension] = field(default_factory=list)
    all_reasons: List[str] = field(default_factory=list)
    top_contributors: List[Tuple[str, float]] = field(default_factory=list)
    analysis_time_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'timestamp': self.timestamp or time.time(),
            'total_score': self.total_score,
            'threat_level': self.threat_level,
            'threat_level_name': self.threat_level_name,
            'dimensions': [asdict(d) for d in self.dimensions],
            'all_reasons': self.all_reasons[:20],  # 最多保留20个原因
            'top_contributors': self.top_contributors[:5],
            'analysis_time_ms': self.analysis_time_ms,
        }


# ============================================================
# 评分系统
# ============================================================
class ScoringSystem:
    """
    多维度加权评分系统

    支持可配置的权重和阈值，可针对不同文件类型动态调整。
    评分范围 0-100，分数越高代表威胁越大。
    """

    # 默认权重配置 - 各维度权重总和应为1.0
    DEFAULT_WEIGHTS: Dict[str, float] = {
        'pe_analysis': 0.25,           # PE结构分析权重
        'script_analysis': 0.20,        # 脚本分析权重
        'document_analysis': 0.15,      # 文档分析权重
        'generic_analysis': 0.10,       # 通用分析权重
        'entropy': 0.10,                # 熵值分析权重
        'strings_analysis': 0.10,       # 字符串分析权重
        'structure_analysis': 0.10,     # 结构异常分析权重
    }

    # 文件类型对应的权重调整
    FILE_TYPE_WEIGHTS: Dict[str, Dict[str, float]] = {
        'exe': {
            'pe_analysis': 0.35,
            'script_analysis': 0.00,
            'document_analysis': 0.00,
            'generic_analysis': 0.15,
            'entropy': 0.15,
            'strings_analysis': 0.20,
            'structure_analysis': 0.15,
        },
        'dll': {
            'pe_analysis': 0.35,
            'script_analysis': 0.00,
            'document_analysis': 0.00,
            'generic_analysis': 0.15,
            'entropy': 0.15,
            'strings_analysis': 0.20,
            'structure_analysis': 0.15,
        },
        'script': {
            'pe_analysis': 0.00,
            'script_analysis': 0.50,
            'document_analysis': 0.00,
            'generic_analysis': 0.10,
            'entropy': 0.05,
            'strings_analysis': 0.20,
            'structure_analysis': 0.15,
        },
        'document': {
            'pe_analysis': 0.00,
            'script_analysis': 0.00,
            'document_analysis': 0.50,
            'generic_analysis': 0.10,
            'entropy': 0.10,
            'strings_analysis': 0.15,
            'structure_analysis': 0.15,
        },
        'generic': {
            'pe_analysis': 0.00,
            'script_analysis': 0.00,
            'document_analysis': 0.00,
            'generic_analysis': 0.40,
            'entropy': 0.20,
            'strings_analysis': 0.20,
            'structure_analysis': 0.20,
        },
    }

    # 威胁等级阈值
    # 总分 >= 阈值 时触发对应等级
    LEVEL_THRESHOLDS: Dict[int, float] = {
        5: 80.0,    # CRITICAL >= 80
        4: 60.0,    # HIGH    >= 60
        3: 50.0,    # MEDIUM  >= 50
        2: 35.0,    # LOW     >= 35
        1: 10.0,    # INFO    >= 10
        0: 0.0,     # NONE    < 10
    }

    # 威胁等级名称
    LEVEL_NAMES: Dict[int, str] = {
        5: '严重',
        4: '高危',
        3: '中等',
        2: '低危',
        1: '信息',
        0: '无害',
    }

    # 等级对应的检测结果
    LEVEL_RESULTS: Dict[int, int] = {
        5: 2,  # CRITICAL -> MALICIOUS
        4: 2,  # HIGH     -> MALICIOUS
        3: 1,  # MEDIUM   -> SUSPICIOUS
        2: 1,  # LOW      -> SUSPICIOUS
        1: 0,  # INFO     -> CLEAN
        0: 0,  # NONE     -> CLEAN
    }

    def __init__(self, config: Optional[Dict] = None):
        """
        初始化评分系统

        Args:
            config: 可选配置字典，可覆盖默认权重和阈值
        """
        self.weights = dict(self.DEFAULT_WEIGHTS)
        self.thresholds = dict(self.LEVEL_THRESHOLDS)
        self.level_names = dict(self.LEVEL_NAMES)

        if config:
            self._apply_config(config)

    def _apply_config(self, config: Dict):
        """应用配置"""
        if 'weights' in config:
            for key, value in config['weights'].items():
                if key in self.weights:
                    self.weights[key] = float(value)
        if 'thresholds' in config:
            for level, value in config['thresholds'].items():
                self.thresholds[int(level)] = float(value)

    # ============================================================
    # 核心评分方法
    # ============================================================

    def calculate(self, scores: Dict[str, float],
                  file_type: str = 'generic',
                  reasons: Optional[Dict[str, List[str]]] = None,
                  details: Optional[Dict[str, Dict]] = None) -> Tuple[int, int, ScoreReport]:
        """
        计算总分和威胁等级

        Args:
            scores: 各维度原始分数 {维度名: 分数}
            file_type: 文件类型，用于选择权重配置
            reasons: 各维度检测原因 {维度名: [原因列表]}
            details: 各维度详细分析数据

        Returns:
            (总分, 威胁等级, 评分报告)
        """
        # 选择权重配置
        weights = self._get_weights(file_type)

        # 构建评分报告
        report = ScoreReport(
            file_path='',
            file_name='',
            file_size=0,
            file_type=file_type,
            timestamp=time.time(),
        )

        total_score = 0.0
        all_reasons = []
        contributors = []

        # 计算各维度加权分数
        for dim_name, weight in weights.items():
            raw = scores.get(dim_name, 0.0)
            dim_reasons = reasons.get(dim_name, []) if reasons else []
            dim_details = details.get(dim_name, {}) if details else {}

            dimension = ScoreDimension(
                name=dim_name,
                raw_score=float(raw),
                weight=weight,
                max_score=100.0,
                reasons=dim_reasons,
                details=dim_details,
            )
            weighted = dimension.calculate_weighted()
            total_score += weighted
            all_reasons.extend(dim_reasons)

            if weighted > 0:
                contributors.append((dim_name, weighted))

            report.dimensions.append(dimension)

        # 应用非线性放大（高风险区域放大）
        total_score = self._apply_nonlinear_amplification(total_score)

        # 确保不超过100
        total_score = min(total_score, 100.0)

        # 确定威胁等级
        level = self._determine_level(total_score)

        # 填充报告
        report.total_score = round(total_score, 1)
        report.threat_level = level
        report.threat_level_name = self.level_names.get(level, '未知')
        report.all_reasons = all_reasons
        report.top_contributors = sorted(contributors, key=lambda x: x[1], reverse=True)

        return int(total_score), level, report

    def calculate_simple(self, scores: Dict[str, float],
                         file_type: str = 'generic') -> Tuple[int, int]:
        """
        简化评分计算（不生成详细报告）

        Returns:
            (总分, 威胁等级)
        """
        weights = self._get_weights(file_type)
        total = 0.0
        for dim_name, weight in weights.items():
            total += scores.get(dim_name, 0.0) * weight

        total = self._apply_nonlinear_amplification(total)
        total = min(total, 100.0)
        level = self._determine_level(total)

        return int(total), level

    def _get_weights(self, file_type: str) -> Dict[str, float]:
        """根据文件类型获取权重配置"""
        if file_type in self.FILE_TYPE_WEIGHTS:
            return dict(self.FILE_TYPE_WEIGHTS[file_type])

        # 部分匹配
        for ftype, w in self.FILE_TYPE_WEIGHTS.items():
            if ftype in file_type or file_type in ftype:
                return dict(w)

        return dict(self.weights)

    def _apply_nonlinear_amplification(self, score: float) -> float:
        """
        应用非线性放大

        在低分区域(0-30)线性增长，中分区域(30-60)略微加速，
        高分区域(60-100)显著放大，使恶意文件更容易被检出。
        """
        if score <= 30:
            return score
        elif score <= 60:
            # 30-60 区域: 线性 + 轻微加速
            return 30 + (score - 30) * 1.1
        else:
            # 60-100 区域: 显著加速
            amplified = 60 + (score - 60) * 1.3
            return min(amplified, 100.0)

    def _determine_level(self, score: float) -> int:
        """根据分数确定威胁等级"""
        for level in sorted(self.thresholds.keys(), reverse=True):
            if score >= self.thresholds[level]:
                return level
        return 0

    # ============================================================
    # 配置方法
    # ============================================================

    def set_weight(self, dimension: str, weight: float):
        """设置某个维度的权重"""
        if dimension in self.weights:
            self.weights[dimension] = weight
        else:
            self.weights[dimension] = weight

    def set_threshold(self, level: int, threshold: float):
        """设置某个等级的阈值"""
        self.thresholds[level] = threshold

    def get_weights(self) -> Dict[str, float]:
        """获取当前权重配置"""
        return dict(self.weights)

    def get_thresholds(self) -> Dict[int, float]:
        """获取当前阈值配置"""
        return dict(self.thresholds)

    def get_level_result(self, level: int) -> int:
        """获取威胁等级对应的检测结果"""
        return self.LEVEL_RESULTS.get(level, 0)

    # ============================================================
    # 报告生成
    # ============================================================

    def generate_summary(self, report: ScoreReport) -> str:
        """生成评分摘要文字"""
        lines = [
            f"文件: {report.file_name}",
            f"类型: {report.file_type}",
            f"总分: {report.total_score}/100",
            f"威胁等级: {report.threat_level_name}",
            f"分析时间: {report.analysis_time_ms:.1f}ms",
            "",
            "各维度评分:",
        ]

        for dim in report.dimensions:
            if dim.raw_score > 0:
                lines.append(f"  - {dim.name}: {dim.raw_score:.1f}分 (权重{dim.weight:.2f})")

        if report.all_reasons:
            lines.append("")
            lines.append("检测原因:")
            for i, reason in enumerate(report.all_reasons[:15], 1):
                lines.append(f"  {i}. {reason}")

        if report.top_contributors:
            lines.append("")
            lines.append("主要贡献因素:")
            for name, score in report.top_contributors:
                lines.append(f"  - {name}: {score:.1f}分")

        return '\n'.join(lines)

    def get_risk_level_description(self, level: int) -> str:
        """获取风险等级说明"""
        descriptions = {
            5: '严重威胁: 文件极有可能包含恶意代码，建议立即隔离处理',
            4: '高危威胁: 文件包含明显的恶意特征，建议隔离处理',
            3: '中等威胁: 文件存在可疑特征，建议进一步分析',
            2: '低危威胁: 文件存在轻微可疑特征，建议关注',
            1: '信息提示: 文件存在非恶意但值得注意的特征',
            0: '无害: 文件未检测到可疑特征',
        }
        return descriptions.get(level, '未知风险等级')


# ============================================================
# 评分聚合器
# ============================================================
class ScoreAggregator:
    """
    多文件评分聚合器

    用于批量扫描时汇总多个文件的评分结果，生成统计报告。
    """

    def __init__(self):
        self.results: List[ScoreReport] = []
        self._start_time = 0.0

    def start(self):
        """开始聚合"""
        self._start_time = time.time()
        self.results.clear()

    def add(self, report: ScoreReport):
        """添加一个评分结果"""
        self.results.append(report)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        if not self.results:
            return {}

        total = len(self.results)
        scores = [r.total_score for r in self.results]
        threats = sum(1 for r in self.results if r.threat_level >= 3)
        suspicious = sum(1 for r in self.results if r.threat_level == 2)
        clean = sum(1 for r in self.results if r.threat_level <= 1)

        return {
            'total_files': total,
            'threats': threats,
            'suspicious': suspicious,
            'clean': clean,
            'avg_score': sum(scores) / total if total > 0 else 0,
            'max_score': max(scores) if scores else 0,
            'min_score': min(scores) if scores else 0,
            'elapsed_seconds': time.time() - self._start_time,
        }