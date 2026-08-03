#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 启发式分析引擎
集成PE分析、脚本分析、文档分析、通用分析、评分系统
不依赖病毒库，通过分析文件结构和行为特征检测未知威胁
"""

import os
import sys
import time
from typing import Optional, List, Dict, Any, Tuple

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine import ScanEngine, ScanResult, ThreatInfo, ThreatType, ThreatLevel, HashUtil

from .pe_analyzer import PEAnalyzer
from .script_analyzer import ScriptAnalyzer
from .doc_analyzer import DocAnalyzer
from .generic_analyzer import GenericAnalyzer
from .scoring import ScoringSystem, ScoreReport


# ============================================================
# 文件类型与对应分析器映射
# ============================================================
PE_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.drv', '.ax', '.com'}
SCRIPT_EXTENSIONS = {'.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse',
                     '.wsf', '.wsh', '.bat', '.cmd', '.py', '.pyw'}
DOCUMENT_EXTENSIONS = {'.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx',
                       '.ppt', '.pptm', '.pptx', '.pdf', '.rtf',
                       '.dotx', '.dotm', '.xltx', '.xltm', '.potx', '.potm'}
GENERIC_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx',
                      '.doc', '.xls', '.ppt', '.pdf', '.zip', '.rar',
                      '.7z', '.gz', '.bz2', '.cab', '.msi'}

# 扩展名到文件类型映射
EXT_TO_FILE_TYPE = {
    '.exe': 'exe', '.dll': 'dll', '.sys': 'exe', '.scr': 'exe',
    '.cpl': 'exe', '.ocx': 'dll', '.drv': 'dll',
    '.ps1': 'script', '.psm1': 'script', '.vbs': 'script', '.js': 'script',
    '.bat': 'script', '.cmd': 'script', '.py': 'script', '.pyw': 'script',
    '.doc': 'document', '.docm': 'document', '.docx': 'document',
    '.xls': 'document', '.xlsm': 'document', '.xlsx': 'document',
    '.ppt': 'document', '.pptm': 'document', '.pptx': 'document',
    '.pdf': 'document', '.rtf': 'document',
}


class HeuristicEngine(ScanEngine):
    """
    启发式分析引擎

    不依赖病毒库，通过多维度分析文件特征检测未知威胁：
    - PE结构分析
    - 脚本分析
    - 文档分析
    - 通用文件分析
    - 多维度加权评分
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        初始化启发式引擎

        Args:
            config: 可选配置字典
                - heuristic_level: 'low', 'medium', 'high'
                - weights: 自定义权重
                - thresholds: 自定义阈值
                - max_file_size: 最大扫描文件大小(字节)
        """
        super().__init__('HeuristicEngine', enabled=True)
        self._project_root = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        self._exclusion_paths = [self._project_root]
        self.config = config or {}

        # 启发式级别
        self.heuristic_level = self.config.get('heuristic_level', 'medium')

        # 初始化分析器
        self.pe_analyzer = PEAnalyzer(self.config)
        self.script_analyzer = ScriptAnalyzer(self.config)
        self.doc_analyzer = DocAnalyzer(self.config)
        self.generic_analyzer = GenericAnalyzer(self.config)

        # 初始化评分系统
        score_config = {}
        if 'weights' in self.config:
            score_config['weights'] = self.config['weights']
        if 'thresholds' in self.config:
            score_config['thresholds'] = self.config['thresholds']
        self.scoring = ScoringSystem(score_config)

        # 根据启发式级别调整阈值
        self._adjust_level()

        # 统计
        self.stats = {'scanned': 0, 'detected': 0, 'errors': 0, 'time_ms': 0,
                      'pe_scanned': 0, 'script_scanned': 0,
                      'doc_scanned': 0, 'generic_scanned': 0}

    def _adjust_level(self):
        """根据启发式级别调整检测阈值"""
        if self.heuristic_level == 'low':
            # 低级别 - 减少误报，只检测明显恶意
            self.scoring.set_threshold(ThreatLevel.CRITICAL, 85)
            self.scoring.set_threshold(ThreatLevel.HIGH, 70)
            self.scoring.set_threshold(ThreatLevel.MEDIUM, 50)
            self.scoring.set_threshold(ThreatLevel.LOW, 35)
            self.scoring.set_threshold(ThreatLevel.INFO, 20)
        elif self.heuristic_level == 'high':
            # 高级别 - 提高检出率，增加误报风险
            self.scoring.set_threshold(ThreatLevel.CRITICAL, 70)
            self.scoring.set_threshold(ThreatLevel.HIGH, 50)
            self.scoring.set_threshold(ThreatLevel.MEDIUM, 30)
            self.scoring.set_threshold(ThreatLevel.LOW, 15)
            self.scoring.set_threshold(ThreatLevel.INFO, 5)
        # 'medium' 使用默认值

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """
        启发式扫描单个文件

        Args:
            filepath: 文件路径

        Returns:
            检测到威胁返回 ThreatInfo，否则返回 None
        """
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None

        # Skip own project files
        abs_path = os.path.abspath(filepath)
        for excl in self._exclusion_paths:
            if abs_path.startswith(excl):
                self.stats['scanned'] += 1
                return None

        start_time = time.time()

        try:
            ext = os.path.splitext(filepath)[1].lower()
            file_size = os.path.getsize(filepath)

            # 检查文件大小限制
            max_size = self.config.get('max_file_size', 100 * 1024 * 1024)  # 默认100MB
            if file_size > max_size:
                self.stats['scanned'] += 1
                return None

            # 收集各维度评分和原因
            scores = {}
            all_reasons = {}
            all_details = {}

            # ============================================================
            # 1. PE文件分析
            # ============================================================
            if ext in PE_EXTENSIONS:
                pe_score, pe_reasons, pe_details = self.pe_analyzer.analyze(filepath)
                if pe_score > 0:
                    scores['pe_analysis'] = pe_score
                    all_reasons['pe_analysis'] = pe_reasons
                    all_details['pe_analysis'] = pe_details
                self.stats['pe_scanned'] += 1

            # ============================================================
            # 2. 脚本分析
            # ============================================================
            if ext in SCRIPT_EXTENSIONS:
                script_score, script_reasons, script_details = self.script_analyzer.analyze(filepath)
                if script_score > 0:
                    scores['script_analysis'] = script_score
                    all_reasons['script_analysis'] = script_reasons
                    all_details['script_analysis'] = script_details
                self.stats['script_scanned'] += 1

            # ============================================================
            # 3. 文档分析
            # ============================================================
            if ext in DOCUMENT_EXTENSIONS:
                doc_score, doc_reasons, doc_details = self.doc_analyzer.analyze(filepath)
                if doc_score > 0:
                    scores['document_analysis'] = doc_score
                    all_reasons['document_analysis'] = doc_reasons
                    all_details['document_analysis'] = doc_details
                self.stats['doc_scanned'] += 1

            # ============================================================
            # 4. 通用分析（对所有文件执行）
            # ============================================================
            generic_score, generic_reasons, generic_details = self.generic_analyzer.analyze(filepath)
            if generic_score > 0:
                scores['generic_analysis'] = generic_score
                all_reasons['generic_analysis'] = generic_reasons
                all_details['generic_analysis'] = generic_details
            self.stats['generic_scanned'] += 1

            # ============================================================
            # 5. 如果没有检测到任何特征，返回None
            # ============================================================
            if not scores:
                self.stats['scanned'] += 1
                return None

            # ============================================================
            # 6. 计算综合评分
            # ============================================================
            file_type = EXT_TO_FILE_TYPE.get(ext, 'generic')
            total_score, level, report = self.scoring.calculate(
                scores=scores,
                file_type=file_type,
                reasons=all_reasons,
                details=all_details,
            )

            # 设置报告文件信息
            report.file_path = filepath
            report.file_name = os.path.basename(filepath)
            report.file_size = file_size
            report.file_type = file_type
            report.analysis_time_ms = (time.time() - start_time) * 1000

            # ============================================================
            # 7. 根据评分决定检测结果
            # ============================================================
            self.stats['scanned'] += 1
            self.stats['time_ms'] += report.analysis_time_ms

            # 获取检测结果
            result = self.scoring.get_level_result(level)

            if result == ScanResult.CLEAN:
                return None

            # 创建威胁信息
            threat = ThreatInfo(
                file_path=filepath,
                threat_type=ThreatType.HEURISTIC,
                threat_name=self._generate_threat_name(total_score, file_type, all_reasons),
                scan_engine=self.name,
                threat_level=level,
                result=result,
            )

            # 计算哈希
            try:
                threat.md5, threat.sha1, threat.sha256 = HashUtil.compute_all(filepath)
            except Exception:
                pass

            # 填充详细信息
            threat.details = {
                'score': total_score,
                'level': level,
                'level_name': report.threat_level_name,
                'scores': scores,
                'reasons': report.all_reasons[:15],  # 最多15个原因
                'top_contributors': report.top_contributors,
                'analysis_time_ms': round(report.analysis_time_ms, 1),
                'heuristic_level': self.heuristic_level,
                'report': report.to_dict(),
            }

            self.stats['detected'] += 1
            return threat

        except Exception as e:
            self.stats['errors'] += 1
            self.stats['scanned'] += 1
            return None

    def scan_batch(self, filepaths: List[str],
                   callback=None) -> List[ThreatInfo]:
        """
        批量扫描文件

        Args:
            filepaths: 文件路径列表
            callback: 可选的回调对象 (ScanCallback)

        Returns:
            检测到的威胁列表
        """
        results = []
        total = len(filepaths)

        for i, fp in enumerate(filepaths):
            # 检查是否被取消
            if callback and callback.is_cancelled():
                break

            try:
                # 进度回调
                if callback and callback.on_progress:
                    callback.on_progress(i + 1, total)

                # 文件开始回调
                if callback and callback.on_file_start:
                    callback.on_file_start(fp)

                # 执行扫描
                result = self.scan(fp)

                # 文件完成回调
                if callback and callback.on_file_complete:
                    callback.on_file_complete(fp, result)

                if result:
                    results.append(result)
                    # 威胁发现回调
                    if callback and callback.on_threat_found:
                        callback.on_threat_found(result)

            except Exception as e:
                self.stats['errors'] += 1
                if callback and callback.on_error:
                    callback.on_error(fp, str(e))

        return results

    def analyze_with_report(self, filepath: str) -> Optional[ScoreReport]:
        """
        分析文件并返回详细评分报告

        Args:
            filepath: 文件路径

        Returns:
            ScoreReport 详细评分报告，或 None
        """
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None

        start_time = time.time()

        try:
            ext = os.path.splitext(filepath)[1].lower()

            scores = {}
            all_reasons = {}
            all_details = {}

            # PE分析
            if ext in PE_EXTENSIONS:
                pe_score, pe_reasons, pe_details = self.pe_analyzer.analyze(filepath)
                if pe_score > 0:
                    scores['pe_analysis'] = pe_score
                    all_reasons['pe_analysis'] = pe_reasons
                    all_details['pe_analysis'] = pe_details

            # 脚本分析
            if ext in SCRIPT_EXTENSIONS:
                s_score, s_reasons, s_details = self.script_analyzer.analyze(filepath)
                if s_score > 0:
                    scores['script_analysis'] = s_score
                    all_reasons['script_analysis'] = s_reasons
                    all_details['script_analysis'] = s_details

            # 文档分析
            if ext in DOCUMENT_EXTENSIONS:
                d_score, d_reasons, d_details = self.doc_analyzer.analyze(filepath)
                if d_score > 0:
                    scores['document_analysis'] = d_score
                    all_reasons['document_analysis'] = d_reasons
                    all_details['document_analysis'] = d_details

            # 通用分析
            g_score, g_reasons, g_details = self.generic_analyzer.analyze(filepath)
            if g_score > 0:
                scores['generic_analysis'] = g_score
                all_reasons['generic_analysis'] = g_reasons
                all_details['generic_analysis'] = g_details

            if not scores:
                return None

            file_type = EXT_TO_FILE_TYPE.get(ext, 'generic')
            _, _, report = self.scoring.calculate(
                scores=scores,
                file_type=file_type,
                reasons=all_reasons,
                details=all_details,
            )

            # 填充报告信息
            report.file_path = filepath
            report.file_name = os.path.basename(filepath)
            report.file_size = os.path.getsize(filepath)
            report.file_type = file_type
            report.analysis_time_ms = (time.time() - start_time) * 1000

            return report

        except Exception:
            return None

    def _generate_threat_name(self, score: int, file_type: str,
                              reasons: Dict[str, List[str]]) -> str:
        """生成威胁名称"""
        # 收集所有原因
        all_reasons = []
        for rlist in reasons.values():
            all_reasons.extend(rlist)

        # 根据主要特征命名
        threat_type = 'Unknown'
        for reason in all_reasons:
            rl = reason.lower()
            if 'inject' in rl or 'injection' in rl:
                threat_type = 'Injector'
                break
            if 'shellcode' in rl or 'virtualalloc' in rl:
                threat_type = 'Shellcode'
                break
            if 'download' in rl:
                threat_type = 'Downloader'
                break
            if 'keylog' in rl or 'keyboard' in rl:
                threat_type = 'Keylogger'
                break
            if 'encrypt' in rl or 'ransom' in rl:
                threat_type = 'Ransomware'
                break
            if 'packer' in rl or 'packed' in rl or 'upx' in rl:
                threat_type = 'Packed'
                break
            if 'macro' in rl or 'vba' in rl:
                threat_type = 'Macro'
                break
            if 'obfus' in rl or 'confus' in rl:
                threat_type = 'Obfuscated'
                break
            if 'persist' in rl:
                threat_type = 'Persist'
                break
            if 'exploit' in rl or 'heap' in rl:
                threat_type = 'Exploit'
                break
            if 'amsi' in rl or 'bypass' in rl:
                threat_type = 'Bypass'
                break
            if 'mimikatz' in rl or 'password' in rl:
                threat_type = 'CredentialDumper'
                break
            if 'miner' in rl or 'coin' in rl:
                threat_type = 'CoinMiner'
                break
            if 'dropper' in rl:
                threat_type = 'Dropper'
                break
            if 'worm' in rl:
                threat_type = 'Worm'
                break
            if 'backdoor' in rl or 'c2' in rl or 'beacon' in rl:
                threat_type = 'Backdoor'
                break
            if 'rat' in rl:
                threat_type = 'RAT'
                break

        return f'Heuristic.{threat_type}.{file_type}.{score}'

    def get_stats(self) -> Dict:
        """获取引擎统计信息"""
        stats = dict(self.stats)
        stats['pe_analyzer'] = 'loaded'
        stats['script_analyzer'] = 'loaded'
        stats['doc_analyzer'] = 'loaded'
        stats['generic_analyzer'] = 'loaded'
        stats['scoring'] = 'loaded'
        stats['heuristic_level'] = self.heuristic_level
        return stats

    def reset_stats(self):
        """重置统计信息"""
        self.stats = {'scanned': 0, 'detected': 0, 'errors': 0, 'time_ms': 0,
                      'pe_scanned': 0, 'script_scanned': 0,
                      'doc_scanned': 0, 'generic_scanned': 0}

    def get_report(self, threat: ThreatInfo) -> str:
        """获取可读的检测报告"""
        if not threat or not threat.details:
            return '无检测报告'

        details = threat.details
        lines = [
            f'文件: {threat.file_name}',
            f'路径: {threat.file_path}',
            f'大小: {threat.file_size} 字节',
            f'威胁: {threat.threat_name}',
            f'等级: {ThreatLevel.NAMES.get(threat.threat_level, "未知")}',
            f'分数: {details.get("score", 0)}/100',
            f'分析时间: {details.get("analysis_time_ms", 0):.1f}ms',
            f'启发式级别: {details.get("heuristic_level", "medium")}',
            '',
            '各维度评分:',
        ]

        scores = details.get('scores', {})
        for dim, sc in scores.items():
            lines.append(f'  {dim}: {sc:.1f}分')

        reasons = details.get('reasons', [])
        if reasons:
            lines.append('')
            lines.append('检测原因:')
            for i, reason in enumerate(reasons, 1):
                lines.append(f'  {i}. {reason}')

        top = details.get('top_contributors', [])
        if top:
            lines.append('')
            lines.append('主要贡献因素:')
            for name, sc in top:
                lines.append(f'  {name}: {sc:.1f}分')

        return '\n'.join(lines)