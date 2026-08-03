#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 数据分析与可视化工具
"""
import os
import sys
import json
import time
import math
import csv
import io
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DataAnalyzer:
    """数据分析器"""

    @staticmethod
    def analyze_threat_data(threats: List[Dict]) -> Dict:
        """分析威胁数据"""
        analysis = {
            'total_threats': len(threats),
            'by_type': Counter(),
            'by_level': Counter(),
            'by_engine': Counter(),
            'by_hour': Counter(),
            'by_date': Counter(),
            'top_threats': [],
            'timeline': [],
        }
        for t in threats:
            analysis['by_type'][t.get('threat_type', 'unknown')] += 1
            analysis['by_level'][t.get('threat_level', 0)] += 1
            analysis['by_engine'][t.get('scan_engine', 'unknown')] += 1
            ts = t.get('timestamp', time.time())
            hour = datetime.fromtimestamp(ts).hour
            analysis['by_hour'][hour] += 1
            date = datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
            analysis['by_date'][date] += 1
            analysis['timeline'].append({
                'date': date,
                'time': datetime.fromtimestamp(ts).strftime('%H:%M'),
                'name': t.get('threat_name', ''),
                'type': t.get('threat_type', ''),
                'level': t.get('threat_level', 0),
            })
        # 排序
        analysis['top_threats'] = analysis['by_type'].most_common(10)
        analysis['timeline'] = sorted(analysis['timeline'],
                                      key=lambda x: x['date'] + x['time'])
        return analysis

    @staticmethod
    def analyze_scan_history(scans: List[Dict]) -> Dict:
        """分析扫描历史"""
        analysis = {
            'total_scans': len(scans),
            'by_mode': Counter(),
            'total_files': 0,
            'total_threats': 0,
            'avg_duration': 0,
            'avg_files_per_scan': 0,
            'scan_timeline': [],
        }
        durations = []
        for s in scans:
            analysis['by_mode'][s.get('scan_mode', 'unknown')] += 1
            analysis['total_files'] += s.get('scanned_files', 0)
            analysis['total_threats'] += s.get('threats_found', 0)
            durations.append(s.get('duration_seconds', 0))
            analysis['scan_timeline'].append({
                'time': s.get('start_time', ''),
                'mode': s.get('scan_mode', ''),
                'files': s.get('scanned_files', 0),
                'threats': s.get('threats_found', 0),
                'duration': s.get('duration_seconds', 0),
            })
        if durations:
            analysis['avg_duration'] = sum(durations) / len(durations)
        if scans:
            analysis['avg_files_per_scan'] = analysis['total_files'] / len(scans)
        return analysis

    @staticmethod
    def detect_anomalies(data: List[float], threshold: float = 2.0) -> List[int]:
        """检测异常值"""
        if len(data) < 3:
            return []
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        std = math.sqrt(variance)
        anomalies = []
        for i, value in enumerate(data):
            if abs(value - mean) > threshold * std:
                anomalies.append(i)
        return anomalies

    @staticmethod
    def calculate_statistics(data: List[float]) -> Dict:
        """计算统计信息"""
        if not data:
            return {}
        sorted_data = sorted(data)
        n = len(sorted_data)
        mean = sum(sorted_data) / n
        variance = sum((x - mean) ** 2 for x in sorted_data) / n
        std = math.sqrt(variance)
        return {
            'count': n,
            'min': min(sorted_data),
            'max': max(sorted_data),
            'mean': round(mean, 2),
            'median': sorted_data[n // 2] if n % 2 else (sorted_data[n // 2 - 1] + sorted_data[n // 2]) / 2,
            'std': round(std, 2),
            'variance': round(variance, 2),
            'p25': sorted_data[int(n * 0.25)],
            'p50': sorted_data[int(n * 0.50)],
            'p75': sorted_data[int(n * 0.75)],
            'p95': sorted_data[int(n * 0.95)],
            'p99': sorted_data[int(n * 0.99)],
        }

    @staticmethod
    def calculate_correlation(x: List[float], y: List[float]) -> float:
        """计算相关系数"""
        if len(x) != len(y) or len(x) < 2:
            return 0.0
        n = len(x)
        mean_x = sum(x) / n
        mean_y = sum(y) / n
        cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
        std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x) / n)
        std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y) / n)
        if std_x == 0 or std_y == 0:
            return 0.0
        return cov / (n * std_x * std_y)

    @staticmethod
    def moving_average(data: List[float], window: int = 3) -> List[float]:
        """移动平均"""
        if len(data) < window:
            return data
        result = []
        for i in range(len(data)):
            start = max(0, i - window + 1)
            end = i + 1
            result.append(sum(data[start:end]) / (end - start))
        return result

    @staticmethod
    def exponential_moving_average(data: List[float], alpha: float = 0.3) -> List[float]:
        """指数移动平均"""
        if not data:
            return []
        result = [data[0]]
        for i in range(1, len(data)):
            result.append(alpha * data[i] + (1 - alpha) * result[-1])
        return result


class ReportExporter:
    """报告导出器"""

    @staticmethod
    def export_csv(data: List[Dict], filepath: str) -> bool:
        """导出 CSV"""
        try:
            if not data:
                return False
            with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            return True
        except Exception:
            return False

    @staticmethod
    def export_json(data: Any, filepath: str, pretty: bool = True) -> bool:
        """导出 JSON"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2 if pretty else None)
            return True
        except Exception:
            return False

    @staticmethod
    def export_html(data: Dict, filepath: str, title: str = 'Report') -> bool:
        """导出 HTML 报告"""
        try:
            html = ReportExporter._generate_html(data, title)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
            return True
        except Exception:
            return False

    @staticmethod
    def _generate_html(data: Dict, title: str) -> str:
        """生成 HTML"""
        def render_value(key, value, indent=0):
            if isinstance(value, dict):
                rows = ''.join(f'<tr><td>{k}</td><td>{v}</td></tr>'
                              for k, v in value.items())
                return f'<table>{rows}</table>'
            elif isinstance(value, list):
                items = ''.join(f'<li>{v}</li>' for v in value[:20])
                if len(value) > 20:
                    items += f'<li>... and {len(value) - 20} more</li>'
                return f'<ul>{items}</ul>'
            else:
                return str(value)

        rows = ''.join(
            f'<tr><td style="font-weight:bold">{k}</td><td>{render_value(k, v)}</td></tr>'
            for k, v in data.items()
        )
        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>{title}</title>
<style>
body {{ font-family: 'Microsoft YaHei', sans-serif; margin: 40px; color: #333; }}
h1 {{ color: #1a73e8; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
tr:hover {{ background-color: #f5f5f5; }}
</style></head>
<body>
<h1>{title}</h1>
<p>生成时间: {datetime.now().isoformat()}</p>
<table>{rows}</table>
</body></html>'''


class LogParser:
    """日志解析器"""

    @staticmethod
    def parse_tiandun_log(filepath: str) -> List[Dict]:
        """解析天盾日志"""
        entries = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    try:
                        parts = line.strip().split(' | ')
                        if len(parts) >= 4:
                            entries.append({
                                'timestamp': parts[0],
                                'level': parts[1].strip(),
                                'module': parts[2].strip(),
                                'message': ' | '.join(parts[3:]),
                            })
                    except Exception:
                        pass
            return entries
        except Exception:
            return []

    @staticmethod
    def parse_scan_log(filepath: str) -> List[Dict]:
        """解析扫描日志"""
        entries = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    try:
                        parts = line.strip().split(' | ')
                        if len(parts) >= 5:
                            entries.append({
                                'timestamp': parts[0],
                                'result': parts[1].strip(),
                                'engine': parts[2].strip(),
                                'threat_name': parts[3].strip(),
                                'duration_ms': parts[4].strip(),
                                'filepath': parts[5].strip() if len(parts) > 5 else '',
                            })
                    except Exception:
                        pass
            return entries
        except Exception:
            return []

    @staticmethod
    def parse_threat_log(filepath: str) -> List[Dict]:
        """解析威胁日志"""
        threats = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    try:
                        threats.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
            return threats
        except Exception:
            return []


class DataVisualizer:
    """数据可视化器"""

    @staticmethod
    def generate_timeline_chart(data: List[Dict], date_key: str = 'date',
                                 value_key: str = 'count', title: str = 'Timeline') -> str:
        """生成时间线图表（文本格式）"""
        if not data:
            return '无数据'
        lines = [f'\n{"=" * 60}', f'  {title}', f'{"=" * 60}']
        max_val = max(d.get(value_key, 0) for d in data)
        for d in data:
            label = d.get(date_key, '')
            val = d.get(value_key, 0)
            bar_len = int(val / max_val * 40) if max_val > 0 else 0
            bar = '█' * bar_len
            lines.append(f'  {label} | {bar} {val}')
        lines.append(f'{"=" * 60}')
        return '\n'.join(lines)

    @staticmethod
    def generate_bar_chart(counter: Counter, max_items: int = 10,
                           title: str = 'Bar Chart') -> str:
        """生成柱状图（文本格式）"""
        items = counter.most_common(max_items)
        if not items:
            return '无数据'
        lines = [f'\n{"=" * 60}', f'  {title}', f'{"=" * 60}']
        max_val = max(v for _, v in items)
        for label, val in items:
            bar_len = int(val / max_val * 30) if max_val > 0 else 0
            bar = '█' * bar_len
            lines.append(f'  {label:20s} | {bar} {val}')
        lines.append(f'{"=" * 60}')
        return '\n'.join(lines)

    @staticmethod
    def generate_pie_chart(counter: Counter, max_items: int = 8,
                           title: str = 'Pie Chart') -> str:
        """生成饼图（文本格式）"""
        items = counter.most_common(max_items)
        if not items:
            return '无数据'
        total = sum(v for _, v in items)
        lines = [f'\n{"=" * 60}', f'  {title}', f'{"=" * 60}']
        symbols = ['●', '◆', '■', '▲', '▼', '◆', '●', '■']
        for i, (label, val) in enumerate(items):
            pct = val / total * 100 if total > 0 else 0
            sym = symbols[i % len(symbols)]
            bar_len = int(pct / 2)
            bar = '─' * bar_len
            lines.append(f'  {sym} {label:20s} {bar} {val:5d} ({pct:5.1f}%)')
        lines.append(f'  {"─" * 40}')
        lines.append(f'  {"总计":20s} {total:5d} (100.0%)')
        lines.append(f'{"=" * 60}')
        return '\n'.join(lines)

    @staticmethod
    def generate_heatmap(data: List[List[int]], row_labels: List[str],
                          col_labels: List[str], title: str = 'Heatmap') -> str:
        """生成热力图（文本格式）"""
        if not data or not row_labels or not col_labels:
            return '无数据'
        lines = [f'\n{title}']
        max_val = max(max(row) for row in data)
        header = '     ' + ' '.join(f'{c:4s}' for c in col_labels)
        lines.append(header)
        for i, row in enumerate(data):
            row_str = ' '.join(
                ' █' if v > max_val * 0.75 else
                ' ▓' if v > max_val * 0.5 else
                ' ▒' if v > max_val * 0.25 else
                ' ░' if v > 0 else '  '
                for v in row
            )
            lines.append(f'{row_labels[i]:4s} {row_str}')
        return '\n'.join(lines)


class DataAggregator:
    """数据聚合器"""

    @staticmethod
    def aggregate_by_time(data: List[Dict], time_key: str = 'timestamp',
                          value_key: str = 'count', interval: str = 'hour') -> Dict:
        """按时间聚合"""
        result = defaultdict(int)
        for d in data:
            ts = d.get(time_key, 0)
            if isinstance(ts, (int, float)):
                dt = datetime.fromtimestamp(ts)
            else:
                try:
                    dt = datetime.fromisoformat(ts)
                except Exception:
                    continue
            if interval == 'hour':
                key = dt.strftime('%Y-%m-%d %H:00')
            elif interval == 'day':
                key = dt.strftime('%Y-%m-%d')
            elif interval == 'month':
                key = dt.strftime('%Y-%m')
            else:
                key = dt.strftime('%Y-%m-%d %H:00')
            result[key] += d.get(value_key, 1)
        return dict(result)

    @staticmethod
    def aggregate_by_category(data: List[Dict], category_key: str,
                               value_key: str = 'count') -> Dict:
        """按类别聚合"""
        result = defaultdict(int)
        for d in data:
            category = d.get(category_key, 'unknown')
            result[category] += d.get(value_key, 1)
        return dict(result)

    @staticmethod
    def pivot_table(data: List[Dict], rows: str, cols: str,
                    values: str, agg_func: str = 'sum') -> Dict:
        """数据透视表"""
        result = defaultdict(lambda: defaultdict(float))
        for d in data:
            row_val = d.get(rows, '')
            col_val = d.get(cols, '')
            val = d.get(values, 0)
            if agg_func == 'sum':
                result[row_val][col_val] += val
            elif agg_func == 'count':
                result[row_val][col_val] += 1
            elif agg_func == 'max':
                result[row_val][col_val] = max(result[row_val][col_val], val)
            elif agg_func == 'min':
                result[row_val][col_val] = min(result[row_val][col_val], val) if result[row_val][col_val] else val
        return {str(k): dict(v) for k, v in result.items()}


class PatternFinder:
    """模式查找器"""

    @staticmethod
    def find_sequences(data: List[int], min_length: int = 2) -> List[Tuple]:
        """查找序列模式"""
        sequences = []
        i = 0
        while i < len(data):
            j = i + 1
            while j < len(data) and data[j] == data[i] + (j - i):
                j += 1
            if j - i >= min_length:
                sequences.append((i, j - i, data[i:j]))
                i = j
            else:
                i += 1
        return sequences

    @staticmethod
    def find_cycles(data: List[float], min_period: int = 2,
                    max_period: int = 100) -> List[Dict]:
        """查找周期模式"""
        cycles = []
        n = len(data)
        for period in range(min_period, min(max_period, n // 2)):
            matches = 0
            for i in range(n - period):
                if abs(data[i] - data[i + period]) < 0.1:
                    matches += 1
            if matches > n * 0.7:
                cycles.append({
                    'period': period,
                    'confidence': matches / (n - period),
                })
        return sorted(cycles, key=lambda x: x['confidence'], reverse=True)[:5]


class DataFilter:
    """数据过滤器"""

    @staticmethod
    def filter_by_date(data: List[Dict], date_key: str = 'timestamp',
                        start: float = None, end: float = None) -> List[Dict]:
        """按日期过滤"""
        if start is None:
            start = 0
        if end is None:
            end = time.time()
        return [d for d in data if start <= d.get(date_key, 0) <= end]

    @staticmethod
    def filter_by_field(data: List[Dict], field: str, value: Any) -> List[Dict]:
        """按字段过滤"""
        return [d for d in data if d.get(field) == value]

    @staticmethod
    def filter_by_regex(data: List[Dict], field: str, pattern: str) -> List[Dict]:
        """按正则表达式过滤"""
        import re
        regex = re.compile(pattern)
        return [d for d in data if regex.search(str(d.get(field, '')))]

    @staticmethod
    def top_n(data: List[Dict], sort_by: str, n: int = 10,
              reverse: bool = True) -> List[Dict]:
        """取前N条"""
        return sorted(data, key=lambda x: x.get(sort_by, 0), reverse=reverse)[:n]


class DataSampler:
    """数据采样器"""

    @staticmethod
    def random_sample(data: List, sample_size: int) -> List:
        """随机采样"""
        import random
        if len(data) <= sample_size:
            return list(data)
        return random.sample(data, sample_size)

    @staticmethod
    def systematic_sample(data: List, step: int) -> List:
        """系统采样"""
        return [data[i] for i in range(0, len(data), step)]

    @staticmethod
    def stratified_sample(data: List[Dict], strata_key: str,
                          sample_size: int) -> List:
        """分层采样"""
        strata = defaultdict(list)
        for d in data:
            strata[d.get(strata_key, 'unknown')].append(d)
        result = []
        import random
        for group in strata.values():
            if len(group) <= sample_size // len(strata):
                result.extend(group)
            else:
                result.extend(random.sample(group, sample_size // len(strata)))
        return result