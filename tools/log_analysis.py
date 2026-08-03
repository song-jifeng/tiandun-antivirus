#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 日志分析与管理工具
包含日志解析、分析、报告生成功能
"""
import os
import sys
import json
import time
import re
import gzip
import shutil
from typing import Dict, List, Optional, Any
from collections import Counter, defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class LogAnalyzer:
    """日志分析器"""

    @staticmethod
    def analyze_tiandun_logs(log_dir: str = None) -> Dict:
        """分析天盾日志"""
        if log_dir is None:
            log_dir = os.environ.get('TIANDUN_LOGS', 'D:/Antivirus/logs')
        analysis = {
            'log_dir': log_dir,
            'total_files': 0,
            'total_size': 0,
            'total_lines': 0,
            'by_level': Counter(),
            'by_module': Counter(),
            'by_hour': Counter(),
            'errors': [],
            'warnings': [],
            'time_range': {'start': None, 'end': None},
        }
        if not os.path.exists(log_dir):
            return analysis
        for f in os.listdir(log_dir):
            fpath = os.path.join(log_dir, f)
            if os.path.isfile(fpath) and f.endswith('.log'):
                analysis['total_files'] += 1
                analysis['total_size'] += os.path.getsize(fpath)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                        for line in fh:
                            analysis['total_lines'] += 1
                            parts = line.strip().split(' | ')
                            if len(parts) >= 4:
                                level = parts[1].strip()
                                module = parts[2].strip()
                                analysis['by_level'][level] += 1
                                analysis['by_module'][module] += 1
                                try:
                                    hour = parts[0].split(' ')[1].split(':')[0]
                                    analysis['by_hour'][int(hour)] += 1
                                except (IndexError, ValueError):
                                    pass
                                if level == 'ERROR':
                                    analysis['errors'].append(line.strip()[:200])
                                elif level == 'WARNING':
                                    analysis['warnings'].append(line.strip()[:200])
                                if analysis['time_range']['start'] is None:
                                    analysis['time_range']['start'] = parts[0]
                                analysis['time_range']['end'] = parts[0]
                except Exception:
                    pass
        # 截断
        analysis['errors'] = analysis['errors'][-100:]
        analysis['warnings'] = analysis['warnings'][-100:]
        analysis['by_level'] = dict(analysis['by_level'].most_common())
        analysis['by_module'] = dict(analysis['by_module'].most_common(20))
        analysis['by_hour'] = dict(sorted(analysis['by_hour'].items()))
        return analysis

    @staticmethod
    def analyze_scan_results(log_dir: str = None) -> Dict:
        """分析扫描结果日志"""
        if log_dir is None:
            log_dir = os.environ.get('TIANDUN_LOGS', 'D:/Antivirus/logs')
        analysis = {
            'total_scans': 0,
            'clean_files': 0,
            'malicious_files': 0,
            'suspicious_files': 0,
            'errors': 0,
            'by_engine': Counter(),
            'by_threat': Counter(),
            'recent_threats': [],
        }
        scan_log = os.path.join(log_dir, 'scan_results.log')
        if os.path.exists(scan_log):
            try:
                with open(scan_log, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        analysis['total_scans'] += 1
                        parts = line.strip().split(' | ')
                        if len(parts) >= 5:
                            result = parts[1].strip()
                            engine = parts[2].strip()
                            threat = parts[3].strip()
                            if result == 'MALICIOUS':
                                analysis['malicious_files'] += 1
                                analysis['by_threat'][threat] += 1
                                analysis['recent_threats'].append(line.strip()[:300])
                            elif result == 'SUSPICIOUS':
                                analysis['suspicious_files'] += 1
                            elif result == 'CLEAN':
                                analysis['clean_files'] += 1
                            elif result == 'ERROR':
                                analysis['errors'] += 1
                            analysis['by_engine'][engine] += 1
            except Exception:
                pass
        analysis['recent_threats'] = analysis['recent_threats'][-50:]
        analysis['by_engine'] = dict(analysis['by_engine'].most_common())
        analysis['by_threat'] = dict(analysis['by_threat'].most_common(20))
        return analysis

    @staticmethod
    def analyze_threat_logs(log_dir: str = None) -> Dict:
        """分析威胁日志"""
        if log_dir is None:
            log_dir = os.environ.get('TIANDUN_LOGS', 'D:/Antivirus/logs')
        analysis = {
            'total_threats': 0,
            'by_type': Counter(),
            'by_level': Counter(),
            'by_engine': Counter(),
            'by_date': Counter(),
            'by_hour': Counter(),
            'recent_threats': [],
        }
        threat_log = os.path.join(log_dir, 'threats.log')
        if os.path.exists(threat_log):
            try:
                with open(threat_log, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        try:
                            threat = json.loads(line.strip())
                            analysis['total_threats'] += 1
                            analysis['by_type'][threat.get('threat_type', 'unknown')] += 1
                            analysis['by_level'][threat.get('threat_level', 0)] += 1
                            analysis['by_engine'][threat.get('scan_engine', 'unknown')] += 1
                            ts = threat.get('timestamp', 0)
                            try:
                                dt = datetime.fromtimestamp(ts)
                                analysis['by_date'][dt.strftime('%Y-%m-%d')] += 1
                                analysis['by_hour'][dt.hour] += 1
                            except Exception:
                                pass
                            analysis['recent_threats'].append(threat)
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass
        analysis['recent_threats'] = analysis['recent_threats'][-50:]
        analysis['by_type'] = dict(analysis['by_type'].most_common())
        analysis['by_level'] = {str(k): v for k, v in analysis['by_level'].most_common()}
        analysis['by_engine'] = dict(analysis['by_engine'].most_common())
        analysis['by_date'] = dict(sorted(analysis['by_date'].items()))
        analysis['by_hour'] = dict(sorted(analysis['by_hour'].items()))
        return analysis


class LogManager:
    """日志管理器"""

    def __init__(self, log_dir: str = None):
        self.log_dir = log_dir or os.environ.get('TIANDUN_LOGS', 'D:/Antivirus/logs')
        os.makedirs(self.log_dir, exist_ok=True)

    def rotate_logs(self, max_size_mb: int = 50, keep_count: int = 10):
        """轮转日志"""
        for f in os.listdir(self.log_dir):
            if f.endswith('.log'):
                fpath = os.path.join(self.log_dir, f)
                size_mb = os.path.getsize(fpath) / (1024 * 1024)
                if size_mb > max_size_mb:
                    # 压缩旧日志
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    archive_name = f"{f}.{timestamp}.gz"
                    archive_path = os.path.join(self.log_dir, archive_name)
                    with open(fpath, 'rb') as f_in:
                        with gzip.open(archive_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    # 清空原日志
                    with open(fpath, 'w') as fh:
                        fh.write(f"# Log rotated at {datetime.now().isoformat()}\n")
        # 清理旧归档
        archives = sorted([f for f in os.listdir(self.log_dir) if f.endswith('.gz')])
        while len(archives) > keep_count:
            oldest = archives.pop(0)
            try:
                os.remove(os.path.join(self.log_dir, oldest))
            except Exception:
                pass

    def get_log_files(self) -> List[Dict]:
        """获取日志文件列表"""
        files = []
        for f in sorted(os.listdir(self.log_dir)):
            fpath = os.path.join(self.log_dir, f)
            if os.path.isfile(fpath):
                files.append({
                    'name': f,
                    'size': os.path.getsize(fpath),
                    'size_mb': round(os.path.getsize(fpath) / (1024 * 1024), 2),
                    'modified': datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat(),
                    'path': fpath,
                })
        return files

    def search_logs(self, keyword: str, max_results: int = 100) -> List[str]:
        """搜索日志"""
        results = []
        for f in sorted(os.listdir(self.log_dir)):
            if f.endswith('.log'):
                fpath = os.path.join(self.log_dir, f)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                        for line in fh:
                            if keyword.lower() in line.lower():
                                results.append(line.strip())
                                if len(results) >= max_results:
                                    return results
                except Exception:
                    pass
        return results

    def get_logs_by_level(self, level: str, max_results: int = 100) -> List[str]:
        """按级别获取日志"""
        return self.search_logs(f'| {level} |', max_results)

    def clean_logs(self, days: int = 30):
        """清理旧日志"""
        cutoff = time.time() - days * 86400
        for f in os.listdir(self.log_dir):
            fpath = os.path.join(self.log_dir, f)
            if os.path.isfile(fpath):
                if os.path.getmtime(fpath) < cutoff:
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass


class LogExporter:
    """日志导出器"""

    @staticmethod
    def export_to_csv(log_entries: List[Dict], output_path: str) -> bool:
        """导出为CSV"""
        try:
            import csv
            if not log_entries:
                return False
            with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=log_entries[0].keys())
                writer.writeheader()
                writer.writerows(log_entries)
            return True
        except Exception:
            return False

    @staticmethod
    def export_to_json(log_entries: List[Dict], output_path: str) -> bool:
        """导出为JSON"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(log_entries, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    @staticmethod
    def export_to_html(log_entries: List[Dict], output_path: str,
                        title: str = 'Log Report') -> bool:
        """导出为HTML"""
        try:
            rows = []
            for entry in log_entries[:1000]:
                rows.append('<tr>')
                for key in entry.keys():
                    rows.append(f'<td>{entry.get(key, "")}</td>')
                rows.append('</tr>')
            html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>{title}</title>
<style>
body {{ font-family: 'Microsoft YaHei', sans-serif; margin: 40px; }}
h1 {{ color: #1a73e8; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
tr:hover {{ background-color: #f5f5f5; }}
th {{ background-color: #f8f9fa; font-weight: bold; }}
</style></head>
<body>
<h1>{title}</h1>
<p>Total entries: {len(log_entries)}</p>
<p>Generated: {datetime.now().isoformat()}</p>
<table><tr>{''.join(f'<th>{k}</th>' for k in log_entries[0].keys())}</tr>
{''.join(rows)}
</table></body></html>'''
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            return True
        except Exception:
            return False


class LogFilter:
    """日志过滤器"""

    @staticmethod
    def filter_by_time(entries: List[Dict], start: str, end: str) -> List[Dict]:
        """按时间过滤"""
        return [e for e in entries if start <= e.get('timestamp', '') <= end]

    @staticmethod
    def filter_by_level(entries: List[Dict], level: str) -> List[Dict]:
        """按级别过滤"""
        return [e for e in entries if e.get('level', '') == level]

    @staticmethod
    def filter_by_module(entries: List[Dict], module: str) -> List[Dict]:
        """按模块过滤"""
        return [e for e in entries if e.get('module', '') == module]

    @staticmethod
    def filter_by_keyword(entries: List[Dict], keyword: str) -> List[Dict]:
        """按关键词过滤"""
        keyword = keyword.lower()
        return [e for e in entries if keyword in json.dumps(e, ensure_ascii=False).lower()]

    @staticmethod
    def limit(entries: List[Dict], n: int = 100) -> List[Dict]:
        """限制数量"""
        return entries[-n:]


class LogAggregator:
    """日志聚合器"""

    @staticmethod
    def aggregate_by_hour(entries: List[Dict]) -> Dict[int, int]:
        """按小时聚合"""
        result = defaultdict(int)
        for e in entries:
            ts = e.get('timestamp', '')
            try:
                hour = int(ts.split(' ')[1].split(':')[0]) if ' ' in ts else 0
                result[hour] += 1
            except (ValueError, IndexError):
                pass
        return dict(sorted(result.items()))

    @staticmethod
    def aggregate_by_date(entries: List[Dict]) -> Dict[str, int]:
        """按日期聚合"""
        result = defaultdict(int)
        for e in entries:
            ts = e.get('timestamp', '')
            date = ts.split(' ')[0] if ' ' in ts else ts[:10]
            result[date] += 1
        return dict(sorted(result.items()))

    @staticmethod
    def aggregate_by_module(entries: List[Dict]) -> Dict[str, int]:
        """按模块聚合"""
        result = defaultdict(int)
        for e in entries:
            result[e.get('module', 'unknown')] += 1
        return dict(result.most_common())

    @staticmethod
    def aggregate_by_level(entries: List[Dict]) -> Dict[str, int]:
        """按级别聚合"""
        result = defaultdict(int)
        for e in entries:
            result[e.get('level', 'UNKNOWN')] += 1
        return dict(result)


class LogReport:
    """日志报告生成器"""

    @staticmethod
    def generate_summary(entries: List[Dict]) -> Dict:
        """生成摘要"""
        return {
            'total_entries': len(entries),
            'time_range': {
                'start': entries[0].get('timestamp', '') if entries else '',
                'end': entries[-1].get('timestamp', '') if entries else '',
            },
            'by_level': LogAggregator.aggregate_by_level(entries),
            'by_module': LogAggregator.aggregate_by_module(entries),
            'by_hour': LogAggregator.aggregate_by_hour(entries),
            'by_date': LogAggregator.aggregate_by_date(entries),
        }

    @staticmethod
    def generate_html_report(entries: List[Dict], output_path: str) -> bool:
        """生成HTML报告"""
        summary = LogReport.generate_summary(entries)
        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Log Report</title>
<style>
body {{ font-family: 'Microsoft YaHei', sans-serif; margin: 40px; }}
h1, h2 {{ color: #1a73e8; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
tr:hover {{ background-color: #f5f5f5; }}
th {{ background-color: #f8f9fa; }}
.card {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 15px 0; }}
.summary {{ display: flex; gap: 20px; }}
.summary-item {{ flex: 1; text-align: center; padding: 20px; background: white;
                border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.summary-value {{ font-size: 28px; font-weight: bold; color: #1a73e8; }}
.summary-label {{ font-size: 14px; color: #5f6368; }}
</style></head>
<body>
<h1>Log Report</h1>
<p>Generated: {datetime.now().isoformat()}</p>
<div class="summary">
<div class="summary-item"><div class="summary-value">{summary['total_entries']}</div><div class="summary-label">Total Entries</div></div>
<div class="summary-item"><div class="summary-value">{len(summary.get('by_module', {}))}</div><div class="summary-label">Modules</div></div>
<div class="summary-item"><div class="summary-value">{len(summary.get('by_date', {}))}</div><div class="summary-label">Days</div></div>
</div>
<h2>By Level</h2>
<table>{"".join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in summary.get('by_level', {}).items())}</table>
<h2>By Module</h2>
<table>{"".join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in summary.get('by_module', {}).items())}</table>
</body></html>'''
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return True


class LogWatcher:
    """日志监视器"""

    def __init__(self, log_dir: str = None, patterns: List[str] = None):
        self.log_dir = log_dir or os.environ.get('TIANDUN_LOGS', 'D:/Antivirus/logs')
        self.patterns = patterns or ['ERROR', 'CRITICAL', 'WARNING']
        self._positions = {}
        self._alerts = []

    def watch(self, max_lines: int = 10) -> List[Dict]:
        """监视日志变化"""
        alerts = []
        for f in os.listdir(self.log_dir):
            if f.endswith('.log'):
                fpath = os.path.join(self.log_dir, f)
                try:
                    if fpath not in self._positions:
                        self._positions[fpath] = 0
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                        fh.seek(self._positions[fpath])
                        for line in fh:
                            for pattern in self.patterns:
                                if f'| {pattern} |' in line:
                                    alerts.append({
                                        'file': f,
                                        'line': line.strip(),
                                        'pattern': pattern,
                                        'timestamp': datetime.now().isoformat(),
                                    })
                        self._positions[fpath] = fh.tell()
                except Exception:
                    pass
        self._alerts.extend(alerts)
        self._alerts = self._alerts[-100:]
        return alerts[-max_lines:]

    def get_alerts(self) -> List[Dict]:
        return list(self._alerts)

    def clear_alerts(self):
        self._alerts.clear()
        self._positions.clear()