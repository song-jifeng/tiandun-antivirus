#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 数据导出与报告生成工具
"""
import os
import sys
import json
import csv
import io
import time
from typing import Dict, List, Any
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DataExporter:
    """数据导出器"""

    @staticmethod
    def to_csv(data: List[Dict], filepath: str) -> bool:
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
    def to_json(data: Any, filepath: str, pretty: bool = True) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2 if pretty else None)
            return True
        except Exception:
            return False

    @staticmethod
    def to_html_table(data: List[Dict], title: str = 'Data Export') -> str:
        if not data:
            return '<p>No data</p>'
        headers = data[0].keys()
        rows = []
        for row in data:
            rows.append('<tr>' + ''.join(f'<td>{row.get(k, "")}</td>' for k in headers) + '</tr>')
        return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:sans-serif;margin:40px}}
table{{border-collapse:collapse;width:100%}}
th,td{{padding:8px;text-align:left;border-bottom:1px solid #ddd}}
th{{background:#f8f9fa}}tr:hover{{background:#f5f5f5}}
</style></head><body>
<h1>{title}</h1>
<p>Generated: {datetime.now().isoformat()}</p>
<p>Total rows: {len(data)}</p>
<table><tr>{''.join(f'<th>{k}</th>' for k in headers)}</tr>
{''.join(rows)}</table></body></html>'''

    @staticmethod
    def to_markdown_table(data: List[Dict]) -> str:
        if not data:
            return '*No data*'
        headers = list(data[0].keys())
        lines = ['| ' + ' | '.join(headers) + ' |']
        lines.append('| ' + ' | '.join('---' for _ in headers) + ' |')
        for row in data:
            lines.append('| ' + ' | '.join(str(row.get(k, '')) for k in headers) + ' |')
        return '\n'.join(lines)

    @staticmethod
    def to_text_report(data: Dict, title: str = 'Report') -> str:
        lines = [f'{"=" * 60}', f'  {title}', f'  {datetime.now().isoformat()}', f'{"=" * 60}']
        def _render(data, indent=0):
            prefix = '  ' * indent
            if isinstance(data, dict):
                for k, v in data.items():
                    lines.append(f'{prefix}{k}:')
                    _render(v, indent + 1)
            elif isinstance(data, list):
                for i, v in enumerate(data[:20]):
                    lines.append(f'{prefix}{i + 1}. {v}')
                if len(data) > 20:
                    lines.append(f'{prefix}... and {len(data) - 20} more')
            else:
                lines[-1] = lines[-1].rstrip() + f' {data}'
        _render(data)
        lines.append(f'{"=" * 60}')
        return '\n'.join(lines)


class ReportGenerator:
    """报告生成器"""

    @staticmethod
    def generate_scan_report(report_data: Dict) -> str:
        return DataExporter.to_text_report(report_data, 'Scan Report')

    @staticmethod
    def generate_threat_report(threats: List[Dict]) -> str:
        return DataExporter.to_html_table(threats, 'Threat Report')

    @staticmethod
    def generate_system_report(system_info: Dict) -> str:
        return DataExporter.to_text_report(system_info, 'System Report')

    @staticmethod
    def generate_performance_report(metrics: Dict) -> str:
        return DataExporter.to_text_report(metrics, 'Performance Report')

    @staticmethod
    def export_all(reports: Dict[str, Any], output_dir: str) -> Dict:
        results = {}
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        for name, data in reports.items():
            filepath = os.path.join(output_dir, f'{name}_{timestamp}.json')
            success = DataExporter.to_json(data, filepath)
            results[name] = {'file': filepath, 'success': success}
        return results


class ThreatReportBuilder:
    """威胁报告构建器"""

    def __init__(self):
        self._sections = []

    def add_title(self, title: str):
        self._sections.append({'type': 'title', 'content': title})

    def add_summary(self, total: int, critical: int, high: int,
                    medium: int, low: int):
        self._sections.append({
            'type': 'summary',
            'content': {
                'total': total, 'critical': critical, 'high': high,
                'medium': medium, 'low': low,
            }
        })

    def add_threat_table(self, threats: List[Dict]):
        self._sections.append({'type': 'table', 'content': threats})

    def add_timeline(self, events: List[Dict]):
        self._sections.append({'type': 'timeline', 'content': events})

    def add_recommendations(self, recommendations: List[str]):
        self._sections.append({'type': 'list', 'content': recommendations})

    def build_html(self) -> str:
        html = '<!DOCTYPE html><html><head><meta charset="utf-8">'
        html += '<title>Threat Report</title>'
        html += '<style>body{font-family:sans-serif;margin:40px}'
        html += 'h1{color:#1a73e8}h2{color:#333}'
        html += 'table{width:100%;border-collapse:collapse}'
        html += 'th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd}'
        html += 'th{background:#f8f9fa}.critical{color:#d93025}.high{color:#ea4335}'
        html += '.medium{color:#fbbc04}.low{color:#34a853}'
        html += '.summary{display:flex;gap:20px}'
        html += '.summary-item{flex:1;text-align:center;padding:20px;'
        html += 'background:#f8f9fa;border-radius:8px}'
        html += '.summary-value{font-size:28px;font-weight:bold;color:#1a73e8}'
        html += '</style></head><body>'

        for section in self._sections:
            if section['type'] == 'title':
                html += f'<h1>{section["content"]}</h1>'
            elif section['type'] == 'summary':
                c = section['content']
                html += '<div class="summary">'
                html += f'<div class="summary-item"><div class="summary-value">{c["total"]}</div><div>Total</div></div>'
                html += f'<div class="summary-item"><div class="summary-value critical">{c["critical"]}</div><div>Critical</div></div>'
                html += f'<div class="summary-item"><div class="summary-value high">{c["high"]}</div><div>High</div></div>'
                html += f'<div class="summary-item"><div class="summary-value medium">{c["medium"]}</div><div>Medium</div></div>'
                html += f'<div class="summary-item"><div class="summary-value low">{c["low"]}</div><div>Low</div></div>'
                html += '</div>'
            elif section['type'] == 'table':
                data = section['content']
                if data:
                    html += '<table><tr>'
                    for k in data[0].keys():
                        html += f'<th>{k}</th>'
                    html += '</tr>'
                    for row in data:
                        html += '<tr>'
                        for k in row.keys():
                            html += f'<td>{row.get(k, "")}</td>'
                        html += '</tr>'
                    html += '</table>'
            elif section['type'] == 'list':
                html += '<ul>'
                for item in section['content']:
                    html += f'<li>{item}</li>'
                html += '</ul>'
            elif section['type'] == 'timeline':
                html += '<div class="timeline">'
                for event in section['content'][:50]:
                    html += f'<div>{event.get("time", "")} - {event.get("event", "")}</div>'
                html += '</div>'

        html += '</body></html>'
        return html

    def build_text(self) -> str:
        lines = []
        for section in self._sections:
            if section['type'] == 'title':
                lines.append(f'\n{"=" * 60}')
                lines.append(f'  {section["content"]}')
                lines.append(f'{"=" * 60}')
            elif section['type'] == 'summary':
                c = section['content']
                lines.append(f'\nSummary: {c["total"]} threats detected')
                lines.append(f'  Critical: {c["critical"]}')
                lines.append(f'  High: {c["high"]}')
                lines.append(f'  Medium: {c["medium"]}')
                lines.append(f'  Low: {c["low"]}')
            elif section['type'] == 'table':
                for row in section['content'][:30]:
                    lines.append(f'  {row}')
            elif section['type'] == 'list':
                for item in section['content']:
                    lines.append(f'  - {item}')
        return '\n'.join(lines)


class CSVExporter:
    """CSV导出器"""

    @staticmethod
    def export_threats(threats: List[Dict], filepath: str) -> bool:
        fields = ['timestamp', 'file_path', 'threat_name', 'threat_type',
                  'threat_level', 'scan_engine', 'file_size']
        try:
            with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for t in threats:
                    row = {f: t.get(f, '') for f in fields}
                    writer.writerow(row)
            return True
        except Exception:
            return False

    @staticmethod
    def export_scans(scans: List[Dict], filepath: str) -> bool:
        fields = ['start_time', 'scan_mode', 'scanned_files',
                  'threats_found', 'duration_seconds']
        try:
            with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for s in scans:
                    row = {f: s.get(f, '') for f in fields}
                    writer.writerow(row)
            return True
        except Exception:
            return False


class JSONExporter:
    """JSON导出器"""

    @staticmethod
    def export_threats(threats: List[Dict], filepath: str) -> bool:
        return DataExporter.to_json(threats, filepath)

    @staticmethod
    def export_config(config: Dict, filepath: str) -> bool:
        return DataExporter.to_json(config, filepath)


class PDFExporter:
    """PDF导出器（简化版）"""

    @staticmethod
    def export_text(text: str, filepath: str) -> bool:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            c = canvas.Canvas(filepath, pagesize=A4)
            width, height = A4
            y = height - 50
            for line in text.split('\n'):
                if y < 50:
                    c.showPage()
                    y = height - 50
                c.drawString(50, y, line[:100])
                y -= 14
            c.save()
            return True
        except ImportError:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(text)
            return False
        except Exception:
            return False


class ExporterFactory:
    """导出器工厂"""

    @staticmethod
    def get_exporter(format: str):
        exporters = {
            'csv': CSVExporter(),
            'json': JSONExporter(),
            'html': ReportGenerator(),
            'txt': DataExporter(),
        }
        return exporters.get(format.lower(), DataExporter())

    @staticmethod
    def export(data: Any, format: str, filepath: str) -> bool:
        exporter = ExporterFactory.get_exporter(format)
        if format == 'csv' and isinstance(data, list):
            return DataExporter.to_csv(data, filepath)
        elif format == 'json':
            return DataExporter.to_json(data, filepath)
        elif format == 'html' and isinstance(data, list):
            html = DataExporter.to_html_table(data)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
            return True
        return False