#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 系统监控与诊断工具
包含实时监控、诊断报告、性能分析等功能
"""
import os
import sys
import time
import json
import platform
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SystemMonitor:
    """系统监控器"""

    def __init__(self, max_history: int = 3600):
        self.max_history = max_history
        self._history = deque(maxlen=max_history)
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    def start(self, interval: int = 5):
        """启动监控"""
        self._running = True
        self._thread = threading.Thread(target=self._monitor,
                                       args=(interval,), daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _monitor(self, interval: int):
        while self._running:
            try:
                snapshot = self._capture_snapshot()
                with self._lock:
                    self._history.append(snapshot)
            except Exception:
                pass
            time.sleep(interval)

    def _capture_snapshot(self) -> Dict:
        """捕获系统快照"""
        snapshot = {'timestamp': time.time()}
        try:
            import psutil
            snapshot['cpu'] = {
                'percent': psutil.cpu_percent(interval=0.1),
                'count': psutil.cpu_count(),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
            }
            snapshot['memory'] = {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'swap': psutil.swap_memory()._asdict() if psutil.swap_memory() else {},
            }
            snapshot['disk'] = {}
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    snapshot['disk'][part.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                    }
                except Exception:
                    pass
            snapshot['network'] = {}
            net = psutil.net_io_counters()
            snapshot['network'] = {
                'bytes_sent': net.bytes_sent,
                'bytes_recv': net.bytes_recv,
                'packets_sent': net.packets_sent,
                'packets_recv': net.packets_recv,
            }
            snapshot['processes'] = len(list(psutil.process_iter()))
        except ImportError:
            pass
        except Exception:
            pass
        return snapshot

    def get_current(self) -> Dict:
        """获取当前状态"""
        return self._capture_snapshot()

    def get_history(self, duration: int = 300) -> List[Dict]:
        """获取历史数据"""
        cutoff = time.time() - duration
        with self._lock:
            return [h for h in self._history if h['timestamp'] >= cutoff]

    def get_cpu_history(self, duration: int = 300) -> List[float]:
        """获取CPU历史"""
        snapshots = self.get_history(duration)
        return [s.get('cpu', {}).get('percent', 0) for s in snapshots]

    def get_memory_history(self, duration: int = 300) -> List[float]:
        """获取内存历史"""
        snapshots = self.get_history(duration)
        return [s.get('memory', {}).get('percent', 0) for s in snapshots]

    def get_stats(self) -> Dict:
        """获取统计信息"""
        snapshots = list(self._history)
        if not snapshots:
            return {}
        cpu_values = [s.get('cpu', {}).get('percent', 0) for s in snapshots]
        mem_values = [s.get('memory', {}).get('percent', 0) for s in snapshots]
        return {
            'samples': len(snapshots),
            'duration': snapshots[-1]['timestamp'] - snapshots[0]['timestamp'] if len(snapshots) > 1 else 0,
            'cpu_avg': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
            'cpu_max': max(cpu_values) if cpu_values else 0,
            'cpu_min': min(cpu_values) if cpu_values else 0,
            'mem_avg': sum(mem_values) / len(mem_values) if mem_values else 0,
            'mem_max': max(mem_values) if mem_values else 0,
            'mem_min': min(mem_values) if mem_values else 0,
        }


class DiagnosticReport:
    """诊断报告"""

    @staticmethod
    def generate() -> Dict:
        """生成完整诊断报告"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system': DiagnosticReport._get_system_info(),
            'performance': DiagnosticReport._get_performance_info(),
            'storage': DiagnosticReport._get_storage_info(),
            'network': DiagnosticReport._get_network_info(),
            'security': DiagnosticReport._get_security_info(),
            'applications': DiagnosticReport._get_applications_info(),
            'recommendations': [],
        }
        # 生成建议
        if report['performance'].get('memory_percent', 0) > 80:
            report['recommendations'].append('内存使用率过高，建议关闭不必要的程序')
        if report['storage'].get('critical_disks', []):
            report['recommendations'].append(f"磁盘空间不足: {', '.join(report['storage']['critical_disks'])}")
        if not report['security'].get('firewall_enabled', True):
            report['recommendations'].append('防火墙已关闭，建议启用')
        return report

    @staticmethod
    def _get_system_info() -> Dict:
        info = {
            'hostname': platform.node(),
            'os': f"{platform.system()} {platform.release()}",
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version,
            'boot_time': '',
        }
        try:
            import psutil
            info['boot_time'] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            info['uptime'] = str(timedelta(seconds=int(time.time() - psutil.boot_time())))
        except Exception:
            pass
        return info

    @staticmethod
    def _get_performance_info() -> Dict:
        info = {'cpu_percent': 0, 'memory_percent': 0, 'load': []}
        try:
            import psutil
            info['cpu_percent'] = psutil.cpu_percent(interval=1)
            info['cpu_count'] = psutil.cpu_count()
            info['cpu_freq'] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
            info['memory_percent'] = psutil.virtual_memory().percent
            info['memory_total'] = psutil.virtual_memory().total
            info['memory_available'] = psutil.virtual_memory().available
            info['swap_percent'] = psutil.swap_memory().percent
            info['process_count'] = len(list(psutil.process_iter()))
            info['thread_count'] = sum(p.num_threads() for p in psutil.process_iter())
        except Exception:
            pass
        return info

    @staticmethod
    def _get_storage_info() -> Dict:
        info = {'disks': [], 'critical_disks': []}
        try:
            import psutil
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_info = {
                        'mount': part.mountpoint,
                        'fstype': part.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                    }
                    info['disks'].append(disk_info)
                    if usage.percent > 90:
                        info['critical_disks'].append(part.mountpoint)
                except Exception:
                    pass
        except Exception:
            pass
        return info

    @staticmethod
    def _get_network_info() -> Dict:
        info = {'interfaces': [], 'connections': 0, 'firewall_enabled': True}
        try:
            import psutil
            info['connections'] = len(psutil.net_connections())
            net = psutil.net_io_counters()
            info['bytes_sent'] = net.bytes_sent
            info['bytes_recv'] = net.bytes_recv
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == 2:  # AF_INET
                        info['interfaces'].append({
                            'name': name,
                            'ip': addr.address,
                            'netmask': addr.netmask,
                        })
        except Exception:
            pass
        try:
            import subprocess
            result = subprocess.run(
                'netsh advfirewall show allprofiles state',
                shell=True, capture_output=True, text=True, timeout=5
            )
            info['firewall_enabled'] = 'ON' in result.stdout
        except Exception:
            pass
        return info

    @staticmethod
    def _get_security_info() -> Dict:
        info = {
            'uac_enabled': False,
            'auto_updates': False,
            'defender_enabled': False,
            'last_updates': [],
        }
        try:
            import subprocess
            result = subprocess.run(
                'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA',
                shell=True, capture_output=True, text=True, timeout=5
            )
            info['uac_enabled'] = '0x1' in result.stdout
            result = subprocess.run(
                'wmic qfe list brief /format:csv',
                shell=True, capture_output=True, text=True, timeout=10
            )
            updates = []
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 4:
                        updates.append({
                            'hotfix': parts[1].strip('"') if len(parts) > 1 else '',
                            'installed': parts[3].strip('"') if len(parts) > 3 else '',
                        })
            info['last_updates'] = updates[-10:]
        except Exception:
            pass
        return info

    @staticmethod
    def _get_applications_info() -> Dict:
        info = {'installed': 0, 'running': 0}
        try:
            import winreg
            keys = [
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'),
            ]
            count = 0
            for hive, key_path in keys:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            subkey = winreg.EnumKey(key, i)
                            sk = winreg.OpenKey(hive, f'{key_path}\\{subkey}')
                            try:
                                winreg.QueryValueEx(sk, 'DisplayName')
                                count += 1
                            except FileNotFoundError:
                                pass
                            winreg.CloseKey(sk)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
            info['installed'] = count
        except Exception:
            pass
        try:
            import psutil
            info['running'] = len(list(psutil.process_iter()))
        except Exception:
            pass
        return info


class PerformanceAnalyzer:
    """性能分析器"""

    @staticmethod
    def analyze_response_time(operation: str, times: List[float]) -> Dict:
        """分析响应时间"""
        if not times:
            return {}
        sorted_times = sorted(times)
        n = len(sorted_times)
        return {
            'operation': operation,
            'samples': n,
            'min': min(sorted_times),
            'max': max(sorted_times),
            'avg': sum(sorted_times) / n,
            'median': sorted_times[n // 2] if n % 2 else (sorted_times[n // 2 - 1] + sorted_times[n // 2]) / 2,
            'p95': sorted_times[int(n * 0.95)],
            'p99': sorted_times[int(n * 0.99)],
            'std': PerformanceAnalyzer._std_dev(sorted_times),
        }

    @staticmethod
    def _std_dev(data: List[float]) -> float:
        if len(data) < 2:
            return 0.0
        avg = sum(data) / len(data)
        variance = sum((x - avg) ** 2 for x in data) / (len(data) - 1)
        return variance ** 0.5

    @staticmethod
    def analyze_throughput(items: int, duration: float) -> Dict:
        """分析吞吐量"""
        if duration <= 0:
            return {}
        return {
            'items': items,
            'duration': duration,
            'throughput': items / duration,
            'throughput_per_second': items / duration,
            'throughput_per_minute': items / duration * 60,
        }

    @staticmethod
    def analyze_resource_usage(snapshots: List[Dict]) -> Dict:
        """分析资源使用"""
        if not snapshots:
            return {}
        cpu_values = [s.get('cpu', {}).get('percent', 0) for s in snapshots]
        mem_values = [s.get('memory', {}).get('percent', 0) for s in snapshots]
        return {
            'cpu': PerformanceAnalyzer.analyze_response_time('cpu', cpu_values),
            'memory': PerformanceAnalyzer.analyze_response_time('memory', mem_values),
            'samples': len(snapshots),
            'duration': snapshots[-1]['timestamp'] - snapshots[0]['timestamp'] if len(snapshots) > 1 else 0,
        }


class HealthCheck:
    """健康检查器"""

    @staticmethod
    def check_all() -> Dict:
        """全面健康检查"""
        checks = {
            'cpu': HealthCheck._check_cpu(),
            'memory': HealthCheck._check_memory(),
            'disk': HealthCheck._check_disk(),
            'network': HealthCheck._check_network(),
            'services': HealthCheck._check_services(),
            'updates': HealthCheck._check_updates(),
        }
        scores = [c.get('score', 0) for c in checks.values()]
        overall = sum(scores) / len(scores) if scores else 0
        return {
            'overall_score': overall,
            'level': 'healthy' if overall >= 80 else 'fair' if overall >= 60 else 'poor',
            'checks': checks,
            'timestamp': datetime.now().isoformat(),
        }

    @staticmethod
    def _check_cpu() -> Dict:
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=1)
            if cpu < 50:
                return {'status': 'good', 'score': 100 - cpu, 'value': cpu}
            elif cpu < 80:
                return {'status': 'warning', 'score': 100 - cpu, 'value': cpu}
            return {'status': 'critical', 'score': max(0, 100 - cpu), 'value': cpu}
        except Exception:
            return {'status': 'unknown', 'score': 50}

    @staticmethod
    def _check_memory() -> Dict:
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {'status': 'good' if mem.percent < 70 else 'warning' if mem.percent < 85 else 'critical',
                    'score': 100 - mem.percent, 'value': mem.percent}
        except Exception:
            return {'status': 'unknown', 'score': 50}

    @staticmethod
    def _check_disk() -> Dict:
        try:
            import psutil
            disks = []
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({'mount': part.mountpoint, 'percent': usage.percent})
                except Exception:
                    pass
            worst = max(d['percent'] for d in disks) if disks else 0
            return {'status': 'good' if worst < 80 else 'warning' if worst < 90 else 'critical',
                    'score': 100 - worst, 'value': worst, 'disks': disks}
        except Exception:
            return {'status': 'unknown', 'score': 50}

    @staticmethod
    def _check_network() -> Dict:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('8.8.8.8', 53))
            sock.close()
            return {'status': 'good' if result == 0 else 'warning',
                    'score': 100 if result == 0 else 30, 'connected': result == 0}
        except Exception:
            return {'status': 'unknown', 'score': 50}

    @staticmethod
    def _check_services() -> Dict:
        try:
            import subprocess
            result = subprocess.run(
                'sc query type= service state= all | findstr "RUNNING"',
                shell=True, capture_output=True, text=True, timeout=10
            )
            running = len([l for l in result.stdout.split('\n') if l.strip()])
            return {'status': 'good', 'score': min(100, running * 2), 'running': running}
        except Exception:
            return {'status': 'unknown', 'score': 50}

    @staticmethod
    def _check_updates() -> Dict:
        try:
            import subprocess
            result = subprocess.run(
                'wmic qfe list brief /format:csv',
                shell=True, capture_output=True, text=True, timeout=10
            )
            updates = len([l for l in result.stdout.split('\n') if l.strip()]) - 1
            return {'status': 'good' if updates > 0 else 'warning',
                    'score': min(100, updates * 5), 'updates': max(0, updates)}
        except Exception:
            return {'status': 'unknown', 'score': 50}


class AlertRule:
    """告警规则"""
    def __init__(self, name: str, metric: str, operator: str,
                 threshold: float, severity: str = 'warning',
                 message: str = ''):
        self.name = name
        self.metric = metric
        self.operator = operator
        self.threshold = threshold
        self.severity = severity
        self.message = message

    def evaluate(self, value: float) -> Optional[Dict]:
        triggered = False
        if self.operator == '>' and value > self.threshold:
            triggered = True
        elif self.operator == '<' and value < self.threshold:
            triggered = True
        elif self.operator == '>=' and value >= self.threshold:
            triggered = True
        elif self.operator == '<=' and value <= self.threshold:
            triggered = True
        elif self.operator == '==' and value == self.threshold:
            triggered = True
        if triggered:
            return {
                'rule': self.name,
                'metric': self.metric,
                'value': value,
                'threshold': self.threshold,
                'severity': self.severity,
                'message': self.message or f"{self.metric} {self.operator} {self.threshold}",
            }
        return None


class AlertManager:
    """告警管理器"""
    def __init__(self):
        self.rules: List[AlertRule] = []
        self.alerts: List[Dict] = []
        self._max_alerts = 1000

    def add_rule(self, rule: AlertRule):
        self.rules.append(rule)

    def evaluate(self, metrics: Dict) -> List[Dict]:
        new_alerts = []
        for rule in self.rules:
            value = metrics.get(rule.metric)
            if value is not None:
                result = rule.evaluate(value)
                if result:
                    result['timestamp'] = datetime.now().isoformat()
                    new_alerts.append(result)
                    self.alerts.append(result)
        self.alerts = self.alerts[-self._max_alerts:]
        return new_alerts

    def get_alerts(self, severity: str = None, limit: int = 50) -> List[Dict]:
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a.get('severity') == severity]
        return alerts[-limit:]

    def clear(self):
        self.alerts.clear()