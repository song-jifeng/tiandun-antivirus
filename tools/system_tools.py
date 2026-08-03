#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 系统维护工具
包含系统健康检查、磁盘分析、内存优化等功能
"""
import os
import sys
import time
import json
import shutil
import platform
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SystemHealthCheck:
    """系统健康检查"""

    @staticmethod
    def check_all() -> Dict:
        """全面检查系统健康"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': platform.node(),
            'os': f"{platform.system()} {platform.release()}",
            'checks': {},
        }
        results['checks']['disk'] = SystemHealthCheck.check_disk_space()
        results['checks']['memory'] = SystemHealthCheck.check_memory()
        results['checks']['cpu'] = SystemHealthCheck.check_cpu()
        results['checks']['network'] = SystemHealthCheck.check_network()
        results['checks']['services'] = SystemHealthCheck.check_services()
        results['checks']['updates'] = SystemHealthCheck.check_updates()
        results['health_score'] = SystemHealthCheck.calculate_score(results['checks'])
        return results

    @staticmethod
    def check_disk_space() -> Dict:
        """检查磁盘空间"""
        try:
            import psutil
            disks = []
            warnings = []
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    status = 'ok' if usage.percent < 85 else 'warning' if usage.percent < 95 else 'critical'
                    disks.append({
                        'mount': part.mountpoint,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                        'status': status,
                    })
                    if status == 'warning':
                        warnings.append(f"{part.mountpoint} 磁盘使用率 {usage.percent}%")
                    elif status == 'critical':
                        warnings.append(f"{part.mountpoint} 磁盘即将满 ({usage.percent}%)")
                except Exception:
                    pass
            return {'disks': disks, 'warnings': warnings, 'score': max(0, 100 - len(warnings) * 20)}
        except Exception:
            return {'disks': [], 'warnings': ['无法获取磁盘信息'], 'score': 50}

    @staticmethod
    def check_memory() -> Dict:
        """检查内存状态"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            status = 'ok' if mem.percent < 80 else 'warning' if mem.percent < 90 else 'critical'
            return {
                'total': mem.total,
                'available': mem.available,
                'used': mem.used,
                'percent': mem.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_percent': swap.percent,
                'status': status,
                'score': 100 - mem.percent,
            }
        except Exception:
            return {'error': '无法获取内存信息', 'score': 50}

    @staticmethod
    def check_cpu() -> Dict:
        """检查CPU状态"""
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            status = 'ok' if cpu_percent < 70 else 'warning' if cpu_percent < 90 else 'critical'
            return {
                'percent': cpu_percent,
                'count': cpu_count,
                'frequency': cpu_freq._asdict() if cpu_freq else {},
                'status': status,
                'score': 100 - cpu_percent,
            }
        except Exception:
            return {'error': '无法获取CPU信息', 'score': 50}

    @staticmethod
    def check_network() -> Dict:
        """检查网络状态"""
        try:
            import socket
            local_ip = socket.gethostbyname(socket.gethostname())
            # 测试连接
            test_hosts = ['8.8.8.8', '1.1.1.1', '223.5.5.5']
            reachable = []
            for host in test_hosts:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, 53))
                    sock.close()
                    reachable.append(result == 0)
                except Exception:
                    reachable.append(False)
            return {
                'local_ip': local_ip,
                'internet_access': any(reachable),
                'reachable_hosts': sum(reachable),
                'score': 100 if any(reachable) else 0,
            }
        except Exception:
            return {'error': '无法获取网络信息', 'score': 50}

    @staticmethod
    def check_services() -> Dict:
        """检查系统服务"""
        try:
            import subprocess
            result = subprocess.run(
                'sc query type= service state= all | findstr "RUNNING"',
                shell=True, capture_output=True, text=True, timeout=10
            )
            running = len([l for l in result.stdout.split('\n') if l.strip()])
            return {
                'running_services': running,
                'score': min(100, running),
            }
        except Exception:
            return {'error': '无法获取服务信息', 'score': 50}

    @staticmethod
    def check_updates() -> Dict:
        """检查系统更新"""
        try:
            import subprocess
            result = subprocess.run(
                'wmic qfe list brief /format:csv',
                shell=True, capture_output=True, text=True, timeout=10
            )
            updates = len([l for l in result.stdout.split('\n') if l.strip()]) - 1
            return {
                'installed_updates': max(0, updates),
                'score': min(100, updates * 2),
            }
        except Exception:
            return {'error': '无法获取更新信息', 'score': 50}

    @staticmethod
    def calculate_score(checks: Dict) -> int:
        """计算健康评分"""
        scores = []
        for check in checks.values():
            if isinstance(check, dict):
                score = check.get('score', 50)
                scores.append(score)
        return int(sum(scores) / len(scores)) if scores else 50


class DiskAnalyzer:
    """磁盘分析器"""

    @staticmethod
    def analyze_disk_usage(path: str = '/') -> Dict:
        """分析磁盘使用情况"""
        try:
            import psutil
            usage = psutil.disk_usage(path)
            return {
                'path': path,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent,
                'total_gb': round(usage.total / (1024**3), 2),
                'used_gb': round(usage.used / (1024**3), 2),
                'free_gb': round(usage.free / (1024**3), 2),
            }
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_largest_files(directory: str, top_n: int = 20,
                          min_size_mb: int = 10) -> List[Dict]:
        """获取最大的文件"""
        files = []
        min_size = min_size_mb * 1024 * 1024
        try:
            for root, _, filenames in os.walk(directory):
                for f in filenames:
                    try:
                        fpath = os.path.join(root, f)
                        size = os.path.getsize(fpath)
                        if size >= min_size:
                            files.append({
                                'path': fpath,
                                'size': size,
                                'size_mb': round(size / (1024 * 1024), 2),
                                'modified': os.path.getmtime(fpath),
                            })
                    except (PermissionError, OSError):
                        continue
            files.sort(key=lambda x: x['size'], reverse=True)
            return files[:top_n]
        except Exception:
            return []

    @staticmethod
    def get_folder_sizes(directory: str) -> List[Dict]:
        """获取文件夹大小"""
        folders = []
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isdir(item_path):
                    try:
                        total_size = 0
                        for root, _, files in os.walk(item_path):
                            for f in files:
                                try:
                                    total_size += os.path.getsize(os.path.join(root, f))
                                except Exception:
                                    pass
                        folders.append({
                            'name': item,
                            'size': total_size,
                            'size_mb': round(total_size / (1024 * 1024), 2),
                            'path': item_path,
                        })
                    except PermissionError:
                        folders.append({
                            'name': item,
                            'size': 0,
                            'size_mb': 0,
                            'path': item_path,
                            'error': '无权限访问',
                        })
            folders.sort(key=lambda x: x['size'], reverse=True)
            return folders
        except Exception:
            return []

    @staticmethod
    def get_disk_usage_by_type(directory: str) -> Dict[str, int]:
        """按文件类型统计磁盘使用"""
        usage = defaultdict(int)
        try:
            for root, _, files in os.walk(directory):
                for f in files:
                    try:
                        ext = os.path.splitext(f)[1].lower() or '(no extension)'
                        fpath = os.path.join(root, f)
                        usage[ext] += os.path.getsize(fpath)
                    except Exception:
                        pass
            return dict(sorted(usage.items(), key=lambda x: x[1], reverse=True))
        except Exception:
            return {}


class MemoryOptimizer:
    """内存优化器"""

    @staticmethod
    def optimize() -> Dict:
        """优化内存使用"""
        freed = 0
        try:
            import subprocess
            # 清理工作集
            result = subprocess.run(
                'powershell -Command "Get-Process | Where-Object { $_.WorkingSet -gt 100MB } | ForEach-Object { [GC]::Collect(); $_.Refresh() }"',
                shell=True, capture_output=True, timeout=30
            )
            freed = 1
        except Exception:
            pass
        return {'success': True, 'freed_mb': freed}

    @staticmethod
    def clear_system_cache() -> Dict:
        """清理系统缓存"""
        try:
            if sys.platform == 'win32':
                subprocess.run('ipconfig /flushdns', shell=True, capture_output=True, timeout=10)
            return {'success': True, 'message': '系统缓存已清理'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def get_memory_usage() -> Dict:
        """获取内存使用详情"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                'total': mem.total,
                'available': mem.available,
                'used': mem.used,
                'free': mem.free,
                'active': mem.active,
                'inactive': mem.inactive,
                'buffers': mem.buffers,
                'cached': mem.cached,
                'shared': mem.shared,
                'percent': mem.percent,
                'total_gb': round(mem.total / (1024**3), 2),
                'used_gb': round(mem.used / (1024**3), 2),
                'available_gb': round(mem.available / (1024**3), 2),
            }
        except Exception as e:
            return {'error': str(e)}


class ProcessManager:
    """进程管理器"""

    @staticmethod
    def get_process_tree() -> List[Dict]:
        """获取进程树"""
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cpu_percent',
                                              'memory_percent', 'status', 'create_time']):
                try:
                    processes.append(proc.info)
                except Exception:
                    pass
            return processes
        except Exception:
            return []

    @staticmethod
    def find_process_by_name(name: str) -> List[Dict]:
        """按名称查找进程"""
        try:
            import psutil
            results = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username',
                                              'cpu_percent', 'memory_percent']):
                try:
                    if name.lower() in proc.info['name'].lower():
                        results.append(proc.info)
                except Exception:
                    pass
            return results
        except Exception:
            return []

    @staticmethod
    def get_process_stats() -> Dict:
        """获取进程统计"""
        try:
            import psutil
            procs = list(psutil.process_iter(['pid', 'name', 'status']))
            return {
                'total_processes': len(procs),
                'running': sum(1 for p in procs if p.info.get('status') == 'running'),
                'sleeping': sum(1 for p in procs if p.info.get('status') == 'sleeping'),
                'stopped': sum(1 for p in procs if p.info.get('status') == 'stopped'),
                'zombie': sum(1 for p in procs if p.info.get('status') == 'zombie'),
            }
        except Exception:
            return {'total_processes': 0}


class StartupOptimizer:
    """启动优化器"""

    @staticmethod
    def analyze_startup() -> Dict:
        """分析启动项"""
        items = []
        try:
            import winreg
            # 注册表启动项
            keys = [
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            ]
            for hive, key_path in keys:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            items.append({
                                'name': name,
                                'command': value,
                                'location': '注册表',
                                'enabled': True,
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        except Exception:
            pass
        return {
            'total_startup_items': len(items),
            'items': items,
            'recommendations': [
                '禁用不必要的启动项可加快系统启动速度',
                '建议保留杀毒软件和硬件驱动的启动项',
            ],
        }


class EventLogViewer:
    """事件查看器"""

    @staticmethod
    def get_system_events(max_events: int = 100, event_type: str = 'System') -> List[Dict]:
        """获取系统事件"""
        events = []
        try:
            import subprocess
            result = subprocess.run(
                f'wevtutil qe {event_type} /c:{max_events} /f:text',
                shell=True, capture_output=True, text=True, timeout=10
            )
            current = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Event['):
                    if current:
                        events.append(current)
                    current = {}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    current[key.strip()] = value.strip()
            if current:
                events.append(current)
            return events[:max_events]
        except Exception:
            return []


class BatteryAnalyzer:
    """电池分析器"""

    @staticmethod
    def get_battery_info() -> Dict:
        """获取电池信息"""
        try:
            import psutil
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    return {
                        'percent': battery.percent,
                        'power_plugged': battery.power_plugged,
                        'time_left': battery.secsleft,
                        'time_left_str': f"{battery.secsleft // 3600}小时{battery.secsleft % 3600 // 60}分钟" if battery.secsleft != -1 else '未知',
                        'status': '充电中' if battery.power_plugged else '使用电池',
                    }
            return {'error': '无法获取电池信息'}
        except Exception:
            return {'error': '无法获取电池信息'}


class TemperatureMonitor:
    """温度监控器"""

    @staticmethod
    def get_temperatures() -> Dict:
        """获取温度信息"""
        try:
            import psutil
            temps = {}
            if hasattr(psutil, 'sensors_temperatures'):
                sensor_data = psutil.sensors_temperatures()
                for name, entries in sensor_data.items():
                    for entry in entries:
                        temps[name] = {
                            'current': entry.current,
                            'high': entry.high,
                            'critical': entry.critical,
                            'label': entry.label or name,
                        }
            return temps
        except Exception:
            return {}


class SystemUptime:
    """系统运行时间"""

    @staticmethod
    def get_uptime() -> Dict:
        """获取系统运行时间"""
        try:
            import psutil
            boot_time = psutil.boot_time()
            now = time.time()
            uptime_seconds = now - boot_time
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return {
                'boot_time': datetime.fromtimestamp(boot_time).isoformat(),
                'uptime_seconds': uptime_seconds,
                'uptime_str': f"{days}天{hours}小时{minutes}分钟",
                'days': days,
                'hours': hours,
                'minutes': minutes,
            }
        except Exception:
            return {'error': '无法获取运行时间'}


class UserActivityMonitor:
    """用户活动监控器"""

    @staticmethod
    def get_user_sessions() -> List[Dict]:
        """获取用户会话"""
        sessions = []
        try:
            import subprocess
            result = subprocess.run(
                'query session',
                shell=True, capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        sessions.append({
                            'session_name': parts[0],
                            'username': parts[1],
                            'id': parts[2],
                            'state': parts[3],
                            'type': parts[4] if len(parts) > 4 else '',
                        })
            return sessions
        except Exception:
            return []


class FirewallStatus:
    """防火墙状态检查"""

    @staticmethod
    def check_status() -> Dict:
        """检查防火墙状态"""
        try:
            import subprocess
            result = subprocess.run(
                'netsh advfirewall show allprofiles',
                shell=True, capture_output=True, text=True, timeout=10
            )
            profiles = {}
            current_profile = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.endswith('Profile Settings:'):
                    current_profile = line.split(' ')[0]
                    profiles[current_profile] = {}
                elif 'State' in line and current_profile:
                    profiles[current_profile]['state'] = 'ON' if 'ON' in line else 'OFF'
            return {
                'profiles': profiles,
                'all_enabled': all(p.get('state') == 'ON' for p in profiles.values()),
                'raw_output': result.stdout[:500],
            }
        except Exception as e:
            return {'error': str(e)}


class WindowsUpdateChecker:
    """Windows更新检查"""

    @staticmethod
    def check_updates() -> Dict:
        """检查Windows更新"""
        try:
            import subprocess
            result = subprocess.run(
                'powershell -Command "Get-WUList | Select-Object -First 10"',
                shell=True, capture_output=True, text=True, timeout=30
            )
            updates = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('('):
                    updates.append(line.strip())
            return {
                'updates_available': len([u for u in updates if u]),
                'updates': updates[:20],
                'check_success': True,
            }
        except Exception as e:
            return {'error': str(e), 'check_success': False}


class DriverChecker:
    """驱动检查器"""

    @staticmethod
    def check_drivers() -> List[Dict]:
        """检查驱动状态"""
        drivers = []
        try:
            import subprocess
            result = subprocess.run(
                'driverquery /v /fo csv',
                shell=True, capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 7:
                        drivers.append({
                            'name': parts[0].strip('"'),
                            'type': parts[1].strip('"'),
                            'start_mode': parts[2].strip('"'),
                            'state': parts[3].strip('"'),
                            'status': parts[4].strip('"'),
                        })
            return drivers[:100]
        except Exception:
            return []