#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 进程浏览器
"""
import os
import sys
import time
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ProcessExplorer:
    """进程浏览器"""

    @staticmethod
    def get_processes() -> List[Dict[str, Any]]:
        """获取进程列表"""
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username',
                                              'cpu_percent', 'memory_percent',
                                              'create_time', 'status',
                                              'num_threads']):
                try:
                    pinfo = proc.info
                    if pinfo['create_time']:
                        pinfo['create_time_str'] = time.strftime(
                            '%Y-%m-%d %H:%M:%S',
                            time.localtime(pinfo['create_time'])
                        )
                    processes.append(pinfo)
                except Exception:
                    pass
        except ImportError:
            pass
        return processes

    @staticmethod
    def get_process_info(pid: int) -> Dict[str, Any]:
        """获取进程详细信息"""
        info = {}
        try:
            import psutil
            proc = psutil.Process(pid)
            info = {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cwd': proc.cwd(),
                'cmdline': ' '.join(proc.cmdline()),
                'username': proc.username(),
                'status': proc.status(),
                'create_time': time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.localtime(proc.create_time())),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'memory_rss': proc.memory_info().rss if proc.memory_info() else 0,
                'num_threads': proc.num_threads(),
                'num_handles': proc.num_handles() if hasattr(proc, 'num_handles') else 0,
                'connections': [],
                'open_files': [],
            }
            # 连接信息
            try:
                for conn in proc.connections():
                    info['connections'].append({
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                        'status': conn.status,
                    })
            except Exception:
                pass
            # 打开的文件
            try:
                info['open_files'] = [f.path for f in proc.open_files()]
            except Exception:
                pass
            # 子进程
            try:
                info['children'] = [{'pid': c.pid, 'name': c.name()}
                                   for c in proc.children()]
            except Exception:
                pass
        except Exception:
            pass
        return info

    @staticmethod
    def kill_process(pid: int) -> bool:
        """终止进程"""
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            return True
        except Exception:
            return False

    @staticmethod
    def suspend_process(pid: int) -> bool:
        """挂起进程"""
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.suspend()
            return True
        except Exception:
            return False

    @staticmethod
    def resume_process(pid: int) -> bool:
        """恢复进程"""
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.resume()
            return True
        except Exception:
            return False