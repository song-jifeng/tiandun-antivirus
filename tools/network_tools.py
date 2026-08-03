#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 网络工具集
包含网络诊断、DNS查询、路由追踪等功能
"""
import os
import sys
import socket
import struct
import time
import json
import threading
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class NetworkDiagnostics:
    """网络诊断工具"""

    @staticmethod
    def ping(host: str, count: int = 4, timeout: int = 3) -> Dict:
        """Ping 主机"""
        try:
            import subprocess
            param = '-n' if sys.platform == 'win32' else '-c'
            result = subprocess.run(
                ['ping', param, str(count), host],
                capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout + result.stderr
            # 解析结果
            times = []
            for line in output.split('\n'):
                if 'time=' in line or '时间=' in line:
                    try:
                        idx = line.find('time=') if 'time=' in line else line.find('时间=')
                        part = line[idx:].split()[0]
                        val = ''.join(c for c in part if c.isdigit() or c == '.')
                        if val:
                            times.append(float(val))
                    except (ValueError, IndexError):
                        pass
            return {
                'host': host,
                'alive': result.returncode == 0,
                'sent': count,
                'received': len(times),
                'lost': count - len(times),
                'loss_rate': round((count - len(times)) / count * 100, 1),
                'min_rtt': min(times) if times else 0,
                'max_rtt': max(times) if times else 0,
                'avg_rtt': round(sum(times) / len(times), 2) if times else 0,
                'output': output[:500],
            }
        except subprocess.TimeoutExpired:
            return {'host': host, 'alive': False, 'error': 'timeout'}
        except Exception as e:
            return {'host': host, 'alive': False, 'error': str(e)}

    @staticmethod
    def traceroute(host: str, max_hops: int = 30, timeout: int = 3) -> Dict:
        """路由追踪"""
        hops = []
        try:
            import subprocess
            cmd = ['tracert', '-h', str(max_hops), '-w', str(timeout * 1000), host]
            if sys.platform != 'win32':
                cmd = ['traceroute', '-m', str(max_hops), '-w', str(timeout), host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * max_hops)
            for line in result.stdout.split('\n'):
                if 'ms' in line and ('*' not in line.split()[0] if line.split() else True):
                    hops.append(line.strip())
            return {
                'host': host,
                'hops': len(hops) - 1,
                'details': hops[:20],
                'success': result.returncode == 0,
            }
        except Exception as e:
            return {'host': host, 'error': str(e)}

    @staticmethod
    def dns_lookup(hostname: str) -> Dict:
        """DNS 查询"""
        results = []
        try:
            addrs = socket.getaddrinfo(hostname, 80)
            seen = set()
            for addr in addrs:
                ip = addr[4][0]
                if ip not in seen:
                    seen.add(ip)
                    results.append({
                        'ip': ip,
                        'family': 'IPv4' if addr[0] == socket.AF_INET else 'IPv6',
                    })
            return {
                'hostname': hostname,
                'ips': results,
                'count': len(results),
                'success': True,
            }
        except socket.gaierror:
            return {'hostname': hostname, 'ips': [], 'success': False, 'error': 'DNS解析失败'}
        except Exception as e:
            return {'hostname': hostname, 'ips': [], 'success': False, 'error': str(e)}

    @staticmethod
    def reverse_dns_lookup(ip: str) -> Dict:
        """反向 DNS 查询"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {'ip': ip, 'hostname': hostname, 'success': True}
        except socket.herror:
            return {'ip': ip, 'hostname': '', 'success': False, 'error': '无PTR记录'}
        except Exception as e:
            return {'ip': ip, 'hostname': '', 'success': False, 'error': str(e)}

    @staticmethod
    def check_port(host: str, port: int, timeout: int = 2) -> Dict:
        """端口检测"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.time()
            result = sock.connect_ex((host, port))
            elapsed = round((time.time() - start) * 1000, 1)
            sock.close()
            return {
                'host': host,
                'port': port,
                'open': result == 0,
                'response_time_ms': elapsed,
            }
        except Exception as e:
            return {'host': host, 'port': port, 'open': False, 'error': str(e)}

    @staticmethod
    def scan_ports(host: str, ports: List[int], timeout: int = 1,
                   max_threads: int = 50) -> Dict:
        """端口扫描"""
        results = {}
        lock = threading.Lock()

        def scan(port):
            result = NetworkDiagnostics.check_port(host, port, timeout)
            with lock:
                results[port] = result['open']

        threads = []
        for port in ports:
            t = threading.Thread(target=scan, args=(port,))
            t.start()
            threads.append(t)
            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []
        for t in threads:
            t.join()

        open_ports = [p for p, o in results.items() if o]
        return {
            'host': host,
            'scanned': len(ports),
            'open_ports': open_ports,
            'open_count': len(open_ports),
            'results': results,
        }

    @staticmethod
    def bandwidth_test(duration: int = 5) -> Dict:
        """带宽测试"""
        import socket
        import select
        try:
            # 连接到测试服务器
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('speedtest.example.com', 80))
            sock.setblocking(False)

            start = time.time()
            bytes_received = 0
            while time.time() - start < duration:
                ready = select.select([sock], [], [], 0.1)
                if ready[0]:
                    data = sock.recv(65536)
                    if not data:
                        break
                    bytes_received += len(data)

            sock.close()
            elapsed = time.time() - start
            speed_mbps = (bytes_received * 8) / (elapsed * 1000000)
            return {
                'bytes_received': bytes_received,
                'duration': round(elapsed, 1),
                'speed_mbps': round(speed_mbps, 2),
            }
        except Exception as e:
            return {'error': str(e)}


class URLTools:
    """URL 工具"""

    @staticmethod
    def parse_url(url: str) -> Dict:
        """解析 URL"""
        try:
            parsed = urlparse(url)
            return {
                'url': url,
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'hostname': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'username': parsed.username,
                'password': '***' if parsed.password else '',
            }
        except Exception as e:
            return {'url': url, 'error': str(e)}

    @staticmethod
    def normalize_url(url: str) -> str:
        """规范化 URL"""
        parsed = urlparse(url)
        scheme = parsed.scheme or 'http'
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip('/') or '/'
        if parsed.query:
            return f'{scheme}://{netloc}{path}?{parsed.query}'
        return f'{scheme}://{netloc}{path}'

    @staticmethod
    def extract_domain(url: str) -> str:
        """提取域名"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.lower().split(':')[0]

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """验证 URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False


class HTTPTools:
    """HTTP 工具"""

    @staticmethod
    def check_headers(url: str, timeout: int = 5) -> Dict:
        """检查 HTTP 头"""
        try:
            import requests
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return {
                'url': url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', ''),
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': response.headers.get('Content-Length', ''),
                'redirect_url': response.url if response.url != url else '',
            }
        except requests.Timeout:
            return {'url': url, 'error': 'timeout'}
        except Exception as e:
            return {'url': url, 'error': str(e)}

    @staticmethod
    def check_certificate(url: str, timeout: int = 5) -> Dict:
        """检查 SSL 证书"""
        import ssl
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return {'url': url, 'error': '无法解析主机名'}
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'url': url,
                        'hostname': hostname,
                        'issuer': dict(cert.get('issuer', [])),
                        'subject': dict(cert.get('subject', [])),
                        'expiry': cert.get('notAfter', ''),
                        'valid': True,
                    }
        except Exception as e:
            return {'url': url, 'error': str(e)}


class ProxyChecker:
    """代理检测工具"""

    @staticmethod
    def check_proxy(proxy_host: str, proxy_port: int, test_url: str = 'http://httpbin.org/ip',
                    timeout: int = 10) -> Dict:
        """检查代理"""
        try:
            import requests
            proxies = {
                'http': f'http://{proxy_host}:{proxy_port}',
                'https': f'http://{proxy_host}:{proxy_port}',
            }
            start = time.time()
            response = requests.get(test_url, proxies=proxies, timeout=timeout)
            elapsed = round((time.time() - start) * 1000, 1)
            return {
                'proxy': f'{proxy_host}:{proxy_port}',
                'working': response.status_code == 200,
                'response_time_ms': elapsed,
                'status_code': response.status_code,
                'ip': response.text.strip() if response.ok else '',
            }
        except requests.Timeout:
            return {'proxy': f'{proxy_host}:{proxy_port}', 'working': False, 'error': 'timeout'}
        except Exception as e:
            return {'proxy': f'{proxy_host}:{proxy_port}', 'working': False, 'error': str(e)}


class SpeedTest:
    """网速测试"""

    @staticmethod
    def download_speed(test_url: str = 'http://speedtest.example.com/100mb.bin',
                       timeout: int = 30) -> Dict:
        """下载速度测试"""
        try:
            import requests
            start = time.time()
            response = requests.get(test_url, stream=True, timeout=timeout)
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                total += len(chunk)
                if time.time() - start > 10:
                    break
            elapsed = time.time() - start
            speed_mbps = (total * 8) / (elapsed * 1000000)
            return {
                'bytes_downloaded': total,
                'duration': round(elapsed, 1),
                'speed_mbps': round(speed_mbps, 2),
                'speed_mbps_str': f'{speed_mbps:.2f} Mbps',
            }
        except Exception as e:
            return {'error': str(e)}


class NetworkMonitor:
    """网络监控器"""

    def __init__(self):
        self._connections = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._monitor, daemon=True).start()

    def stop(self):
        self._running = False

    def _monitor(self):
        while self._running:
            try:
                import psutil
                conns = []
                for conn in psutil.net_connections():
                    if conn.raddr:
                        conns.append({
                            'pid': conn.pid,
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'time': time.time(),
                        })
                with self._lock:
                    self._connections = conns[-100:]
            except Exception:
                pass
            time.sleep(5)

    def get_connections(self) -> List[Dict]:
        with self._lock:
            return list(self._connections)

    def get_stats(self) -> Dict:
        conns = self.get_connections()
        return {
            'total_connections': len(conns),
            'established': sum(1 for c in conns if c.get('status') == 'ESTABLISHED'),
            'time_wait': sum(1 for c in conns if c.get('status') == 'TIME_WAIT'),
            'listening': sum(1 for c in conns if c.get('status') == 'LISTEN'),
        }


class BandwidthMonitor:
    """带宽监控器"""

    def __init__(self):
        self._last_counters = None
        self._last_time = None
        self._stats = {'download_speed': 0, 'upload_speed': 0}

    def update(self):
        try:
            import psutil
            counters = psutil.net_io_counters()
            now = time.time()

            if self._last_counters and self._last_time:
                elapsed = now - self._last_time
                if elapsed > 0:
                    down_speed = (counters.bytes_recv - self._last_counters.bytes_recv) / elapsed
                    up_speed = (counters.bytes_sent - self._last_counters.bytes_sent) / elapsed
                    self._stats = {
                        'download_speed': down_speed,
                        'upload_speed': up_speed,
                        'download_speed_mbps': down_speed * 8 / 1000000,
                        'upload_speed_mbps': up_speed * 8 / 1000000,
                        'total_download': counters.bytes_recv,
                        'total_upload': counters.bytes_sent,
                    }

            self._last_counters = counters
            self._last_time = now
        except Exception:
            pass

    def get_stats(self) -> Dict:
        return dict(self._stats)