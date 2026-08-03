#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 云查杀引擎
发送文件哈希到云端查询，提供本地缓存
"""
import os
import sys
import json
import time
import hashlib
import threading
from typing import Optional, Dict, Any, List
from collections import OrderedDict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine import ScanEngine, ScanResult, ThreatInfo, ThreatType, ThreatLevel, HashUtil
from engine.logger import logger
from engine.config import config


class CloudCache:
    """云查杀缓存 - LRU缓存"""
    def __init__(self, cache_file: str, max_entries: int = 10000, ttl_hours: int = 24):
        self.cache_file = cache_file
        self.max_entries = max_entries
        self.ttl = ttl_hours * 3600
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        """从文件加载缓存"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                now = time.time()
                for key, value in data.items():
                    if now - value.get('timestamp', 0) < self.ttl:
                        self._cache[key] = value
                logger.info(f"云缓存已加载: {len(self._cache)} 条")
        except Exception:
            pass

    def save(self):
        """保存缓存到文件"""
        try:
            with self._lock:
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    json.dump(dict(self._cache), f, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存云缓存失败: {e}")

    def get(self, key: str) -> Optional[Dict]:
        """获取缓存"""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if time.time() - entry.get('timestamp', 0) < self.ttl:
                    self._cache.move_to_end(key)
                    return entry
                else:
                    del self._cache[key]
            return None

    def set(self, key: str, value: Dict):
        """设置缓存"""
        with self._lock:
            value['timestamp'] = time.time()
            self._cache[key] = value
            if len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)

    def stats(self) -> Dict:
        """缓存统计"""
        with self._lock:
            return {
                'entries': len(self._cache),
                'max_entries': self.max_entries,
                'ttl_hours': self.ttl / 3600,
            }


class CloudProtocol:
    """云通信协议"""
    def __init__(self, server_url: str, timeout: int = 10):
        self.server_url = server_url
        self.timeout = timeout

    def build_request(self, file_hash: str, file_size: int = 0,
                     extension: str = '') -> Dict:
        """构建查询请求"""
        return {
            'hash': file_hash,
            'size': file_size,
            'extension': extension,
            'version': '1.0',
            'timestamp': int(time.time()),
            'client_id': self._get_client_id(),
        }

    def _get_client_id(self) -> str:
        """获取客户端ID"""
        machine_id = os.environ.get('COMPUTERNAME', 'unknown')
        user_id = os.environ.get('USERNAME', 'unknown')
        return hashlib.md5(f"{machine_id}-{user_id}".encode()).hexdigest()[:16]

    def parse_response(self, response_data: Dict) -> Dict:
        """解析云响应"""
        return {
            'status': response_data.get('status', 'error'),
            'malicious': response_data.get('malicious', False),
            'threat_name': response_data.get('threat_name', ''),
            'threat_type': response_data.get('threat_type', ''),
            'confidence': response_data.get('confidence', 0),
            'description': response_data.get('description', ''),
            'first_seen': response_data.get('first_seen', ''),
            'family': response_data.get('family', ''),
        }


class ThreatIntelligence:
    """本地威胁情报"""
    def __init__(self):
        self.malicious_ips = [
            '185.234.72.0/24', '91.121.0.0/16', '45.33.0.0/16',
            '103.235.0.0/16', '5.188.0.0/16', '149.28.0.0/16',
            '45.76.0.0/16', '104.238.0.0/16', '107.172.0.0/16',
            '192.3.0.0/16', '23.94.0.0/16', '198.12.0.0/16',
        ]
        self.malicious_domains = [
            'malware.example.com', 'c2.panel.com', 'ransom.pay.com',
            'phishing.example.com', 'botnet.cnc.com',
            'malware.test.com', 'evil.example.org',
        ]
        self.malicious_urls = [
            'http://malware.example.com/bot.exe',
            'http://c2.panel.com/command',
            'http://ransom.pay.com/pay',
        ]

    def check_ip(self, ip: str) -> bool:
        """检查IP是否恶意"""
        for cidr in self.malicious_ips:
            if ip.startswith(cidr.split('/')[0].rsplit('.', 1)[0]):
                return True
        return False

    def check_domain(self, domain: str) -> bool:
        """检查域名是否恶意"""
        return domain.lower() in self.malicious_domains

    def check_url(self, url: str) -> bool:
        """检查URL是否恶意"""
        return url.lower() in self.malicious_urls

    def get_iocs(self) -> Dict:
        """获取IOC列表"""
        return {
            'ips': self.malicious_ips,
            'domains': self.malicious_domains,
            'urls': self.malicious_urls,
        }


class CloudEngine(ScanEngine):
    """云查杀引擎"""

    def __init__(self):
        super().__init__('CloudEngine', enabled=True)
        self.cache = CloudCache(
            cache_file=os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))),
                'cloud_cache.json'
            ),
            max_entries=config.get('cloud.cache_size', 10000),
            ttl_hours=config.get('cloud.cache_ttl_hours', 24),
        )
        self.protocol = CloudProtocol(
            server_url=config.get('cloud.server_url', 'https://cloud.tiandun.security/api/scan'),
            timeout=config.get('cloud.timeout_seconds', 10),
        )
        self.threat_intel = ThreatIntelligence()
        self.offline_mode = config.get('cloud.offline_mode', False)
        self.privacy_mode = config.get('cloud.privacy_mode', True)

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """云查杀"""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None

        if self.offline_mode:
            return None

        try:
            # 计算哈希
            file_hash = HashUtil.sha256_file(filepath)
            if not file_hash:
                return None

            # 检查缓存
            cached = self.cache.get(file_hash)
            if cached:
                if cached.get('malicious'):
                    return self._build_threat(filepath, cached)
                return None

            # 检查本地威胁情报
            file_size = os.path.getsize(filepath)
            ext = os.path.splitext(filepath)[1].lower()

            # 构建查询
            request = self.protocol.build_request(file_hash, file_size, ext)

            # 在隐私模式下，只发送哈希
            if self.privacy_mode:
                request = {'hash': file_hash, 'timestamp': request['timestamp']}

            # 发送查询
            import requests
            try:
                response = requests.post(
                    self.protocol.server_url,
                    json=request,
                    timeout=self.protocol.timeout
                )
                if response.status_code == 200:
                    result = self.protocol.parse_response(response.json())
                    self.cache.set(file_hash, result)

                    if result.get('malicious'):
                        return self._build_threat(filepath, result)
                else:
                    # 服务器不可用时，使用本地情报
                    pass
            except requests.Timeout:
                logger.debug(f"云查杀超时: {filepath}")
            except requests.ConnectionError:
                logger.debug(f"云查杀连接失败: {filepath}")
            except Exception:
                pass

            # 缓存未命中结果
            self.cache.set(file_hash, {'malicious': False, 'timestamp': time.time()})

        except Exception as e:
            logger.error(f"云查杀错误: {e}")

        return None

    def _build_threat(self, filepath: str, result: Dict) -> ThreatInfo:
        """构建威胁信息"""
        threat = ThreatInfo(
            file_path=filepath,
            threat_type=result.get('threat_type', ThreatType.UNKNOWN),
            threat_name=result.get('threat_name', 'Cloud.Unknown'),
            scan_engine=self.name,
            threat_level=ThreatLevel.HIGH if result.get('confidence', 0) > 80 else ThreatLevel.MEDIUM,
            result=ScanResult.MALICIOUS
        )
        threat.details = {
            'confidence': result.get('confidence', 0),
            'description': result.get('description', ''),
            'first_seen': result.get('first_seen', ''),
            'family': result.get('family', ''),
        }
        return threat

    def get_stats(self) -> Dict:
        stats = super().get_stats()
        stats['cache'] = self.cache.stats()
        return stats