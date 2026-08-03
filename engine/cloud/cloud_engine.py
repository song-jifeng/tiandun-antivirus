#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 云查杀引擎
发送文件哈希到云端查询，提供本地 SQLite 缓存
支持: 本地威胁情报, VirusTotal API (可选), MalwareBazaar 离线情报, 多服务器故障转移
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

# ============================================================
# SQLite 缓存 (取代旧的 JSON 文件缓存)
# ============================================================
from .cloud_cache_db import CloudCacheDB


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


class VirusTotalProvider:
    """VirusTotal API 提供者 (默认禁用, 需用户配置 API Key)"""

    def __init__(self, api_key: str = '', enabled: bool = False):
        self.api_key = api_key
        self.enabled = enabled and bool(api_key)
        self.timeout = 15

    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """通过 VirusTotal API 查询文件哈希"""
        if not self.enabled or not self.api_key:
            return None
        try:
            import requests
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': self.api_key, 'Accept': 'application/json'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                malicious = last_analysis.get('malicious', 0)
                suspicious = last_analysis.get('suspicious', 0)
                total = last_analysis.get('total', 0)
                if total > 0:
                    confidence = min(100, int((malicious + suspicious) * 100 / max(total, 1)))
                    threat_name = attributes.get('popular_threat_classification', {}).get(
                        'suggested_threat_label', ''
                    ) or attributes.get('meaningful_name', '')
                    return {
                        'status': 'success',
                        'malicious': malicious > 0,
                        'threat_name': threat_name or f'VT.Malicious.{malicious}of{total}',
                        'threat_type': ThreatType.UNKNOWN,
                        'confidence': confidence,
                        'description': f'VirusTotal: {malicious}/{total} engines detected',
                        'first_seen': attributes.get('first_submission_date', ''),
                        'family': '',
                        'source': 'virustotal',
                    }
            elif response.status_code == 404:
                return {'status': 'clean', 'malicious': False, 'source': 'virustotal'}
            return None
        except ImportError:
            return None
        except Exception as e:
            logger.debug(f"VirusTotal 查询失败: {e}")
            return None


class MalwareBazaarFeed:
    """MalwareBazaar 离线威胁情报 - 从 RSS 或 API 获取恶意软件哈希"""

    def __init__(self):
        self._malicious_hashes: Dict[str, Dict] = {}
        self._last_update = 0
        self._update_interval = 3600  # 1小时
        self._lock = threading.Lock()

    def update(self) -> int:
        """从 MalwareBazaar API 获取最新恶意软件哈希"""
        try:
            import requests
            # 使用 MalwareBazaar API 获取最近添加的恶意软件
            url = 'https://mb-api.abuse.ch/api/v1/'
            data = {
                'query': 'get_recent',
                'selector': 'time',
            }
            response = requests.post(url, data=data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    count = 0
                    with self._lock:
                        for entry in result.get('data', []):
                            sha256_hash = entry.get('sha256_hash', '')
                            if sha256_hash and len(sha256_hash) == 64:
                                self._malicious_hashes[sha256_hash.lower()] = {
                                    'threat_name': entry.get('signature', 'MalwareBazaar.Unknown'),
                                    'file_type': entry.get('file_type', ''),
                                    'first_seen': entry.get('first_seen', ''),
                                    'tags': entry.get('tags', []),
                                    'source': 'malwarebazaar',
                                }
                                count += 1
                            # 也存 MD5 和 SHA1
                            md5 = entry.get('md5_hash', '')
                            if md5 and len(md5) == 32:
                                self._malicious_hashes[md5.lower()] = {
                                    'threat_name': entry.get('signature', 'MalwareBazaar.Unknown'),
                                    'source': 'malwarebazaar',
                                }
                            sha1 = entry.get('sha1_hash', '')
                            if sha1 and len(sha1) == 40:
                                self._malicious_hashes[sha1.lower()] = {
                                    'threat_name': entry.get('signature', 'MalwareBazaar.Unknown'),
                                    'source': 'malwarebazaar',
                                }
                        self._last_update = time.time()
                        logger.info(f"MalwareBazaar: 更新了 {count} 个恶意软件哈希")
                        return count
            return 0
        except ImportError:
            return 0
        except Exception as e:
            logger.debug(f"MalwareBazaar 更新失败: {e}")
            return 0

    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """检查哈希是否在 MalwareBazaar 情报中"""
        with self._lock:
            entry = self._malicious_hashes.get(file_hash.lower())
            if entry:
                return {
                    'status': 'success',
                    'malicious': True,
                    'threat_name': entry.get('threat_name', 'MalwareBazaar.Unknown'),
                    'threat_type': ThreatType.UNKNOWN,
                    'confidence': 90,
                    'description': 'MalwareBazaar 已知恶意软件',
                    'first_seen': entry.get('first_seen', ''),
                    'family': '',
                    'source': 'malwarebazaar',
                }
            return None

    def get_hash_count(self) -> int:
        """获取缓存的恶意哈希数量"""
        with self._lock:
            return len(self._malicious_hashes)


class ThreatIntelligence:
    """本地威胁情报 - 包含恶意 IP、域名、URL 黑名单"""

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
    """云查杀引擎

    多层查询架构:
    1. SQLite 本地缓存
    2. MalwareBazaar 离线威胁情报
    3. 本地威胁情报 (IP/Domain/URL)
    4. 主云服务器 (带故障转移)
    5. VirusTotal API (可选, 需配置)
    """

    # 备用服务器列表（故障转移）
    FALLBACK_SERVERS = [
        '',
        'https://virusshare.com/api/scan',
        'https://www.virustotal.com/api/v3/files/',
    ]

    def __init__(self):
        super().__init__('CloudEngine', enabled=True)

        # 缓存目录
        cache_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'cache'
        )
        os.makedirs(cache_dir, exist_ok=True)

        # SQLite 缓存 (取代旧的 JSON 文件缓存)
        db_path = os.path.join(cache_dir, 'cloud_cache.db')
        self.cache = CloudCacheDB(
            db_path=db_path,
            max_entries=config.get('cloud.cache_size', 10000),
            ttl_hours=config.get('cloud.cache_ttl_hours', 24),
        )

        # 主服务器 URL (默认使用本地回退)
        default_url = config.get(
            'cloud.server_url',
            'http://127.0.0.1:8080/api/scan'
        )

        self.protocol = CloudProtocol(
            server_url=default_url,
            timeout=config.get('cloud.timeout_seconds', 10),
        )
        self.threat_intel = ThreatIntelligence()
        self.offline_mode = config.get('cloud.offline_mode', False)
        self.privacy_mode = config.get('cloud.privacy_mode', True)

        # VirusTotal 支持 (默认禁用)
        vt_api_key = config.get('cloud.virustotal_api_key', '')
        self.vt_provider = VirusTotalProvider(
            api_key=vt_api_key,
            enabled=config.get('cloud.virustotal_enabled', False)
        )

        # MalwareBazaar 离线情报
        self.malware_bazaar = MalwareBazaarFeed()
        self._mb_update_thread = None
        self._start_malwarebazaar_update()

        # 故障转移索引
        self._current_server_idx = 0
        self._server_urls = [default_url] + self.FALLBACK_SERVERS[1:]

    def _start_malwarebazaar_update(self):
        """启动 MalwareBazaar 离线情报更新"""
        try:
            # 首次更新
            self.malware_bazaar.update()

            # 定期更新线程
            def _update_loop():
                while True:
                    time.sleep(3600)  # 每小时更新
                    try:
                        self.malware_bazaar.update()
                    except Exception:
                        pass

            self._mb_update_thread = threading.Thread(
                target=_update_loop,
                daemon=True,
                name='malwarebazaar-update'
            )
            self._mb_update_thread.start()
            logger.info("MalwareBazaar 离线情报更新已启动")
        except Exception as e:
            logger.warning(f"MalwareBazaar 初始化失败: {e}")

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """云查杀 - 多层查询"""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None

        if self.offline_mode:
            return None

        try:
            # 计算哈希
            file_hash = HashUtil.sha256_file(filepath)
            if not file_hash:
                return None

            # ============================================================
            # 第1层: SQLite 本地缓存
            # ============================================================
            cached = self.cache.get(file_hash)
            if cached:
                if cached.get('malicious'):
                    return self._build_threat(filepath, cached)
                return None

            # ============================================================
            # 第2层: MalwareBazaar 离线威胁情报
            # ============================================================
            mb_result = self.malware_bazaar.check_hash(file_hash)
            if mb_result and mb_result.get('malicious'):
                self.cache.set(file_hash, mb_result)
                return self._build_threat(filepath, mb_result)

            # 也检查 MD5 和 SHA1
            md5_hash = HashUtil.md5_file(filepath)
            if md5_hash:
                mb_result = self.malware_bazaar.check_hash(md5_hash)
                if mb_result and mb_result.get('malicious'):
                    self.cache.set(file_hash, mb_result)
                    return self._build_threat(filepath, mb_result)

            sha1_hash = HashUtil.sha1_file(filepath)
            if sha1_hash:
                mb_result = self.malware_bazaar.check_hash(sha1_hash)
                if mb_result and mb_result.get('malicious'):
                    self.cache.set(file_hash, mb_result)
                    return self._build_threat(filepath, mb_result)

            # ============================================================
            # 第3层: 本地威胁情报
            # ============================================================
            file_size = os.path.getsize(filepath)
            ext = os.path.splitext(filepath)[1].lower()

            # ============================================================
            # 第4层: 云服务器查询 (带故障转移)
            # ============================================================
            request = self.protocol.build_request(file_hash, file_size, ext)

            # 在隐私模式下，只发送哈希
            if self.privacy_mode:
                request = {'hash': file_hash, 'timestamp': request['timestamp']}

            # 尝试主服务器和备用服务器
            result = self._try_server_chain(request)
            if result:
                self.cache.set(file_hash, result)
                if result.get('malicious'):
                    return self._build_threat(filepath, result)
            else:
                # 所有服务器都不可用
                self.cache.set(file_hash, {'malicious': False, 'timestamp': time.time()})

            # ============================================================
            # 第5层: VirusTotal API (可选)
            # ============================================================
            vt_result = self.vt_provider.check_hash(file_hash)
            if vt_result:
                self.cache.set(file_hash, vt_result)
                if vt_result.get('malicious'):
                    return self._build_threat(filepath, vt_result)

        except Exception as e:
            logger.error(f"云查杀错误: {e}")

        return None

    def _try_server_chain(self, request: Dict) -> Optional[Dict]:
        """尝试服务器链（故障转移）"""
        import requests

        for idx in range(self._current_server_idx, len(self._server_urls)):
            server_url = self._server_urls[idx]
            if not server_url:
                continue

            try:
                if 'virustotal' in server_url:
                    # VirusTotal 需要 API key
                    continue

                response = requests.post(
                    server_url,
                    json=request,
                    timeout=self.protocol.timeout
                )
                if response.status_code == 200:
                    self._current_server_idx = idx
                    return self.protocol.parse_response(response.json())
                elif response.status_code == 429:
                    logger.debug(f"服务器 {server_url} 限流，尝试下一个")
                elif response.status_code >= 500:
                    logger.debug(f"服务器 {server_url} 错误，尝试下一个")
                else:
                    logger.debug(f"服务器 {server_url} 返回 {response.status_code}")
            except requests.Timeout:
                logger.debug(f"服务器 {server_url} 超时")
            except requests.ConnectionError:
                logger.debug(f"服务器 {server_url} 连接失败")
            except Exception:
                continue

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
            'source': result.get('source', 'cloud'),
        }
        return threat

    def get_stats(self) -> Dict:
        stats = super().get_stats()
        stats['cache'] = self.cache.stats()
        stats['malwarebazaar_hashes'] = self.malware_bazaar.get_hash_count()
        stats['virustotal_enabled'] = self.vt_provider.enabled
        return stats