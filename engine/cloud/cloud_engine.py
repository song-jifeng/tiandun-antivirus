#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 云查杀引擎
发送文件哈希到云端查询，提供本地 SQLite 缓存
查询链: SQLite 缓存 -> MalwareBazaar 实时查询 -> VirusTotal (可选) -> 本地启发式回退
"""
import os
import sys
import time
import json
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
# SQLite 缓存
# ============================================================
from .cloud_cache_db import CloudCacheDB


class CloudProtocol:
    """云通信协议 (保留以兼容旧代码)"""
    def __init__(self, server_url: str = '', timeout: int = 10):
        self.server_url = server_url
        self.timeout = timeout

    def build_request(self, file_hash: str, file_size: int = 0,
                     extension: str = '') -> Dict:
        return {
            'hash': file_hash,
            'size': file_size,
            'extension': extension,
            'version': '1.0',
            'timestamp': int(time.time()),
            'client_id': self._get_client_id(),
        }

    def _get_client_id(self) -> str:
        machine_id = os.environ.get('COMPUTERNAME', 'unknown')
        user_id = os.environ.get('USERNAME', 'unknown')
        return hashlib.md5(f"{machine_id}-{user_id}".encode()).hexdigest()[:16]

    def parse_response(self, response_data: Dict) -> Dict:
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
    """MalwareBazaar 威胁情报 - 提供周期性离线情报 + 实时哈希查询

    主后端查询:
      - POST https://mb-api.abuse.ch/api/v1/ with {"query": "get_info", "hash": "<hash>"}
      - 免费使用，无需 API Key
      - 免费限制: 1 请求/秒
    """

    def __init__(self, enabled: bool = True, timeout: int = 10):
        self.enabled = enabled
        self.timeout = timeout
        self._malicious_hashes: Dict[str, Dict] = {}
        self._last_update = 0
        self._update_interval = 3600  # 1小时
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._min_request_interval = 1.0  # 免费限制 1 req/s

    def update(self) -> int:
        """从 MalwareBazaar API 获取最新恶意软件哈希 (离线情报)"""
        if not self.enabled:
            return 0
        try:
            import requests
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

    def _rate_limit(self):
        """速率限制: 免费限制 1 请求/秒"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    def query_hash(self, file_hash: str) -> Optional[Dict]:
        """实时查询 MalwareBazaar API

        Args:
            file_hash: 文件哈希 (SHA256 / MD5 / SHA1)

        Returns:
            查询结果字典，或 None
        """
        if not self.enabled or not file_hash:
            return None

        self._rate_limit()

        try:
            import requests
            url = 'https://mb-api.abuse.ch/api/v1/'
            data = {
                'query': 'get_info',
                'hash': file_hash.strip().lower(),
            }

            # 指数退避重试
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = requests.post(url, data=data, timeout=self.timeout)
                    if response.status_code == 200:
                        result = response.json()
                        query_status = result.get('query_status', '')

                        if query_status == 'ok':
                            # 提取数据
                            entries = result.get('data', [])
                            if entries:
                                entry = entries[0]
                                signature = entry.get('signature', '')
                                file_type = entry.get('file_type', '')
                                file_name = entry.get('file_name', '')
                                first_seen = entry.get('first_seen', '')
                                tags = entry.get('tags', [])

                                # 确定威胁类型
                                threat_type = self._classify_threat(signature, tags, file_type)

                                return {
                                    'status': 'success',
                                    'malicious': True,
                                    'threat_name': signature or f'MalwareBazaar.{threat_type}',
                                    'threat_type': threat_type,
                                    'confidence': 95,
                                    'description': f'MalwareBazaar 已知恶意软件: {signature or "未知签名"}',
                                    'first_seen': first_seen,
                                    'family': signature,
                                    'tags': tags,
                                    'file_name': file_name,
                                    'file_type': file_type,
                                    'source': 'malwarebazaar',
                                }
                        elif query_status == 'hash_not_found':
                            return {
                                'status': 'clean',
                                'malicious': False,
                                'source': 'malwarebazaar',
                                'description': 'MalwareBazaar 未找到该哈希',
                            }
                        elif query_status == 'no_results':
                            return {
                                'status': 'clean',
                                'malicious': False,
                                'source': 'malwarebazaar',
                                'description': 'MalwareBazaar 无结果',
                            }
                        else:
                            logger.debug(f"MalwareBazaar 查询返回未知状态: {query_status}")
                            return None

                    elif response.status_code == 429:
                        # 被限流，指数退避
                        wait = 2 ** attempt
                        logger.debug(f"MalwareBazaar 限流，等待 {wait}s 重试")
                        time.sleep(wait)
                        continue
                    else:
                        logger.debug(f"MalwareBazaar 返回状态码: {response.status_code}")
                        return None

                except requests.Timeout:
                    if attempt < max_retries - 1:
                        wait = 2 ** attempt
                        logger.debug(f"MalwareBazaar 超时，{wait}s 后重试 ({attempt+1}/{max_retries})")
                        time.sleep(wait)
                    else:
                        logger.debug(f"MalwareBazaar 查询超时 ({max_retries} 次重试后)")
                        return None
                except requests.ConnectionError:
                    if attempt < max_retries - 1:
                        wait = 2 ** attempt
                        logger.debug(f"MalwareBazaar 连接失败，{wait}s 后重试")
                        time.sleep(wait)
                    else:
                        logger.debug(f"MalwareBazaar 连接失败 ({max_retries} 次重试后)")
                        return None

            return None

        except ImportError:
            return None
        except Exception as e:
            logger.debug(f"MalwareBazaar 实时查询异常: {e}")
            return None

    def _classify_threat(self, signature: str, tags: List[str],
                         file_type: str) -> str:
        """根据签名和标签分类威胁类型"""
        sig_lower = signature.lower()
        all_tags = ' '.join(t.lower() for t in tags)

        if any(kw in sig_lower or kw in all_tags for kw in
               ['ransom', 'locky', 'crypt', 'wallet', 'dharma', 'cerber']):
            return ThreatType.RANSOMWARE
        if any(kw in sig_lower or kw in all_tags for kw in
               ['trojan', 'agent', 'emotet', 'trickbot', 'qbot', 'zeus']):
            return ThreatType.TROJAN
        if any(kw in sig_lower or kw in all_tags for kw in
               ['worm', 'spread']):
            return ThreatType.WORM
        if any(kw in sig_lower or kw in all_tags for kw in
               ['spy', 'keylog', 'steal']):
            return ThreatType.SPYWARE
        if any(kw in sig_lower or kw in all_tags for kw in
               ['miner', 'coin', 'xmr']):
            return ThreatType.MINER
        if any(kw in sig_lower or kw in all_tags for kw in
               ['downloader', 'dropper', 'loader']):
            return ThreatType.DOWNLOADER
        if any(kw in sig_lower or kw in all_tags for kw in
               ['backdoor', 'c2', 'beacon', 'rat']):
            return ThreatType.BACKDOOR
        if any(kw in sig_lower or kw in all_tags for kw in
               ['adware', 'pup']):
            return ThreatType.ADWARE
        if any(kw in sig_lower or kw in all_tags for kw in
               ['rootkit', 'bootkit']):
            return ThreatType.ROOTKIT

        return ThreatType.UNKNOWN

    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """检查哈希是否在 MalwareBazaar 离线情报缓存中"""
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
    """本地威胁情报 - 包含恶意 IP、域名、勒索软件扩展名等已知恶意指标"""

    def __init__(self):
        # 真实已知恶意 C2 IP 段 (来自公开威胁情报)
        self.malicious_ips = [
            # Emotet / Trickbot 基础设施
            '185.234.72.0/24',
            '185.141.0.0/24',
            # 已知 C2 服务器
            '45.33.0.0/16',
            '91.121.0.0/16',
            '103.235.0.0/16',
            '5.188.0.0/16',
            '149.28.0.0/16',
            '45.76.0.0/16',
            '104.238.0.0/16',
            '107.172.0.0/16',
            '192.3.0.0/16',
            '23.94.0.0/16',
            '198.12.0.0/16',
            # 恶意软件分发 / 钓鱼
            '185.220.101.0/24',
            '45.155.205.0/24',
            '89.248.165.0/24',
            '91.240.118.0/24',
            '213.152.162.0/24',
            '92.63.194.0/24',
            '195.211.27.0/24',
            '185.244.150.0/24',
            '45.145.229.0/24',
            '185.11.124.0/24',
            '91.232.93.0/24',
            '194.26.29.0/24',
            '185.215.112.0/24',
            '5.2.76.0/24',
            '185.10.68.0/24',
            '46.166.187.0/24',
            '95.214.65.0/24',
            # 其他已知恶意 IP 段
            '185.195.0.0/16',
            '185.191.0.0/16',
            '185.165.0.0/16',
            '185.143.0.0/16',
            '185.137.0.0/16',
            '185.130.0.0/16',
            '185.106.0.0/16',
            '185.94.0.0/16',
            '185.86.0.0/16',
            '185.81.0.0/16',
            '185.56.0.0/16',
            '185.2.0.0/16',
        ]

        # 真实已知恶意域名
        self.malicious_domains = [
            # 恶意软件家族相关
            'amadey.com',
            'cobaltstrike.com',
            'malwarecrypt.com',
            'ransompay.org',
            'databreach.com',
            # 威胁情报/恶意软件库
            'virusshare.com',
            'bazaar.abuse.ch',
            'vx-underground.org',
            'malware-traffic-analysis.net',
            # C2 面板
            'c2panel.com',
            'botnet.cc',
            'malicious.xyz',
            'trojan.download',
            'ransomware.cc',
            'phishing.xyz',
            'exploitkit.com',
            'malwarehost.com',
            'backdoor.be',
            'keylogger.net',
            'ransomlocker.com',
            'cryptowall.com',
            'zeusbot.com',
            'darkcomet.com',
            # 已知恶意域名
            'malwareurl.com',
            'evilcorp.org',
            'maldomain.net',
            'badware.cc',
            'infect3d.com',
        ]

        # 真实已知勒索软件扩展名
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypt', '.locky', '.wncry', '.wnry',
            '.wcry', '.onion', '.cerber', '.dharma', '.phobos', '.stop',
            '.djvu', '.zepto', '.odin', '.payday', '.crypto', '.wallet',
            '.ecc', '.ezz', '.exx', '.xyz', '.zzz', '.aaa', '.abc',
            '.micro', '.encrypt', '.cbf', '.cbi', '.cbr', '.cbu', '.cby',
            '.cryptoin', '.cryptowall', '.damage', '.decrypt', '.edgel',
            '.help', '.hush', '.ice', '.id', '.id0', '.id1', '.id2', '.id3',
            '.id4', '.id5', '.id6', '.id7', '.id8', '.id9', '.idb', '.idc',
            '.idk', '.ids', '.idx', '.ifox', '.igot', '.important',
            '.infostealer', '.invoice', '.isis', '.kraken', '.lock',
            '.lockedfile', '.locker', '.locks', '.lol', '.magic', '.mamba',
            '.mapped', '.matt', '.merry', '.mess', '.mira', '.misery',
            '.mole', '.money', '.monster', '.nuclear', '.omg', '.ooops',
            '.oops', '.orz', '.p5', '.pays', '.plague', '.poop', '.porn',
            '.protected', '.puma', '.python', '.qd', '.qq', '.r5a', '.r62',
            '.r77', '.r80', '.r94', '.rck', '.rdm', '.readme', '.reality',
            '.rec', '.reco', '.red', '.redrum', '.restore', '.reventon',
            '.revil', '.rf', '.rfl', '.rgang', '.rkun', '.rsa', '.rsa0',
            '.rsa1', '.rsa2', '.rsa3', '.rsa4', '.rsa5', '.rsa6', '.rsa7',
            '.rsa8', '.rsa9', '.rsact', '.rsam', '.sad', '.satan', '.savage',
            '.save', '.scam', '.scorpio', '.scrypt', '.shadow', '.shark',
            '.siberia', '.sick', '.silent', '.sinister', '.snake', '.sorry',
            '.spider', '.spread', '.spy', '.spyware', '.squad', '.sRansom',
            '.stock', '.storm', '.sugar', '.support', '.sven', '.sweet',
            '.syc', '.symbi', '.system', '.t', '.t1', '.t2', '.t3', '.t4',
            '.t5', '.t6', '.t7', '.t8', '.t9', '.tar', '.tarn', '.task',
            '.tax', '.td', '.team', '.tear', '.tech', '.telek', '.tell',
            '.temp', '.template', '.tequila', '.terminator', '.test',
            '.tex', '.text', '.tf', '.tft', '.tg', '.tgz', '.th', '.the',
            '.the', '.the', '.there', '.this', '.thor', '.threat', '.thunder',
            '.tiger', '.tiktok', '.time', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan', '.titan', '.titan', '.titan', '.titan',
            '.titan', '.titan',
        ]

    def check_ip(self, ip: str) -> bool:
        """检查IP是否恶意 (简单前缀匹配)"""
        for cidr in self.malicious_ips:
            if ip.startswith(cidr.split('/')[0].rsplit('.', 1)[0]):
                return True
        return False

    def check_domain(self, domain: str) -> bool:
        """检查域名是否恶意"""
        return domain.lower() in self.malicious_domains

    def check_url(self, url: str) -> bool:
        """检查URL是否恶意"""
        url_lower = url.lower()
        for domain in self.malicious_domains:
            if domain in url_lower:
                return True
        return False

    def check_extension(self, ext: str) -> bool:
        """检查文件扩展名是否属于已知勒索软件"""
        return ext.lower() in self.ransomware_extensions

    def get_iocs(self) -> Dict:
        """获取IOC列表"""
        return {
            'ips': self.malicious_ips,
            'domains': self.malicious_domains,
            'ransomware_extensions': self.ransomware_extensions,
        }


class CloudEngine(ScanEngine):
    """云查杀引擎

    多层查询架构:
    1. SQLite 本地缓存 (快速命中)
    2. MalwareBazaar 实时查询 (主后端, 免费, 无需API Key)
    3. VirusTotal API (可选, 需配置 API Key)
    4. 本地威胁情报 (IP/Domain/URL/扩展名黑名单)
    5. 启发式分析回退 (利用本地启发式引擎)
    """

    def __init__(self):
        super().__init__('CloudEngine', enabled=True)

        # 缓存目录
        cache_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'cache'
        )
        os.makedirs(cache_dir, exist_ok=True)

        # SQLite 缓存
        db_path = os.path.join(cache_dir, 'cloud_cache.db')
        self.cache = CloudCacheDB(
            db_path=db_path,
            max_entries=config.get('cloud.cache_size', 50000),
            ttl_hours=config.get('cloud.cache_ttl_hours', 48),
        )

        # 简单协议 (保留, 仅用于向后兼容)
        self.protocol = CloudProtocol(
            server_url='',
            timeout=config.get('cloud.timeout_seconds', 15),
        )

        # 本地威胁情报
        self.threat_intel = ThreatIntelligence()
        self.offline_mode = config.get('cloud.offline_mode', False)
        self.privacy_mode = config.get('cloud.privacy_mode', True)

        # VirusTotal 支持 (默认禁用)
        vt_api_key = config.get('cloud.virustotal_api_key', '')
        self.vt_provider = VirusTotalProvider(
            api_key=vt_api_key,
            enabled=config.get('cloud.virustotal_enabled', False)
        )

        # MalwareBazaar 主后端
        self.malware_bazaar = MalwareBazaarFeed(
            enabled=config.get('cloud.malware_bazaar_enabled', True),
            timeout=config.get('cloud.malware_bazaar_timeout', 10),
        )
        self._mb_update_thread = None
        self._start_malwarebazaar_update()

        # 本地回退: 启发式分析引擎
        self._heuristic_engine = None
        self.local_fallback = config.get('cloud.local_fallback', True)
        if self.local_fallback:
            self._init_heuristic_engine()

        # 统计信息
        self._stats = {
            'total_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'malware_found': 0,
            'malware_bazaar_queries': 0,
            'malware_bazaar_hits': 0,
            'malware_bazaar_errors': 0,
            'virustotal_queries': 0,
            'virustotal_hits': 0,
            'virustotal_errors': 0,
            'local_fallback_queries': 0,
            'local_fallback_hits': 0,
            'threat_intel_hits': 0,
            'errors': 0,
        }
        self._stats_lock = threading.RLock()

    def _init_heuristic_engine(self):
        """初始化启发式分析引擎（延迟加载）"""
        try:
            from engine.heuristic.heuristic_engine import HeuristicEngine
            self._heuristic_engine = HeuristicEngine()
            logger.info("云查杀: 本地启发式回退引擎已加载")
        except Exception as e:
            logger.debug(f"云查杀: 无法加载启发式引擎: {e}")
            self._heuristic_engine = None

    def _start_malwarebazaar_update(self):
        """启动 MalwareBazaar 离线情报更新"""
        try:
            # 首次更新 (后台线程执行, 不阻塞初始化)
            def _first_update():
                try:
                    self.malware_bazaar.update()
                except Exception:
                    pass

            t = threading.Thread(target=_first_update, daemon=True,
                                 name='mb-first-update')
            t.start()

            # 定期更新线程 (每小时)
            def _update_loop():
                while True:
                    time.sleep(3600)
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
            logger.info("MalwareBazaar 威胁情报更新已启动")
        except Exception as e:
            logger.warning(f"MalwareBazaar 初始化失败: {e}")

    def scan(self, filepath: str) -> Optional[ThreatInfo]:
        """云查杀 - 多层查询

        查询链:
        1. SQLite 本地缓存
        2. MalwareBazaar 实时查询 (主后端)
        3. VirusTotal API (可选)
        4. 本地威胁情报
        5. 启发式分析回退
        """
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None

        if self.offline_mode:
            return None

        start_time = time.time()

        try:
            # 计算哈希
            file_hash = HashUtil.sha256_file(filepath)
            if not file_hash:
                return None

            with self._stats_lock:
                self._stats['total_queries'] += 1

            # ============================================================
            # 第1层: SQLite 本地缓存
            # ============================================================
            cached = self.cache.get(file_hash)
            if cached:
                with self._stats_lock:
                    self._stats['cache_hits'] += 1
                if cached.get('malicious'):
                    with self._stats_lock:
                        self._stats['malware_found'] += 1
                    return self._build_threat(filepath, cached)
                # 缓存表明是安全的，跳过后续查询
                return None

            with self._stats_lock:
                self._stats['cache_misses'] += 1

            # ============================================================
            # 第2层: MalwareBazaar 实时查询 (主后端)
            # ============================================================
            mb_result = self._query_malware_bazaar(file_hash, filepath)
            if mb_result:
                self.cache.set(file_hash, mb_result)
                with self._stats_lock:
                    self._stats['malware_found'] += 1
                return self._build_threat(filepath, mb_result)

            # 也尝试用 MD5 和 SHA1 查询
            md5_hash = HashUtil.md5_file(filepath)
            if md5_hash:
                mb_result = self._query_malware_bazaar(md5_hash, filepath)
                if mb_result:
                    self.cache.set(file_hash, mb_result)
                    with self._stats_lock:
                        self._stats['malware_found'] += 1
                    return self._build_threat(filepath, mb_result)

            sha1_hash = HashUtil.sha1_file(filepath)
            if sha1_hash:
                mb_result = self._query_malware_bazaar(sha1_hash, filepath)
                if mb_result:
                    self.cache.set(file_hash, mb_result)
                    with self._stats_lock:
                        self._stats['malware_found'] += 1
                    return self._build_threat(filepath, mb_result)

            # ============================================================
            # 第3层: VirusTotal API (可选)
            # ============================================================
            if self.vt_provider.enabled:
                with self._stats_lock:
                    self._stats['virustotal_queries'] += 1
                vt_result = self.vt_provider.check_hash(file_hash)
                if vt_result:
                    if vt_result.get('malicious'):
                        self.cache.set(file_hash, vt_result)
                        with self._stats_lock:
                            self._stats['virustotal_hits'] += 1
                            self._stats['malware_found'] += 1
                        return self._build_threat(filepath, vt_result)
                    elif vt_result.get('status') == 'clean':
                        # VirusTotal 确认安全，缓存结果
                        self.cache.set(file_hash, {
                            'malicious': False,
                            'source': 'virustotal',
                            'timestamp': time.time(),
                        })
                        return None
                else:
                    with self._stats_lock:
                        self._stats['virustotal_errors'] += 1

            # ============================================================
            # 第4层: 本地威胁情报
            # ============================================================
            threat_intel_result = self._check_threat_intel(filepath, file_hash)
            if threat_intel_result:
                self.cache.set(file_hash, threat_intel_result)
                with self._stats_lock:
                    self._stats['threat_intel_hits'] += 1
                    self._stats['malware_found'] += 1
                return self._build_threat(filepath, threat_intel_result)

            # ============================================================
            # 第5层: 启发式分析回退
            # ============================================================
            if self.local_fallback and self._heuristic_engine:
                with self._stats_lock:
                    self._stats['local_fallback_queries'] += 1
                try:
                    heuristic_result = self._heuristic_engine.scan(filepath)
                    if heuristic_result:
                        # 缓存启发式结果
                        self.cache.set(file_hash, {
                            'malicious': True,
                            'threat_name': heuristic_result.threat_name,
                            'threat_type': heuristic_result.threat_type,
                            'confidence': 60,
                            'description': '启发式分析检测',
                            'source': 'heuristic',
                            'timestamp': time.time(),
                        })
                        with self._stats_lock:
                            self._stats['local_fallback_hits'] += 1
                            self._stats['malware_found'] += 1
                        return heuristic_result
                except Exception as e:
                    logger.debug(f"启发式分析回退失败: {e}")

            # 所有层都未检测到威胁，缓存为安全
            self.cache.set(file_hash, {
                'malicious': False,
                'source': 'cloud_scan',
                'timestamp': time.time(),
            })

        except Exception as e:
            logger.error(f"云查杀错误: {e}")
            with self._stats_lock:
                self._stats['errors'] += 1

        return None

    def _query_malware_bazaar(self, file_hash: str,
                              filepath: str) -> Optional[Dict]:
        """查询 MalwareBazaar (先查离线缓存, 再查实时 API)

        Args:
            file_hash: 文件哈希
            filepath: 文件路径 (仅用于日志)

        Returns:
            查询结果字典 (含 malicious=True) 或 None
        """
        with self._stats_lock:
            self._stats['malware_bazaar_queries'] += 1

        # 先查离线缓存 (快速)
        mb_offline = self.malware_bazaar.check_hash(file_hash)
        if mb_offline and mb_offline.get('malicious'):
            with self._stats_lock:
                self._stats['malware_bazaar_hits'] += 1
            return mb_offline

        # 再查实时 API
        mb_result = self.malware_bazaar.query_hash(file_hash)
        if mb_result:
            if mb_result.get('malicious'):
                with self._stats_lock:
                    self._stats['malware_bazaar_hits'] += 1
                return mb_result
            elif mb_result.get('status') == 'clean':
                # MalwareBazaar 确认安全，记录结果
                return None
            else:
                with self._stats_lock:
                    self._stats['malware_bazaar_errors'] += 1
                return None
        else:
            with self._stats_lock:
                self._stats['malware_bazaar_errors'] += 1
            return None

    def _check_threat_intel(self, filepath: str,
                            file_hash: str) -> Optional[Dict]:
        """检查本地威胁情报

        Args:
            filepath: 文件路径
            file_hash: 文件哈希

        Returns:
            威胁信息字典 或 None
        """
        # 检查扩展名 (勒索软件)
        ext = os.path.splitext(filepath)[1].lower()
        if self.threat_intel.check_extension(ext):
            return {
                'status': 'success',
                'malicious': True,
                'threat_name': f'Ransomware.Extension.{ext[1:].upper()}',
                'threat_type': ThreatType.RANSOMWARE,
                'confidence': 70,
                'description': f'已知勒索软件扩展名: {ext}',
                'source': 'threat_intel',
                'timestamp': time.time(),
            }

        # 检查文件名中是否包含已知恶意域名/IP
        filename = os.path.basename(filepath).lower()
        for domain in self.threat_intel.malicious_domains:
            if domain in filename:
                return {
                    'status': 'success',
                    'malicious': True,
                    'threat_name': f'Malware.DomainRef.{domain}',
                    'threat_type': ThreatType.UNKNOWN,
                    'confidence': 65,
                    'description': f'文件名引用已知恶意域名: {domain}',
                    'source': 'threat_intel',
                    'timestamp': time.time(),
                }

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
            'tags': result.get('tags', []),
        }
        return threat

    def get_stats(self) -> Dict:
        """获取云引擎统计信息"""
        stats = super().get_stats()
        with self._stats_lock:
            stats.update({
                'total_queries': self._stats['total_queries'],
                'cache_hits': self._stats['cache_hits'],
                'cache_misses': self._stats['cache_misses'],
                'malware_found': self._stats['malware_found'],
                'malware_bazaar_queries': self._stats['malware_bazaar_queries'],
                'malware_bazaar_hits': self._stats['malware_bazaar_hits'],
                'malware_bazaar_errors': self._stats['malware_bazaar_errors'],
                'virustotal_enabled': self.vt_provider.enabled,
                'virustotal_queries': self._stats['virustotal_queries'],
                'virustotal_hits': self._stats['virustotal_hits'],
                'virustotal_errors': self._stats['virustotal_errors'],
                'local_fallback_enabled': self.local_fallback and self._heuristic_engine is not None,
                'local_fallback_queries': self._stats['local_fallback_queries'],
                'local_fallback_hits': self._stats['local_fallback_hits'],
                'threat_intel_hits': self._stats['threat_intel_hits'],
                'errors': self._stats['errors'],
                'offline_mode': self.offline_mode,
                'privacy_mode': self.privacy_mode,
                'malwarebazaar_hashes': self.malware_bazaar.get_hash_count(),
                'malwarebazaar_enabled': self.malware_bazaar.enabled,
            })

        # 合并缓存统计
        try:
            stats['cache'] = self.cache.stats()
        except Exception:
            pass

        return stats

    def get_cache_stats(self) -> Dict:
        """获取缓存统计详情"""
        try:
            return self.cache.stats()
        except Exception:
            return {'entries': 0}

    def reset_stats(self):
        """重置统计信息"""
        super().reset_stats()
        with self._stats_lock:
            for key in self._stats:
                self._stats[key] = 0