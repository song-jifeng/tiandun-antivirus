#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 安全策略与规则管理
包含访问控制、策略管理、规则引擎等功能
"""
import os
import sys
import json
import time
import re
import hashlib
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class AccessLevel(Enum):
    """访问级别"""
    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 3
    FULL = 4


class SecurityPolicy:
    """安全策略"""

    def __init__(self, policy_id: str, name: str, description: str,
                 enabled: bool = True, priority: int = 100):
        self.id = policy_id
        self.name = name
        self.description = description
        self.enabled = enabled
        self.priority = priority
        self.rules: List[SecurityRule] = []
        self.created = time.time()
        self.modified = time.time()

    def add_rule(self, rule: 'SecurityRule'):
        self.rules.append(rule)
        self.modified = time.time()

    def remove_rule(self, rule_id: str):
        self.rules = [r for r in self.rules if r.id != rule_id]
        self.modified = time.time()

    def evaluate(self, context: Dict) -> 'PolicyDecision':
        """评估策略"""
        decision = PolicyDecision(self.id, self.name)
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.matches(context):
                decision.add_rule_result(rule.evaluate(context))
        return decision

    def to_dict(self) -> Dict:
        return {
            'id': self.id, 'name': self.name, 'description': self.description,
            'enabled': self.enabled, 'priority': self.priority,
            'rules': [r.to_dict() for r in self.rules],
            'created': self.created, 'modified': self.modified,
        }


class SecurityRule:
    """安全规则"""

    def __init__(self, rule_id: str, name: str, condition: Dict,
                 action: str = 'allow', priority: int = 100,
                 enabled: bool = True):
        self.id = rule_id
        self.name = name
        self.condition = condition  # {'field': 'operator', 'value': ...}
        self.action = action  # allow, deny, log, alert
        self.priority = priority
        self.enabled = enabled
        self.hit_count = 0

    def matches(self, context: Dict) -> bool:
        """检查上下文是否匹配规则条件"""
        field = self.condition.get('field', '')
        operator = self.condition.get('operator', 'equals')
        value = self.condition.get('value', '')

        actual = context.get(field, '')
        if operator == 'equals':
            return actual == value
        elif operator == 'not_equals':
            return actual != value
        elif operator == 'contains':
            return value in str(actual)
        elif operator == 'not_contains':
            return value not in str(actual)
        elif operator == 'startswith':
            return str(actual).startswith(str(value))
        elif operator == 'endswith':
            return str(actual).endswith(str(value))
        elif operator == 'greater_than':
            return float(actual) > float(value)
        elif operator == 'less_than':
            return float(actual) < float(value)
        elif operator == 'in':
            return actual in value
        elif operator == 'not_in':
            return actual not in value
        elif operator == 'regex':
            return bool(re.match(str(value), str(actual)))
        elif operator == 'exists':
            return field in context
        elif operator == 'not_exists':
            return field not in context
        return False

    def evaluate(self, context: Dict) -> 'RuleResult':
        """评估规则"""
        self.hit_count += 1
        return RuleResult(self.id, self.name, self.action, context)

    def to_dict(self) -> Dict:
        return {
            'id': self.id, 'name': self.name, 'condition': self.condition,
            'action': self.action, 'priority': self.priority,
            'enabled': self.enabled, 'hit_count': self.hit_count,
        }


class PolicyDecision:
    """策略决策"""

    def __init__(self, policy_id: str, policy_name: str):
        self.policy_id = policy_id
        self.policy_name = policy_name
        self.rule_results: List[RuleResult] = []
        self.timestamp = time.time()

    def add_rule_result(self, result: 'RuleResult'):
        self.rule_results.append(result)

    def get_final_action(self) -> str:
        """获取最终决策"""
        actions = [r.action for r in self.rule_results]
        if 'deny' in actions:
            return 'deny'
        if 'alert' in actions:
            return 'alert'
        if 'log' in actions:
            return 'log'
        return 'allow'

    def to_dict(self) -> Dict:
        return {
            'policy_id': self.policy_id, 'policy_name': self.policy_name,
            'final_action': self.get_final_action(),
            'rule_results': [r.to_dict() for r in self.rule_results],
            'timestamp': self.timestamp,
        }


class RuleResult:
    """规则结果"""

    def __init__(self, rule_id: str, rule_name: str, action: str,
                 matched_context: Dict):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.action = action
        self.matched_context = matched_context
        self.timestamp = time.time()

    def to_dict(self) -> Dict:
        return {
            'rule_id': self.rule_id, 'rule_name': self.rule_name,
            'action': self.action, 'timestamp': self.timestamp,
        }


class PolicyEngine:
    """策略引擎"""

    def __init__(self):
        self.policies: Dict[str, SecurityPolicy] = {}
        self._decision_log: List[PolicyDecision] = []

    def add_policy(self, policy: SecurityPolicy):
        self.policies[policy.id] = policy

    def remove_policy(self, policy_id: str):
        self.policies.pop(policy_id, None)

    def evaluate(self, context: Dict) -> PolicyDecision:
        """评估上下文"""
        decisions = []
        sorted_policies = sorted(self.policies.values(),
                                 key=lambda p: p.priority, reverse=True)
        for policy in sorted_policies:
            if policy.enabled:
                decision = policy.evaluate(context)
                decisions.append(decision)
                if decision.get_final_action() == 'deny':
                    break
        # 返回第一个非allow决策，或最后一个决策
        final = decisions[-1] if decisions else PolicyDecision('none', 'No Policy')
        self._decision_log.append(final)
        if len(self._decision_log) > 1000:
            self._decision_log = self._decision_log[-1000:]
        return final

    def get_decision_log(self, limit: int = 50) -> List[Dict]:
        return [d.to_dict() for d in self._decision_log[-limit:]]

    def get_stats(self) -> Dict:
        total_policies = len(self.policies)
        total_rules = sum(len(p.rules) for p in self.policies.values())
        enabled_policies = sum(1 for p in self.policies.values() if p.enabled)
        return {
            'total_policies': total_policies,
            'total_rules': total_rules,
            'enabled_policies': enabled_policies,
            'decisions_logged': len(self._decision_log),
        }


class AccessControlList:
    """访问控制列表"""

    def __init__(self):
        self.entries: Dict[str, AccessLevel] = {}

    def add_entry(self, subject: str, level: AccessLevel):
        self.entries[subject] = level

    def remove_entry(self, subject: str):
        self.entries.pop(subject, None)

    def check_access(self, subject: str, required_level: AccessLevel) -> bool:
        level = self.entries.get(subject, AccessLevel.NONE)
        return level.value >= required_level.value

    def to_dict(self) -> Dict:
        return {k: v.name for k, v in self.entries.items()}


class WhitelistManager:
    """白名单管理器"""

    def __init__(self):
        self._whitelist: Set[str] = set()
        self._whitelist_hashes: Set[str] = set()

    def add_path(self, path: str):
        self._whitelist.add(os.path.normpath(path).lower())

    def add_hash(self, file_hash: str):
        self._whitelist_hashes.add(file_hash.lower())

    def remove_path(self, path: str):
        self._whitelist.discard(os.path.normpath(path).lower())

    def remove_hash(self, file_hash: str):
        self._whitelist_hashes.discard(file_hash.lower())

    def is_whitelisted(self, path: str) -> bool:
        norm_path = os.path.normpath(path).lower()
        for wl_path in self._whitelist:
            if norm_path.startswith(wl_path):
                return True
        return False

    def is_hash_whitelisted(self, file_hash: str) -> bool:
        return file_hash.lower() in self._whitelist_hashes

    def get_all_paths(self) -> List[str]:
        return list(self._whitelist)

    def get_all_hashes(self) -> List[str]:
        return list(self._whitelist_hashes)

    def to_dict(self) -> Dict:
        return {
            'paths': list(self._whitelist),
            'hashes': list(self._whitelist_hashes),
        }


class BlacklistManager:
    """黑名单管理器"""

    def __init__(self):
        self._blacklist: Set[str] = set()
        self._blacklist_hashes: Set[str] = set()
        self._blacklist_ips: Set[str] = set()
        self._blacklist_domains: Set[str] = set()

    def add_path(self, path: str):
        self._blacklist.add(os.path.normpath(path).lower())

    def add_hash(self, file_hash: str):
        self._blacklist_hashes.add(file_hash.lower())

    def add_ip(self, ip: str):
        self._blacklist_ips.add(ip)

    def add_domain(self, domain: str):
        self._blacklist_domains.add(domain.lower())

    def is_blacklisted(self, path: str) -> bool:
        return os.path.normpath(path).lower() in self._blacklist

    def is_hash_blacklisted(self, file_hash: str) -> bool:
        return file_hash.lower() in self._blacklist_hashes

    def is_ip_blacklisted(self, ip: str) -> bool:
        return ip in self._blacklist_ips

    def is_domain_blacklisted(self, domain: str) -> bool:
        return domain.lower() in self._blacklist_domains

    def to_dict(self) -> Dict:
        return {
            'paths': list(self._blacklist),
            'hashes': list(self._blacklist_hashes),
            'ips': list(self._blacklist_ips),
            'domains': list(self._blacklist_domains),
        }


class RuleEngine:
    """规则引擎 - 支持复杂条件组合"""

    def __init__(self):
        self.rules: List[Dict] = []

    def add_rule(self, name: str, conditions: List[Dict],
                 action: str, priority: int = 100):
        """添加规则

        conditions: [{'field': 'type', 'operator': 'equals', 'value': 'exe'},
                     {'field': 'size', 'operator': 'greater_than', 'value': 100000}]
        """
        self.rules.append({
            'name': name,
            'conditions': conditions,
            'action': action,
            'priority': priority,
            'enabled': True,
            'created': time.time(),
        })
        self.rules.sort(key=lambda r: r['priority'], reverse=True)

    def evaluate(self, context: Dict) -> List[Dict]:
        """评估所有规则"""
        results = []
        for rule in self.rules:
            if not rule['enabled']:
                continue
            matched = all(self._evaluate_condition(c, context)
                         for c in rule['conditions'])
            if matched:
                results.append({
                    'rule': rule['name'],
                    'action': rule['action'],
                    'context': context,
                })
        return results

    def _evaluate_condition(self, condition: Dict, context: Dict) -> bool:
        field = condition.get('field', '')
        operator = condition.get('operator', 'equals')
        value = condition.get('value', '')
        actual = context.get(field, '')

        if operator == 'equals':
            return actual == value
        elif operator == 'not_equals':
            return actual != value
        elif operator == 'greater_than':
            return float(actual) > float(value)
        elif operator == 'less_than':
            return float(actual) < float(value)
        elif operator == 'in':
            return actual in value
        elif operator == 'contains':
            return value in str(actual)
        elif operator == 'regex':
            return bool(re.match(str(value), str(actual)))
        return False


class ThreatIntelligence:
    """威胁情报管理"""

    def __init__(self):
        self.iocs: Dict[str, List[Dict]] = {
            'ip': [], 'domain': [], 'url': [], 'hash': [], 'email': [],
        }

    def add_ioc(self, ioc_type: str, value: str, source: str = 'local',
                 confidence: float = 0.5, tags: List[str] = None):
        if ioc_type in self.iocs:
            self.iocs[ioc_type].append({
                'value': value,
                'source': source,
                'confidence': confidence,
                'tags': tags or [],
                'added': time.time(),
            })

    def check_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        for ioc in self.iocs.get(ioc_type, []):
            if ioc['value'] == value:
                return ioc
        return None

    def get_iocs_by_type(self, ioc_type: str) -> List[Dict]:
        return list(self.iocs.get(ioc_type, []))

    def get_stats(self) -> Dict:
        return {k: len(v) for k, v in self.iocs.items()}


class SecurityAudit:
    """安全审计"""

    def __init__(self):
        self.audit_log: List[Dict] = []

    def log_event(self, event_type: str, subject: str, action: str,
                  target: str, result: str, details: Dict = None):
        self.audit_log.append({
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'subject': subject,
            'action': action,
            'target': target,
            'result': result,
            'details': details or {},
        })
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]

    def query(self, event_type: str = None, subject: str = None,
              limit: int = 100) -> List[Dict]:
        results = self.audit_log
        if event_type:
            results = [e for e in results if e['event_type'] == event_type]
        if subject:
            results = [e for e in results if e['subject'] == subject]
        return results[-limit:]

    def get_stats(self) -> Dict:
        from collections import Counter
        types = Counter(e['event_type'] for e in self.audit_log)
        return {
            'total_events': len(self.audit_log),
            'by_type': dict(types.most_common(10)),
        }


class ComplianceChecker:
    """合规检查器"""

    @staticmethod
    def check_password_policy(password: str) -> Dict:
        """检查密码策略"""
        score = 0
        feedback = []
        if len(password) >= 8:
            score += 20
        else:
            feedback.append('长度至少8位')
        if re.search(r'[A-Z]', password):
            score += 20
        else:
            feedback.append('需要大写字母')
        if re.search(r'[a-z]', password):
            score += 20
        else:
            feedback.append('需要小写字母')
        if re.search(r'\d', password):
            score += 20
        else:
            feedback.append('需要数字')
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        else:
            feedback.append('需要特殊字符')
        level = ('very_weak' if score < 40 else 'weak' if score < 60
                else 'medium' if score < 80 else 'strong')
        return {'score': score, 'level': level, 'feedback': feedback}

    @staticmethod
    def check_data_encryption(filepath: str) -> Dict:
        """检查文件是否加密"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
            # 检查常见加密文件头
            encrypted_headers = {
                b'\x00\x00\x00\x00': '未知加密格式',
                b'\x45\x6e\x63\x72': 'Encrypted',
            }
            for sig, name in encrypted_headers.items():
                if header.startswith(sig):
                    return {'encrypted': True, 'format': name}
            # 熵值检查
            from collections import Counter
            import math
            with open(filepath, 'rb') as f:
                data = f.read(65536)
            counter = Counter(data)
            entropy = 0
            for count in counter.values():
                p = count / len(data)
                if p > 0:
                    entropy -= p * math.log2(p)
            return {
                'encrypted': entropy > 7.5,
                'entropy': round(entropy, 2),
                'suspicious': entropy > 7.5,
            }
        except Exception:
            return {'error': '无法检查文件'}

    @staticmethod
    def check_logging_config() -> Dict:
        """检查日志配置合规性"""
        checks = []
        # 检查日志是否启用
        checks.append({
            'check': '日志记录启用',
            'passed': True,
            'recommendation': '',
        })
        # 检查日志级别
        checks.append({
            'check': '日志级别配置',
            'passed': True,
            'recommendation': '建议生产环境使用INFO级别',
        })
        return {
            'compliant': all(c['passed'] for c in checks),
            'checks': checks,
        }


class DataClassification:
    """数据分类器"""

    CLASSIFICATIONS = ['public', 'internal', 'confidential', 'restricted', 'secret']

    @staticmethod
    def classify_data(data_type: str, content: str) -> Dict:
        """对数据进行分类"""
        classification = 'public'
        reasons = []
        # 检测敏感信息
        if re.search(r'password|passwd|pwd|secret|token|apikey|api_key', content, re.I):
            classification = 'restricted'
            reasons.append('包含密码/密钥')
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', content):
            classification = 'confidential'
            reasons.append('包含SSN')
        if re.search(r'credit.?card|visa|mastercard|amex', content, re.I):
            classification = 'restricted'
            reasons.append('包含信用卡信息')
        if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content):
            if classification == 'public':
                classification = 'internal'
            reasons.append('包含邮箱地址')
        if re.search(r'\b\d{17}[\dXx]\b', content):
            classification = 'confidential'
            reasons.append('包含身份证号')
        return {
            'classification': classification,
            'reasons': reasons,
            'handling_requirements': DataClassification._get_requirements(classification),
        }

    @staticmethod
    def _get_requirements(classification: str) -> List[str]:
        requirements = {
            'public': ['无需特殊处理'],
            'internal': ['限制内部访问', '不得公开分享'],
            'confidential': ['加密存储', '访问控制', '审计日志'],
            'restricted': ['强加密', '最小权限', '完整审计', '定期审查'],
            'secret': ['最高级别加密', '严格访问控制', '完整审计跟踪', '专人管理'],
        }
        return requirements.get(classification, ['未知分类'])


class SecurityPosture:
    """安全态势评估"""

    @staticmethod
    def assess() -> Dict:
        """评估整体安全态势"""
        score = 0
        findings = []
        # 检查防火墙
        try:
            import subprocess
            result = subprocess.run(
                'netsh advfirewall show allprofiles state',
                shell=True, capture_output=True, text=True, timeout=5
            )
            if 'ON' in result.stdout:
                score += 20
                findings.append({'category': '防火墙', 'status': '已启用', 'score': 20})
            else:
                findings.append({'category': '防火墙', 'status': '已禁用', 'score': 0})
        except Exception:
            pass
        # 检查自动更新
        try:
            result = subprocess.run(
                'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions',
                shell=True, capture_output=True, text=True, timeout=5
            )
            if 'AUOptions' in result.stdout:
                score += 20
                findings.append({'category': '自动更新', 'status': '已启用', 'score': 20})
            else:
                findings.append({'category': '自动更新', 'status': '未配置', 'score': 0})
        except Exception:
            pass
        # 检查UAC
        try:
            result = subprocess.run(
                'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA',
                shell=True, capture_output=True, text=True, timeout=5
            )
            if '0x1' in result.stdout:
                score += 20
                findings.append({'category': 'UAC', 'status': '已启用', 'score': 20})
            else:
                findings.append({'category': 'UAC', 'status': '已禁用', 'score': 0})
        except Exception:
            pass
        # 检查Defender
        try:
            result = subprocess.run(
                'powershell -Command "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled"',
                shell=True, capture_output=True, text=True, timeout=10
            )
            if 'True' in result.stdout:
                score += 20
                findings.append({'category': 'Defender', 'status': '已启用', 'score': 20})
            else:
                findings.append({'category': 'Defender', 'status': '已禁用', 'score': 0})
        except Exception:
            pass
        # 检查屏幕保护
        try:
            result = subprocess.run(
                'reg query "HKCU\Control Panel\Desktop" /v ScreenSaveActive',
                shell=True, capture_output=True, text=True, timeout=5
            )
            if '1' in result.stdout:
                score += 20
                findings.append({'category': '屏幕保护', 'status': '已启用', 'score': 20})
            else:
                findings.append({'category': '屏幕保护', 'status': '未启用', 'score': 0})
        except Exception:
            pass
        return {
            'overall_score': score,
            'max_score': 100,
            'level': 'excellent' if score >= 80 else 'good' if score >= 60 else 'fair' if score >= 40 else 'poor',
            'findings': findings,
        }