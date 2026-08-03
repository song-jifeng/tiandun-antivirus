#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 验证与数据完整性工具
"""
import os
import sys
import json
import time
import hashlib
from typing import Dict, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DataValidator:
    """数据验证器"""

    @staticmethod
    def validate_string(value: str, min_len: int = 0, max_len: int = 1024,
                        pattern: str = None) -> bool:
        if not isinstance(value, str):
            return False
        if len(value) < min_len or len(value) > max_len:
            return False
        if pattern and not __import__('re').match(pattern, value):
            return False
        return True

    @staticmethod
    def validate_number(value, min_val: float = None, max_val: float = None) -> bool:
        if not isinstance(value, (int, float)):
            return False
        if min_val is not None and value < min_val:
            return False
        if max_val is not None and value > max_val:
            return False
        return True

    @staticmethod
    def validate_list(value, min_len: int = 0, max_len: int = 10000) -> bool:
        if not isinstance(value, list):
            return False
        if len(value) < min_len or len(value) > max_len:
            return False
        return True

    @staticmethod
    def validate_dict(value, required_keys: List[str] = None) -> bool:
        if not isinstance(value, dict):
            return False
        if required_keys:
            for key in required_keys:
                if key not in value:
                    return False
        return True

    @staticmethod
    def validate_file_path(path: str) -> bool:
        try:
            os.path.normpath(path)
            return True
        except Exception:
            return False

    @staticmethod
    def validate_ip(ip: str) -> bool:
        import socket
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def validate_email(email: str) -> bool:
        import re
        return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

    @staticmethod
    def validate_url(url: str) -> bool:
        import re
        return bool(re.match(r'^https?://[^\s/$.?#].[^\s]*$', url))

    @staticmethod
    def validate_hash(hash_str: str) -> bool:
        valid = {32, 40, 64, 128}
        return len(hash_str) in valid and all(c in '0123456789abcdef' for c in hash_str.lower())


class DataSanitizer:
    """数据清理器"""

    @staticmethod
    def sanitize_path(path: str) -> str:
        return os.path.normpath(path).replace('..', '')

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        import re
        return re.sub(r'[<>:"/\\|?*]', '_', filename)

    @staticmethod
    def sanitize_html(html: str) -> str:
        import html
        return html.escape(html)

    @staticmethod
    def sanitize_sql(sql: str) -> str:
        import re
        return re.sub(r"['\"\\;]", '', sql)

    @staticmethod
    def sanitize_shell(cmd: str) -> str:
        import re
        return re.sub(r'[;&|`$(){}]', '', cmd)

    @staticmethod
    def strip_html_tags(html: str) -> str:
        import re
        return re.sub(r'<[^>]+>', '', html)


class ChecksumValidator:
    """校验和验证器"""

    @staticmethod
    def md5(filepath: str, expected: str) -> bool:
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest() == expected.lower()

    @staticmethod
    def sha256(filepath: str, expected: str) -> bool:
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest() == expected.lower()

    @staticmethod
    def verify_checksum_file(checksum_file: str, base_dir: str = '.') -> Dict:
        results = {}
        with open(checksum_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    expected = parts[0]
                    filename = parts[1]
                    filepath = os.path.join(base_dir, filename)
                    if os.path.exists(filepath):
                        valid = ChecksumValidator.sha256(filepath, expected)
                        results[filename] = 'valid' if valid else 'invalid'
                    else:
                        results[filename] = 'missing'
        return results


class SchemaValidator:
    """Schema验证器"""

    @staticmethod
    def validate(data: Any, schema: Dict) -> List[str]:
        errors = []
        for key, rules in schema.items():
            if key not in data:
                if rules.get('required', False):
                    errors.append(f"Missing required field: {key}")
                continue
            value = data[key]
            expected_type = rules.get('type')
            if expected_type and not isinstance(value, expected_type):
                errors.append(f"{key}: expected {expected_type}, got {type(value)}")
            if 'min' in rules and isinstance(value, (int, float)):
                if value < rules['min']:
                    errors.append(f"{key}: {value} < min {rules['min']}")
            if 'max' in rules and isinstance(value, (int, float)):
                if value > rules['max']:
                    errors.append(f"{key}: {value} > max {rules['max']}")
            if 'pattern' in rules and isinstance(value, str):
                import re
                if not re.match(rules['pattern'], value):
                    errors.append(f"{key}: does not match pattern {rules['pattern']}")
            if 'enum' in rules and value not in rules['enum']:
                errors.append(f"{key}: {value} not in {rules['enum']}")
        return errors

    @staticmethod
    def validate_threat(threat: Dict) -> List[str]:
        schema = {
            'file_path': {'type': str, 'required': True},
            'threat_name': {'type': str, 'required': True},
            'threat_type': {'type': str, 'required': True},
            'threat_level': {'type': int, 'required': True, 'min': 0, 'max': 5},
            'result': {'type': int, 'required': True, 'min': -2, 'max': 2},
            'timestamp': {'type': (int, float), 'required': True},
        }
        return SchemaValidator.validate(threat, schema)

    @staticmethod
    def validate_config(config: Dict) -> List[str]:
        errors = []
        if 'general' in config:
            general = config['general']
            if 'language' in general and general['language'] not in ('zh_CN', 'en_US'):
                errors.append("Invalid language")
        if 'realtime' in config:
            rt = config['realtime']
            if 'enabled' in rt and not isinstance(rt['enabled'], bool):
                errors.append("realtime.enabled must be bool")
        if 'scan' in config:
            scan = config['scan']
            if 'thread_count' in scan and not 1 <= scan['thread_count'] <= 16:
                errors.append("scan.thread_count must be 1-16")
        return errors


class DataIntegrityChecker:
    """数据完整性检查器"""

    @staticmethod
    def check_file_hash(filepath: str, expected_hash: str) -> bool:
        return ChecksumValidator.sha256(filepath, expected_hash)

    @staticmethod
    def create_hash_manifest(directory: str) -> Dict:
        manifest = {}
        for root, _, files in os.walk(directory):
            for f in files:
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, directory)
                h = hashlib.sha256()
                with open(fpath, 'rb') as fh:
                    for chunk in iter(lambda: fh.read(65536), b''):
                        h.update(chunk)
                manifest[rel] = h.hexdigest()
        return manifest

    @staticmethod
    def verify_manifest(directory: str, manifest: Dict) -> Dict:
        results = {}
        for rel_path, expected in manifest.items():
            fpath = os.path.join(directory, rel_path)
            if not os.path.exists(fpath):
                results[rel_path] = 'missing'
            elif DataIntegrityChecker.check_file_hash(fpath, expected):
                results[rel_path] = 'valid'
            else:
                results[rel_path] = 'modified'
        return results

    @staticmethod
    def check_directory_integrity(directory: str) -> Dict:
        manifest = DataIntegrityChecker.create_hash_manifest(directory)
        return {
            'directory': directory,
            'files': len(manifest),
            'manifest': manifest,
            'timestamp': time.time(),
        }


class JSONValidator:
    """JSON验证器"""

    @staticmethod
    def validate(json_str: str) -> bool:
        try:
            json.loads(json_str)
            return True
        except json.JSONDecodeError:
            return False

    @staticmethod
    def validate_file(filepath: str) -> bool:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                json.load(f)
            return True
        except Exception:
            return False

    @staticmethod
    def get_errors(json_str: str) -> List[str]:
        errors = []
        try:
            json.loads(json_str)
        except json.JSONDecodeError as e:
            errors.append(str(e))
        return errors


class TypeValidator:
    """类型验证器"""

    @staticmethod
    def is_string(value) -> bool:
        return isinstance(value, str)

    @staticmethod
    def is_number(value) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @staticmethod
    def is_integer(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def is_boolean(value) -> bool:
        return isinstance(value, bool)

    @staticmethod
    def is_list(value) -> bool:
        return isinstance(value, list)

    @staticmethod
    def is_dict(value) -> bool:
        return isinstance(value, dict)

    @staticmethod
    def is_none(value) -> bool:
        return value is None

    @staticmethod
    def type_name(value) -> str:
        return type(value).__name__


class RangeValidator:
    """范围验证器"""

    @staticmethod
    def in_range(value: float, min_val: float, max_val: float) -> bool:
        return min_val <= value <= max_val

    @staticmethod
    def in_list(value, valid_list: list) -> bool:
        return value in valid_list

    @staticmethod
    def length_in_range(value, min_len: int, max_len: int) -> bool:
        return min_len <= len(value) <= max_len

    @staticmethod
    def matches_pattern(value: str, pattern: str) -> bool:
        import re
        return bool(re.match(pattern, value))

    @staticmethod
    def is_in_enum(value, enum_class) -> bool:
        return value in [e.value for e in enum_class]


class CrossValidator:
    """交叉验证器"""

    @staticmethod
    def validate_pair(value1, value2, rule: str) -> bool:
        if rule == 'equals':
            return value1 == value2
        elif rule == 'not_equals':
            return value1 != value2
        elif rule == 'greater_than':
            return value1 > value2
        elif rule == 'less_than':
            return value1 < value2
        elif rule == 'contains':
            return value2 in value1
        return False

    @staticmethod
    def validate_consistency(data: Dict, pairs: List[tuple]) -> List[str]:
        errors = []
        for field1, field2, rule in pairs:
            if field1 in data and field2 in data:
                if not CrossValidator.validate_pair(data[field1], data[field2], rule):
                    errors.append(f"{field1} and {field2} failed {rule} check")
        return errors