#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 数据加密与安全通信工具
"""
import os
import sys
import json
import base64
import hashlib
import hmac
from typing import Dict, Optional, Any
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CryptoUtils:
    """加密工具"""

    @staticmethod
    def hash_password(password: str, salt: str = None) -> Dict:
        """密码哈希"""
        if salt is None:
            salt = os.urandom(16).hex()
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return {
            'hash': key.hex(),
            'salt': salt,
            'algorithm': 'pbkdf2_hmac_sha256',
            'iterations': 100000,
        }

    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        """验证密码"""
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(key.hex(), stored_hash)

    @staticmethod
    def generate_token(length: int = 32) -> str:
        """生成随机令牌"""
        return os.urandom(length).hex()

    @staticmethod
    def encrypt_data(data: str, key: str) -> str:
        """简单加密"""
        encrypted = []
        key_bytes = key.encode()
        for i, c in enumerate(data.encode()):
            encrypted.append(c ^ key_bytes[i % len(key_bytes)])
        return base64.b64encode(bytes(encrypted)).decode()

    @staticmethod
    def decrypt_data(encrypted: str, key: str) -> str:
        """解密"""
        data = base64.b64decode(encrypted)
        decrypted = []
        key_bytes = key.encode()
        for i, c in enumerate(data):
            decrypted.append(c ^ key_bytes[i % len(key_bytes)])
        return bytes(decrypted).decode()

    @staticmethod
    def sign_data(data: str, secret: str) -> str:
        """数据签名"""
        return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(data: str, signature: str, secret: str) -> bool:
        """验证签名"""
        expected = CryptoUtils.sign_data(data, secret)
        return hmac.compare_digest(expected, signature)


class SecureConfig:
    """安全配置管理"""

    def __init__(self, master_key: str = None):
        self._master_key = master_key or os.urandom(32).hex()
        self._config = {}

    def set(self, key: str, value: Any):
        """设置加密配置"""
        encrypted = CryptoUtils.encrypt_data(json.dumps(value), self._master_key)
        self._config[key] = encrypted

    def get(self, key: str, default: Any = None) -> Any:
        """获取解密配置"""
        encrypted = self._config.get(key)
        if encrypted is None:
            return default
        try:
            decrypted = CryptoUtils.decrypt_data(encrypted, self._master_key)
            return json.loads(decrypted)
        except Exception:
            return default

    def export(self, export_key: str) -> str:
        """导出配置"""
        data = json.dumps(self._config)
        return CryptoUtils.encrypt_data(data, export_key)

    def import_config(self, encrypted_data: str, import_key: str):
        """导入配置"""
        try:
            data = CryptoUtils.decrypt_data(encrypted_data, import_key)
            self._config = json.loads(data)
        except Exception:
            raise ValueError("导入配置失败")


class ApiAuth:
    """API认证"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or CryptoUtils.generate_token(32)
        self._tokens = {}

    def generate_token(self, user_id: str, expiry: int = 3600) -> str:
        """生成访问令牌"""
        token = CryptoUtils.generate_token(32)
        self._tokens[token] = {
            'user_id': user_id,
            'created': time.time(),
            'expiry': time.time() + expiry,
        }
        return token

    def validate_token(self, token: str) -> Optional[Dict]:
        """验证令牌"""
        info = self._tokens.get(token)
        if info is None:
            return None
        if time.time() > info['expiry']:
            del self._tokens[token]
            return None
        return info

    def revoke_token(self, token: str):
        """撤销令牌"""
        self._tokens.pop(token, None)

    def authenticate(self, api_key: str) -> bool:
        """API密钥认证"""
        return hmac.compare_digest(api_key, self.api_key)


class SecureCommunication:
    """安全通信"""

    @staticmethod
    def create_message(data: Dict, secret: str) -> Dict:
        """创建安全消息"""
        timestamp = int(time.time())
        nonce = CryptoUtils.generate_token(8)
        payload = json.dumps(data, ensure_ascii=False)
        message = f"{timestamp}:{nonce}:{payload}"
        signature = CryptoUtils.sign_data(message, secret)
        return {
            'timestamp': timestamp,
            'nonce': nonce,
            'payload': base64.b64encode(payload.encode()).decode(),
            'signature': signature,
        }

    @staticmethod
    def verify_message(message: Dict, secret: str, max_age: int = 300) -> Optional[Dict]:
        """验证安全消息"""
        try:
            timestamp = message.get('timestamp', 0)
            if time.time() - timestamp > max_age:
                return None
            nonce = message.get('nonce', '')
            payload = base64.b64decode(message.get('payload', '')).decode()
            expected = f"{timestamp}:{nonce}:{payload}"
            signature = message.get('signature', '')
            if not hmac.compare_digest(CryptoUtils.sign_data(expected, secret), signature):
                return None
            return json.loads(payload)
        except Exception:
            return None


class KeyManager:
    """密钥管理器"""

    def __init__(self):
        self._keys = {}

    def generate_key(self, key_id: str, length: int = 32) -> str:
        """生成密钥"""
        key = os.urandom(length).hex()
        self._keys[key_id] = {
            'key': key,
            'created': time.time(),
            'algorithm': 'AES-256',
        }
        return key

    def get_key(self, key_id: str) -> Optional[str]:
        """获取密钥"""
        info = self._keys.get(key_id)
        return info['key'] if info else None

    def rotate_key(self, key_id: str) -> str:
        """轮转密钥"""
        return self.generate_key(key_id)

    def revoke_key(self, key_id: str):
        """撤销密钥"""
        self._keys.pop(key_id, None)

    def get_key_info(self, key_id: str) -> Optional[Dict]:
        return self._keys.get(key_id)


class CertificateManager:
    """证书管理器"""

    def __init__(self):
        self._certs = {}

    def generate_self_signed(self, common_name: str, days: int = 365) -> Dict:
        """生成自签名证书"""
        cert_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        self._certs[cert_id] = {
            'id': cert_id,
            'common_name': common_name,
            'created': time.time(),
            'expiry': time.time() + days * 86400,
            'self_signed': True,
            'fingerprint': hashlib.sha256(os.urandom(32)).hexdigest(),
        }
        return self._certs[cert_id]

    def validate_cert(self, cert_id: str) -> bool:
        """验证证书"""
        cert = self._certs.get(cert_id)
        if cert is None:
            return False
        if time.time() > cert['expiry']:
            return False
        return True

    def revoke_cert(self, cert_id: str):
        """撤销证书"""
        self._certs.pop(cert_id, None)


class DataSanitizer:
    """数据脱敏工具"""

    @staticmethod
    def mask_email(email: str) -> str:
        """脱敏邮箱"""
        if '@' not in email:
            return email
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            return f"{local[0]}***@{domain}"
        return f"{local[0]}***{local[-1]}@{domain}"

    @staticmethod
    def mask_phone(phone: str) -> str:
        """脱敏手机号"""
        if len(phone) >= 7:
            return phone[:3] + '****' + phone[-4:]
        return phone

    @staticmethod
    def mask_id_card(id_card: str) -> str:
        """脱敏身份证号"""
        if len(id_card) >= 10:
            return id_card[:4] + '**********' + id_card[-4:]
        return id_card

    @staticmethod
    def mask_bank_card(card: str) -> str:
        """脱敏银行卡号"""
        if len(card) >= 8:
            return card[:4] + ' **** **** ' + card[-4:]
        return card

    @staticmethod
    def mask_password(password: str) -> str:
        """脱敏密码"""
        return '*' * len(password)

    @staticmethod
    def sanitize_json(data: Dict, sensitive_fields: list) -> Dict:
        """脱敏JSON数据"""
        result = {}
        for key, value in data.items():
            if key in sensitive_fields:
                if isinstance(value, str):
                    result[key] = DataSanitizer.mask_password(value)
                else:
                    result[key] = '***'
            elif isinstance(value, dict):
                result[key] = DataSanitizer.sanitize_json(value, sensitive_fields)
            else:
                result[key] = value
        return result


class SecureStorage:
    """安全存储"""

    def __init__(self, storage_path: str = None):
        self.storage_path = storage_path or os.path.join(
            os.environ.get('TIANDUN_ROOT', 'D:/Antivirus'),
            'data', 'secure_store.json'
        )
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        self._data = {}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.storage_path):
                data = open(self.storage_path, 'r', encoding='utf-8').read()
                self._data = json.loads(data)
        except Exception:
            self._data = {}

    def _save(self):
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def store(self, key: str, value: Any):
        encrypted = CryptoUtils.encrypt_data(json.dumps(value), 'tiandun-secure-key')
        self._data[key] = encrypted
        self._save()

    def retrieve(self, key: str, default: Any = None) -> Any:
        encrypted = self._data.get(key)
        if encrypted is None:
            return default
        try:
            decrypted = CryptoUtils.decrypt_data(encrypted, 'tiandun-secure-key')
            return json.loads(decrypted)
        except Exception:
            return default

    def delete(self, key: str):
        self._data.pop(key, None)
        self._save()

    def clear(self):
        self._data.clear()
        self._save()


class IntegrityVerifier:
    """完整性验证器"""

    @staticmethod
    def verify_file_integrity(filepath: str, expected_hash: str,
                               algorithm: str = 'sha256') -> bool:
        """验证文件完整性"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            if algorithm == 'sha256':
                actual = hashlib.sha256(data).hexdigest()
            elif algorithm == 'sha1':
                actual = hashlib.sha1(data).hexdigest()
            else:
                actual = hashlib.md5(data).hexdigest()
            return hmac.compare_digest(actual, expected_hash.lower())
        except Exception:
            return False

    @staticmethod
    def verify_directory_integrity(directory: str, manifest: Dict) -> Dict:
        """验证目录完整性"""
        results = {}
        for fpath, expected_hash in manifest.items():
            full_path = os.path.join(directory, fpath)
            if not os.path.exists(full_path):
                results[fpath] = {'status': 'missing', 'expected': expected_hash}
                continue
            valid = IntegrityVerifier.verify_file_integrity(full_path, expected_hash)
            results[fpath] = {'status': 'valid' if valid else 'modified',
                              'expected': expected_hash}
        return results

    @staticmethod
    def create_manifest(directory: str) -> Dict:
        """创建完整性清单"""
        manifest = {}
        for root, _, files in os.walk(directory):
            for f in files:
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, directory)
                with open(fpath, 'rb') as fh:
                    manifest[rel_path] = hashlib.sha256(fh.read()).hexdigest()
        return manifest


class AuditLogger:
    """审计日志"""

    def __init__(self, log_path: str = None):
        self.log_path = log_path or os.path.join(
            os.environ.get('TIANDUN_LOGS', 'D:/Antivirus/logs'),
            'audit.log'
        )
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log(self, event_type: str, user: str, action: str,
            resource: str, result: str, details: Dict = None):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user': user,
            'action': action,
            'resource': resource,
            'result': result,
            'details': details or {},
        }
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def query(self, event_type: str = None, user: str = None,
              limit: int = 100) -> list:
        entries = []
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if event_type and entry.get('event_type') != event_type:
                            continue
                        if user and entry.get('user') != user:
                            continue
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        return entries[-limit:]


class AccessController:
    """访问控制器"""

    def __init__(self):
        self._permissions = {}
        self._roles = {
            'admin': ['read', 'write', 'execute', 'delete', 'manage'],
            'user': ['read', 'execute'],
            'guest': ['read'],
        }

    def add_user(self, username: str, role: str = 'user'):
        self._permissions[username] = self._roles.get(role, ['read'])

    def remove_user(self, username: str):
        self._permissions.pop(username, None)

    def check_permission(self, username: str, permission: str) -> bool:
        perms = self._permissions.get(username, [])
        return permission in perms

    def add_role(self, role: str, permissions: list):
        self._roles[role] = permissions