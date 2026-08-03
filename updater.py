#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 更新管理器
"""
import os
import sys
import json
import time
import hashlib
import threading
import subprocess
from typing import Optional, Dict, Any
from datetime import datetime

import requests

from engine.logger import logger
from engine.config import config
from engine import ENGINE_VERSION, PROJECT_ROOT


class Updater:
    """更新管理器 - 病毒库和程序更新"""

    UPDATE_URL = 'https://update.tiandun.security/api/check'
    SIGNATURE_URL = 'https://update.tiandun.security/api/signatures'

    def __init__(self):
        self._lock = threading.Lock()
        self._updating = False
        self._last_check = 0
        self._update_interval = config.get('general.update_interval_hours', 24) * 3600

    def check_update(self, force: bool = False) -> Dict[str, Any]:
        """检查更新"""
        now = time.time()
        if not force and (now - self._last_check) < self._update_interval:
            return {'status': 'skipped', 'message': '尚未到检查时间'}

        result = {
            'status': 'unknown',
            'program_update': False,
            'signature_update': False,
            'program_version': '',
            'signature_version': '',
            'message': '',
        }

        try:
            logger.info("检查更新...")
            response = requests.get(
                self.UPDATE_URL,
                params={
                    'version': ENGINE_VERSION,
                    'signature_version': config.get('signature_version', ''),
                    'platform': sys.platform,
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                result.update(data)
                self._last_check = now
                logger.info(f"更新检查完成: {result['message']}")
            else:
                result['status'] = 'error'
                result['message'] = f'服务器返回: {response.status_code}'
        except requests.Timeout:
            result['status'] = 'error'
            result['message'] = '连接超时'
        except requests.ConnectionError:
            result['status'] = 'error'
            result['message'] = '无法连接到更新服务器'
        except Exception as e:
            result['status'] = 'error'
            result['message'] = str(e)

        return result

    def update_signatures(self, force: bool = False) -> bool:
        """更新病毒库"""
        with self._lock:
            if self._updating:
                logger.warning("正在更新中...")
                return False
            self._updating = True

        try:
            logger.info("开始更新病毒库...")
            response = requests.get(
                self.SIGNATURE_URL,
                params={
                    'current_version': config.get('signature_version', ''),
                },
                timeout=120
            )

            if response.status_code == 200:
                sig_data = response.json()
                sig_path = PROJECT_ROOT / 'engine' / 'signatures' / 'signatures_db.py'
                with open(sig_path, 'w', encoding='utf-8') as f:
                    f.write('#!/usr/bin/env python3\n')
                    f.write('# -*- coding: utf-8 -*-\n')
                    f.write(f'"""天盾 Antivirus - 病毒库 (更新于 {datetime.now().isoformat()})"""\n\n')
                    f.write(f'SIGNATURE_DB = {json.dumps(sig_data["signatures"], ensure_ascii=False, indent=1)}\n\n')
                    f.write(f'SIGNATURE_COUNT = {len(sig_data["signatures"])}\n')
                    f.write(f'SIGNATURE_VERSION = "{sig_data["version"]}"\n')

                config.set('signature_version', sig_data['version'])
                config.save()
                logger.info(f"病毒库更新完成: {sig_data['version']} ({len(sig_data['signatures'])}条)")
                return True
            elif response.status_code == 304:
                logger.info("病毒库已是最新")
                return True
            else:
                logger.error(f"病毒库更新失败: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"病毒库更新失败: {e}")
            return False
        finally:
            with self._lock:
                self._updating = False

    def update_program(self) -> bool:
        """更新程序"""
        from notifier import notifier
        try:
            logger.info("检查程序更新...")
            result = self.check_update(force=True)
            if result.get('program_update'):
                download_url = result.get('download_url', '')
                if download_url:
                    logger.info(f"下载更新: {download_url}")
                    response = requests.get(download_url, stream=True, timeout=300)
                    if response.status_code == 200:
                        installer_path = os.path.join(
                            os.environ.get('TEMP', 'C:\\Temp'),
                            'tiandun_update.exe'
                        )
                        with open(installer_path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)
                        logger.info("更新下载完成，启动安装...")
                        notifier.notify("更新下载完成", "天盾 Antivirus 更新已下载，即将安装")
                        subprocess.Popen([installer_path, '/silent'])
                        return True
                else:
                    # 提示用户手动下载
                    notifier.notify(
                        "更新可用",
                        f"天盾 Antivirus {result.get('program_version', '')} 已可用，请访问官网下载",
                        'info'
                    )
            return False
        except Exception as e:
            logger.error(f"程序更新失败: {e}")
            return False


# ============================================================
# 全局更新器
# ============================================================
updater = Updater()