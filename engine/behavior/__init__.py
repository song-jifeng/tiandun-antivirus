#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 行为分析引擎包
包含进程监控、文件监控、注册表监控、网络监控、HIPS主动防御
"""
from .behavior_engine import BehaviorEngine
from .hips import HIPSEngine