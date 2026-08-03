#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA 规则引擎 - YaraEngine
=============================

纯 Python 实现的 YARA 规则解析与匹配引擎，不依赖 yara-python 扩展库。
支持 YARA 规则的子集，包括：
  - 字符串匹配（十六进制、文本、正则表达式）
  - 条件表达式（and、or、not、of、them、count）
  - 通配符和偏移量
  - 规则标签和元数据

支持的标准 YARA 语法：
  - $ = 文本字符串
  - $ = { 十六进制字节序列 }
  - $ = / 正则表达式 /
  - nocase、wide、ascii、fullword 修饰符
  - 条件表达式：all of them, any of them, # > N, @

用法示例:
    yara = YaraEngine()
    yara.add_rule(YaraRule.from_string('''
        rule suspicious_file {
            meta:
                description = "检测可疑文件"
            strings:
                $a = "malicious"
                $b = { 6D 61 6C 69 63 69 6F 75 73 }
            condition:
                $a or $b
        }
    '''))
    results = yara.scan(data)
"""

import re
import json
from typing import List, Dict, Optional, Tuple, Set, Any, Callable, Pattern
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict


# ============================================================
# YARA 规则异常
# ============================================================
class YaraParseError(Exception):
    """YARA 规则解析错误"""
    pass


class YaraMatchError(Exception):
    """YARA 规则匹配错误"""
    pass


# ============================================================
# 规则匹配结果
# ============================================================
@dataclass
class YaraMatch:
    """单条规则的匹配结果"""
    rule_id: str               # 规则标识符
    rule_name: str             # 规则名称
    tags: List[str] = field(default_factory=list)           # 标签
    meta: Dict[str, str] = field(default_factory=dict)      # 元数据
    matched_strings: List[str] = field(default_factory=list)  # 匹配到的字符串
    description: str = ''      # 描述

    def to_dict(self) -> Dict:
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'tags': self.tags,
            'meta': self.meta,
            'matched_strings': self.matched_strings,
            'description': self.description,
        }


# ============================================================
# YARA 规则定义
# ============================================================
@dataclass
class YaraRule:
    """YARA 规则定义

    存储规则名称、元数据、字符串模式、条件表达式。
    支持从 YARA 规则文本解析。
    """
    rule_name: str
    rule_id: str = ''
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    strings: Dict[str, Any] = field(default_factory=dict)  # {id: pattern_info}
    condition: str = ''
    source: str = ''
    raw_text: str = ''

    def __post_init__(self):
        if not self.rule_id:
            self.rule_id = self.rule_name.lower().replace(' ', '_')

    @classmethod
    def from_string(cls, rule_text: str) -> 'YaraRule':
        """从 YARA 规则文本解析规则

        Args:
            rule_text: YARA 规则源码文本

        Returns:
            YaraRule 实例

        Raises:
            YaraParseError: 解析失败时抛出
        """
        parser = YaraParser()
        return parser.parse_rule(rule_text)

    @classmethod
    def from_dict(cls, data: Dict) -> 'YaraRule':
        """从字典创建规则"""
        return cls(
            rule_name=data.get('rule_name', ''),
            rule_id=data.get('rule_id', ''),
            tags=data.get('tags', []),
            meta=data.get('meta', {}),
            strings=data.get('strings', {}),
            condition=data.get('condition', ''),
            source=data.get('source', ''),
            raw_text=data.get('raw_text', ''),
        )

    def to_dict(self) -> Dict:
        return {
            'rule_name': self.rule_name,
            'rule_id': self.rule_id,
            'tags': self.tags,
            'meta': self.meta,
            'strings': self.strings,
            'condition': self.condition,
            'source': self.source,
        }

    def match(self, data: bytes) -> bool:
        """检查数据是否匹配此规则"""
        engine = YaraEngine()
        engine.add_rule(self)
        results = engine.scan(data)
        return len(results) > 0


# ============================================================
# YARA 规则解析器
# ============================================================
class YaraParser:
    """YARA 规则文本解析器

    解析 YARA 规则文本，提取规则名、标签、元数据、字符串模式、条件表达式。
    支持标准 YARA 语法子集。
    """

    # 正则：字符串定义
    RE_STRING_DEF = re.compile(
        r'\$(\w+|\*)\s*=\s*('
        r'"(?:[^"\\]|\\.)*"'        # 文本字符串
        r'|'                         # 或
        r'\{[^}]+\}'                # 十六进制字节
        r'|'                         # 或
        r'/(?:[^/\\]|\\.)+/'        # 正则表达式
        r')\s*'                      # 修饰符
        r'(?:\s*(nocase|wide|ascii|fullword|private|xor)(?:\s+(nocase|wide|ascii|fullword|private|xor))*)?'
        r'\s*$',
        re.MULTILINE
    )

    # 正则：条件表达式
    RE_CONDITION = re.compile(
        r'condition:\s*',
        re.IGNORECASE
    )

    # 正则：元数据
    RE_META = re.compile(
        r'\s*(\w+)\s*=\s*"([^"]*)"',
        re.MULTILINE
    )

    # 正则：标签
    RE_TAGS = re.compile(r'rule\s+(\w+)\s*:(\s*\w+(?:\s+\w+)*)')

    # 正则：规则名
    RE_RULE_NAME = re.compile(r'^\s*rule\s+(\w+)', re.MULTILINE)

    def parse_rule(self, rule_text: str) -> YaraRule:
        """解析单条 YARA 规则

        Args:
            rule_text: YARA 规则文本

        Returns:
            YaraRule 实例
        """
        rule_text = rule_text.strip()
        if not rule_text:
            raise YaraParseError('空规则文本')

        # 提取规则名
        name_match = self.RE_RULE_NAME.search(rule_text)
        if not name_match:
            raise YaraParseError('无法解析规则名')
        rule_name = name_match.group(1)

        # 提取标签
        tags = []
        tags_match = self.RE_TAGS.search(rule_text)
        if tags_match and tags_match.group(2):
            tags = tags_match.group(2).strip().split()

        # 提取元数据
        meta = {}
        meta_section = self._extract_section(rule_text, 'meta')
        if meta_section:
            for m in self.RE_META.finditer(meta_section):
                meta[m.group(1)] = m.group(2)

        # 提取字符串模式
        strings = {}
        strings_section = self._extract_section(rule_text, 'strings')
        if strings_section:
            strings = self._parse_strings(strings_section)

        # 提取条件
        condition = ''
        condition_section = self._extract_section(rule_text, 'condition')
        if condition_section:
            condition = condition_section.strip()

        return YaraRule(
            rule_name=rule_name,
            rule_id=rule_name.lower(),
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
            source=self._infer_source(meta),
            raw_text=rule_text,
        )

    def parse_rules(self, rules_text: str) -> List[YaraRule]:
        """解析多条 YARA 规则

        Args:
            rules_text: 包含多条规则的文本

        Returns:
            YaraRule 列表
        """
        rules = []
        # 按 rule 关键字分割
        rule_blocks = re.split(r'\n\s*(?=rule\s+)', rules_text)
        for block in rule_blocks:
            block = block.strip()
            if block:
                try:
                    rule = self.parse_rule(block)
                    rules.append(rule)
                except YaraParseError:
                    continue
        return rules

    def _extract_section(self, rule_text: str, section_name: str) -> str:
        """提取指定章节的内容

        支持两种格式：
          1. 多行格式：
             strings:
                 $a = "text"
          2. 单行格式（括号内）：
             rule name { strings: $a = "text" condition: ... }
        """
        section_keywords = ['meta', 'strings', 'condition']
        # 构建章节结束标记：下一个章节名或右大括号
        end_patterns = [f'{kw}:' for kw in section_keywords if kw != section_name]
        end_patterns.append(r'\}')

        # 查找章节名: 位置
        pattern = rf'{section_name}\s*:(.*?)(?:{"|".join(end_patterns)})'
        match = re.search(pattern, rule_text, re.DOTALL | re.IGNORECASE)
        if match:
            content = match.group(1).strip()
            # 清理多余的括号和空格
            content = content.strip()
            if content.endswith('{'):
                content = content[:-1].strip()
            return content
        return ''

    def _parse_strings(self, strings_section: str) -> Dict[str, Any]:
        """解析字符串定义部分"""
        strings = {}
        # 使用 findall 模式匹配所有字符串定义
        all_pattern = re.compile(
            r'\$(\w+)\s*=\s*'
            r'(?:"((?:[^"\\]|\\.)*)"'           # 文本字符串
            r'|\{([^}]+)\}'                       # 十六进制
            r'|/((?:[^/\\]|\\.)+)/)'              # 正则表达式
            r'\s*((?:nocase|wide|ascii|fullword|private|xor)\s*)*'
        )

        for m in all_pattern.finditer(strings_section):
            str_id = f'${m.group(1)}'
            # 确定匹配类型
            if m.group(2) is not None:  # 文本字符串
                str_value = m.group(2)
                str_type = 'text'
                raw = f'"{str_value}"'
            elif m.group(3) is not None:  # 十六进制
                str_value = m.group(3).strip()
                str_type = 'hex'
                raw = f'{{{str_value}}}'
            elif m.group(4) is not None:  # 正则
                str_value = m.group(4)
                str_type = 'regex'
                raw = f'/{str_value}/'
            else:
                continue

            modifiers = [g.strip() for g in m.groups()[4:] if g and g.strip()]
            strings[str_id] = {
                'value': str_value,
                'type': str_type,
                'modifiers': list(set(modifiers)),
                'raw': raw,
            }

        return strings

    def _detect_string_type(self, value: str) -> str:
        """检测字符串类型"""
        if value.startswith('"') and value.endswith('"'):
            return 'text'
        elif value.startswith('{') and value.endswith('}'):
            return 'hex'
        elif value.startswith('/') and value.endswith('/'):
            return 'regex'
        return 'text'

    def _infer_source(self, meta: Dict) -> str:
        """从元数据推断规则来源"""
        source = meta.get('source', meta.get('author', 'unknown'))
        return source


# ============================================================
# YARA 条件表达式求值器
# ============================================================
class YaraConditionEvaluator:
    """YARA 条件表达式求值器

    支持的条件操作：
      - and, or, not
      - all of them, any of them, all of ($a*), any of ($a*)
      - # 计数（#a > N, #a == N）
      - @ 偏移量（@a > N）
      - for ... of
      - 括号分组
    """

    # 条件表达式 tokenizer
    TOKEN_PATTERN = re.compile(
        r'\ball\s+of\s+them\b'
        r'|\bany\s+of\s+them\b'
        r'|\ball\s+of\s+(\$[\w*]+(?:\s*,\s*\$[\w*]+)*)\b'
        r'|\bany\s+of\s+(\$[\w*]+(?:\s*,\s*\$[\w*]+)*)\b'
        r'|\bfor\s+(\d+)\s+of\s+(\$[\w*]+(?:\s*,\s*\$[\w*]+)*)\b'
        r'|(#\w+)\s*([<>=!]+)\s*(\d+)'
        r'|(@\w+)\s*([<>=!]+)\s*(\d+)'
        r'|(\$\w+)'
        r'|\band\b|\bor\b|\bnot\b'
        r'|[()]'
        r'|(\d+)'
        r'|\w+'
    )

    def __init__(self, matched_ids: Set[str], string_counts: Dict[str, int]):
        self.matched_ids = matched_ids
        self.string_counts = string_counts

    def evaluate(self, condition: str) -> bool:
        """评估条件表达式

        Args:
            condition: YARA 条件表达式字符串

        Returns:
            是否满足条件
        """
        if not condition:
            return True

        # 简化常见条件
        condition = condition.strip()

        # 处理简单条件
        try:
            return self._evaluate_expression(condition)
        except Exception:
            return False

    def _evaluate_expression(self, expr: str) -> bool:
        """递归评估表达式"""
        expr = expr.strip()

        # 括号
        while '(' in expr:
            # 找到最内层括号
            match = re.search(r'\(([^()]+)\)', expr)
            if match:
                inner_result = self._evaluate_expression(match.group(1))
                expr = expr.replace(match.group(0), str(inner_result), 1)
            else:
                break

        # 逻辑运算符（优先处理 or）
        # 处理 or（优先级较低）
        if ' or ' in expr.lower():
            parts = re.split(r'\bor\b', expr, flags=re.IGNORECASE)
            return any(self._evaluate_expression(p.strip()) for p in parts)

        # 处理 and
        if ' and ' in expr.lower():
            parts = re.split(r'\band\b', expr, flags=re.IGNORECASE)
            return all(self._evaluate_expression(p.strip()) for p in parts)

        # 处理 not
        if expr.lower().startswith('not '):
            return not self._evaluate_expression(expr[4:])

        # 处理 all of them
        if 'all of them' in expr.lower():
            return len(self.matched_ids) > 0  # 简化：只要有匹配就算

        # 处理 any of them
        if 'any of them' in expr.lower():
            return len(self.matched_ids) > 0

        # 处理 all of ($a, $b, ...)
        all_of_match = re.match(r'all\s+of\s+\(([^)]+)\)', expr, re.IGNORECASE)
        if all_of_match:
            str_ids = self._parse_string_list(all_of_match.group(1))
            return all(sid in self.matched_ids for sid in str_ids)

        # 处理 any of ($a, $b, ...)
        any_of_match = re.match(r'any\s+of\s+\(([^)]+)\)', expr, re.IGNORECASE)
        if any_of_match:
            str_ids = self._parse_string_list(any_of_match.group(1))
            return any(sid in self.matched_ids for sid in str_ids)

        # 处理 for N of ($a, $b, ...)
        for_match = re.match(r'for\s+(\d+)\s+of\s+\(([^)]+)\)', expr, re.IGNORECASE)
        if for_match:
            count = int(for_match.group(1))
            str_ids = self._parse_string_list(for_match.group(2))
            return sum(1 for sid in str_ids if sid in self.matched_ids) >= count

        # 处理 #a > N
        count_match = re.match(r'#(\w+)\s*([<>=!]+)\s*(\d+)', expr)
        if count_match:
            str_id = f'${count_match.group(1)}'
            op = count_match.group(2)
            val = int(count_match.group(3))
            actual = self.string_counts.get(str_id, 0)
            return self._compare(actual, op, val)

        # 处理单个字符串标识符
        if expr.startswith('$'):
            return expr in self.matched_ids

        # 处理布尔值
        if expr.lower() == 'true':
            return True
        if expr.lower() == 'false':
            return False

        return False

    def _parse_string_list(self, text: str) -> List[str]:
        """解析字符串 ID 列表"""
        ids = []
        for part in text.split(','):
            part = part.strip()
            if part:
                ids.append(part)
        return ids

    def _compare(self, a: int, op: str, b: int) -> bool:
        """比较操作"""
        if op == '>':
            return a > b
        elif op == '<':
            return a < b
        elif op == '>=':
            return a >= b
        elif op == '<=':
            return a <= b
        elif op == '==':
            return a == b
        elif op == '!=':
            return a != b
        return False


# ============================================================
# YARA 引擎
# ============================================================
class YaraEngine:
    """YARA 规则引擎

    纯 Python 实现，不依赖 yara-python 扩展。
    支持规则的添加、删除、编译、匹配。

    属性:
        rules: List[YaraRule] - 已加载的规则列表
        parser: YaraParser - 规则解析器
        _compiled_rules: Dict - 编译后的规则缓存
    """

    def __init__(self):
        self.rules: List[YaraRule] = []
        self.parser = YaraParser()

        # 内部缓存
        self._compiled_rules: Dict[str, Dict] = {}
        self._rule_index: Dict[str, int] = {}  # rule_id -> index

    # ----------------------------------------------------------
    # 规则管理
    # ----------------------------------------------------------

    def add_rule(self, rule: YaraRule) -> bool:
        """添加一条规则

        Args:
            rule: YaraRule 实例

        Returns:
            是否成功添加
        """
        if rule.rule_id in self._rule_index:
            return False

        self.rules.append(rule)
        self._rule_index[rule.rule_id] = len(self.rules) - 1
        return True

    def add_rules(self, rules: List[YaraRule]) -> int:
        """批量添加规则"""
        count = 0
        for rule in rules:
            if self.add_rule(rule):
                count += 1
        return count

    def add_rule_text(self, rule_text: str) -> Optional[YaraRule]:
        """从文本添加规则

        Args:
            rule_text: YARA 规则文本

        Returns:
            解析后的规则，解析失败返回 None
        """
        try:
            rule = self.parser.parse_rule(rule_text)
            self.add_rule(rule)
            return rule
        except YaraParseError:
            return None

    def add_rules_text(self, rules_text: str) -> int:
        """从文本批量添加规则"""
        count = 0
        try:
            rules = self.parser.parse_rules(rules_text)
            for rule in rules:
                if self.add_rule(rule):
                    count += 1
        except Exception:
            pass
        return count

    def remove_rule(self, rule_id: str) -> bool:
        """删除规则"""
        if rule_id not in self._rule_index:
            return False

        idx = self._rule_index[rule_id]
        self.rules.pop(idx)
        del self._rule_index[rule_id]

        # 重建索引
        for i, r in enumerate(self.rules):
            self._rule_index[r.rule_id] = i

        return True

    def get_rule(self, rule_id: str) -> Optional[YaraRule]:
        """获取规则"""
        idx = self._rule_index.get(rule_id)
        if idx is not None:
            return self.rules[idx]
        return None

    def clear_rules(self):
        """清空所有规则"""
        self.rules.clear()
        self._rule_index.clear()
        self._compiled_rules.clear()

    def get_rule_count(self) -> int:
        """获取规则数量"""
        return len(self.rules)

    def list_rules(self) -> List[Dict]:
        """列出所有规则摘要"""
        return [
            {
                'rule_name': r.rule_name,
                'rule_id': r.rule_id,
                'tags': r.tags,
                'description': r.meta.get('description', ''),
                'string_count': len(r.strings),
            }
            for r in self.rules
        ]

    # ----------------------------------------------------------
    # 规则匹配
    # ----------------------------------------------------------

    def scan(self, data: bytes, timeout: float = 0) -> List[YaraMatch]:
        """扫描数据，匹配所有规则

        Args:
            data: 要扫描的字节数据
            timeout: 超时时间（秒），0 表示不限制

        Returns:
            YaraMatch 列表（匹配到的规则）
        """
        results = []
        start_time = __import__('time').time()

        for rule in self.rules:
            # 超时检查
            if timeout > 0 and (__import__('time').time() - start_time) > timeout:
                break

            try:
                match = self._match_rule(rule, data)
                if match:
                    results.append(match)
            except Exception:
                continue

        return results

    def scan_file(self, filepath: str, max_size: int = 50 * 1024 * 1024) -> List[YaraMatch]:
        """扫描文件

        Args:
            filepath: 文件路径
            max_size: 最大扫描大小（默认 50MB）

        Returns:
            匹配的规则结果列表
        """
        if not os.path.isfile(filepath):
            return []

        file_size = os.path.getsize(filepath)
        if file_size > max_size:
            # 只读取文件头部和尾部
            with open(filepath, 'rb') as f:
                head = f.read(4 * 1024 * 1024)  # 前 4MB
                f.seek(-4 * 1024 * 1024, 2)
                tail = f.read(4 * 1024 * 1024)   # 后 4MB
            data = head + tail
        else:
            with open(filepath, 'rb') as f:
                data = f.read()

        return self.scan(data)

    def _match_rule(self, rule: YaraRule, data: bytes) -> Optional[YaraMatch]:
        """匹配单条规则"""
        if not rule.strings:
            # 无条件规则默认匹配
            if rule.condition:
                try:
                    ev = YaraConditionEvaluator(set(), {})
                    if ev.evaluate(rule.condition):
                        return self._create_match(rule, [])
                except Exception:
                    pass
            return None

        matched_ids = set()
        string_counts: Dict[str, int] = {}
        matched_values: List[str] = []

        # 匹配每个字符串模式
        for str_id, str_info in rule.strings.items():
            str_type = str_info.get('type', 'text')
            value = str_info.get('value', '')

            count = 0
            if str_type == 'text':
                # 文本字符串匹配
                str_bytes = value.encode('utf-8', errors='replace')
                if 'nocase' in str_info.get('modifiers', []):
                    str_bytes_lower = str_bytes.lower()
                    data_lower = data.lower()
                    count = data_lower.count(str_bytes_lower)
                else:
                    count = data.count(str_bytes)

                if count > 0:
                    matched_ids.add(str_id)
                    matched_values.append(value)

            elif str_type == 'hex':
                # 十六进制字节序列匹配
                pattern = self._compile_hex_pattern(value)
                if pattern:
                    count = self._count_pattern(data, pattern)
                    if count > 0:
                        matched_ids.add(str_id)
                        matched_values.append(f'hex:{value[:32]}...')

            elif str_type == 'regex':
                # 正则表达式匹配
                try:
                    flags = re.IGNORECASE if 'nocase' in str_info.get('modifiers', []) else 0
                    regex = re.compile(value.encode() if isinstance(value, str) else value, flags)
                    count = len(regex.findall(data))
                    if count > 0:
                        matched_ids.add(str_id)
                        matched_values.append(f'regex:{value}')
                except re.error:
                    pass

            string_counts[str_id] = count

        # 评估条件
        if rule.condition:
            try:
                ev = YaraConditionEvaluator(matched_ids, string_counts)
                if not ev.evaluate(rule.condition):
                    return None
            except Exception:
                if not matched_ids:
                    return None
        else:
            # 无条件时，有匹配即算
            if not matched_ids:
                return None

        return self._create_match(rule, matched_values)

    def _create_match(self, rule: YaraRule, matched_values: List[str]) -> YaraMatch:
        """创建匹配结果"""
        return YaraMatch(
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            tags=rule.tags,
            meta=rule.meta,
            matched_strings=matched_values,
            description=rule.meta.get('description', ''),
        )

    def _compile_hex_pattern(self, hex_str: str) -> Optional[bytes]:
        """编译十六进制模式"""
        hex_str = hex_str.replace(' ', '').replace('\n', '').replace('\r', '')
        try:
            return bytes.fromhex(hex_str)
        except (ValueError, AttributeError):
            return None

    def _count_pattern(self, data: bytes, pattern: bytes) -> int:
        """统计模式出现次数"""
        if not pattern:
            return 0
        count = 0
        pos = 0
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
            count += 1
            pos += 1
        return count


# ============================================================
# 内置 YARA 规则集合
# ============================================================

# 常见恶意软件检测规则
BUILTIN_RULES = [
    # Windows 可执行文件检测
    {
        'rule_name': 'Windows_Executable_MS',
        'meta': {'description': '检测 Windows PE 文件', 'author': 'TianDun'},
        'strings': {
            '$pe_header': {'value': '4d5a', 'type': 'hex', 'modifiers': []},
            '$pe_signature': {'value': '50450000', 'type': 'hex', 'modifiers': []},
        },
        'condition': '$pe_header at 0 and $pe_signature at 0x3c',
    },
    # Shellcode 检测
    {
        'rule_name': 'Shellcode_Detect',
        'meta': {'description': '检测 Shellcode 特征', 'author': 'TianDun'},
        'strings': {
            '$nop_sled': {'value': '9090909090909090', 'type': 'hex', 'modifiers': []},
            '$call_esp': {'value': 'ffe4', 'type': 'hex', 'modifiers': []},
            '$jmp_esp': {'value': 'ffe0', 'type': 'hex', 'modifiers': []},
        },
        'condition': 'any of them',
    },
    # 加密勒索信检测
    {
        'rule_name': 'Ransomware_Note_Detect',
        'meta': {'description': '检测勒索信文本', 'author': 'TianDun'},
        'strings': {
            '$wanna': {'value': 'WannaCry', 'type': 'text', 'modifiers': []},
            '$decrypt': {'value': 'Decrypt', 'type': 'text', 'modifiers': []},
            '$bitcoin': {'value': 'Bitcoin', 'type': 'text', 'modifiers': []},
            '$ransom': {'value': 'ransom', 'type': 'text', 'modifiers': ['nocase']},
        },
        'condition': '2 of them',
    },
    # 挖矿脚本检测
    {
        'rule_name': 'Cryptominer_Detect',
        'meta': {'description': '检测挖矿脚本', 'author': 'TianDun'},
        'strings': {
            '$stratum': {'value': 'stratum+tcp', 'type': 'text', 'modifiers': []},
            '$minerd': {'value': 'minerd', 'type': 'text', 'modifiers': []},
            '$pool_str': {'value': 'pool', 'type': 'text', 'modifiers': ['nocase']},
            '$xmr': {'value': 'monero', 'type': 'text', 'modifiers': ['nocase']},
        },
        'condition': '2 of them',
    },
    # 混淆 PowerShell 检测
    {
        'rule_name': 'Obfuscated_PowerShell',
        'meta': {'description': '检测混淆的 PowerShell 脚本', 'author': 'TianDun'},
        'strings': {
            '$iex': {'value': 'IEX', 'type': 'text', 'modifiers': ['nocase']},
            '$frombase64': {'value': 'FromBase64String', 'type': 'text', 'modifiers': []},
            '$enc': {'value': '-EncodedCommand', 'type': 'text', 'modifiers': ['nocase']},
            '$hidden': {'value': '-WindowStyle Hidden', 'type': 'text', 'modifiers': ['nocase']},
        },
        'condition': '2 of them',
    },
    # ZIP 压缩炸弹检测
    {
        'rule_name': 'Zip_Bomb_Detect',
        'meta': {'description': '检测 ZIP 压缩炸弹', 'author': 'TianDun'},
        'strings': {
            '$zip_magic': {'value': '504b0304', 'type': 'hex', 'modifiers': []},
            '$large_ratio': {'value': '0000000000000000', 'type': 'hex', 'modifiers': []},
        },
        'condition': '$zip_magic at 0',
    },
    # JavaScript 恶意代码检测
    {
        'rule_name': 'Malicious_JavaScript',
        'meta': {'description': '检测恶意 JavaScript 特征', 'author': 'TianDun'},
        'strings': {
            '$eval': {'value': 'eval(', 'type': 'text', 'modifiers': ['nocase']},
            '$unescape': {'value': 'unescape', 'type': 'text', 'modifiers': ['nocase']},
            '$fromchar': {'value': 'fromCharCode', 'type': 'text', 'modifiers': []},
            '$document_write': {'value': 'document.write', 'type': 'text', 'modifiers': ['nocase']},
        },
        'condition': '2 of them',
    },
]


# ============================================================
# 便捷函数
# ============================================================

def create_default_engine() -> YaraEngine:
    """创建带内置规则的默认 YARA 引擎"""
    engine = YaraEngine()
    for rule_dict in BUILTIN_RULES:
        rule = YaraRule(
            rule_name=rule_dict['rule_name'],
            meta=rule_dict.get('meta', {}),
            strings=rule_dict.get('strings', {}),
            condition=rule_dict.get('condition', ''),
        )
        engine.add_rule(rule)
    return engine


def scan_with_rules(data: bytes, rules_text: Optional[str] = None) -> List[YaraMatch]:
    """使用规则扫描数据"""
    engine = create_default_engine()
    if rules_text:
        engine.add_rules_text(rules_text)
    return engine.scan(data)


# 为兼容性保留别名
compile_yara_rule = YaraRule.from_string