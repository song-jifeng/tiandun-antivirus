#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天盾 Antivirus - 数据索引与搜索工具
"""
import os
import sys
import json
import time
import re
import hashlib
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FileIndexer:
    """文件索引器"""

    def __init__(self):
        self._index = {}
        self._tags = defaultdict(set)
        self._full_text = {}

    def index_file(self, filepath: str) -> Dict:
        stat = os.stat(filepath)
        info = {
            'path': os.path.abspath(filepath),
            'name': os.path.basename(filepath),
            'ext': os.path.splitext(filepath)[1].lower(),
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'tags': [],
        }
        with open(filepath, 'rb') as f:
            data = f.read(65536)
        info['md5'] = hashlib.md5(data).hexdigest()
        info['sha256'] = hashlib.sha256(data).hexdigest()
        self._index[filepath] = info
        return info

    def index_directory(self, directory: str, recursive: bool = True) -> int:
        count = 0
        if recursive:
            for root, _, files in os.walk(directory):
                for f in files:
                    try:
                        self.index_file(os.path.join(root, f))
                        count += 1
                    except Exception:
                        pass
        else:
            for f in os.listdir(directory):
                fpath = os.path.join(directory, f)
                if os.path.isfile(fpath):
                    try:
                        self.index_file(fpath)
                        count += 1
                    except Exception:
                        pass
        return count

    def search(self, query: str, field: str = 'name') -> List[Dict]:
        query = query.lower()
        results = []
        for path, info in self._index.items():
            if field == 'name' and query in info['name'].lower():
                results.append(info)
            elif field == 'ext' and query == info['ext']:
                results.append(info)
            elif field == 'path' and query in path.lower():
                results.append(info)
            elif field == 'tag' and query in [t.lower() for t in info.get('tags', [])]:
                results.append(info)
        return results

    def find_duplicates(self) -> Dict[str, List[str]]:
        by_hash = defaultdict(list)
        for path, info in self._index.items():
            by_hash[info['md5']].append(path)
        return {h: paths for h, paths in by_hash.items() if len(paths) > 1}

    def get_stats(self) -> Dict:
        return {
            'total_files': len(self._index),
            'total_size': sum(i['size'] for i in self._index.values()),
            'by_ext': defaultdict(int, {i['ext']: 1 for i in self._index.values()}),
        }


class FullTextSearch:
    """全文搜索"""

    def __init__(self):
        self._inverted_index = defaultdict(set)
        self._documents = {}

    def index_document(self, doc_id: str, content: str):
        self._documents[doc_id] = content
        words = set(re.findall(r'\w+', content.lower()))
        for word in words:
            self._inverted_index[word].add(doc_id)

    def index_file(self, filepath: str):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            self.index_document(filepath, content)
        except Exception:
            pass

    def search(self, query: str) -> List[str]:
        words = re.findall(r'\w+', query.lower())
        if not words:
            return []
        results = self._inverted_index.get(words[0], set())
        for word in words[1:]:
            results &= self._inverted_index.get(word, set())
        return sorted(results)[:100]

    def remove_document(self, doc_id: str):
        self._documents.pop(doc_id, None)
        for word, docs in self._inverted_index.items():
            docs.discard(doc_id)


class MetadataIndex:
    """元数据索引"""

    def __init__(self):
        self._index = {}

    def add(self, key: str, metadata: Dict):
        self._index[key] = {
            **metadata,
            'indexed_at': time.time(),
        }

    def get(self, key: str) -> Optional[Dict]:
        return self._index.get(key)

    def search(self, **kwargs) -> List[Dict]:
        results = []
        for key, metadata in self._index.items():
            match = True
            for field, value in kwargs.items():
                if field not in metadata:
                    match = False
                    break
                if isinstance(value, str) and value.lower() not in str(metadata[field]).lower():
                    match = False
                    break
                elif metadata[field] != value:
                    match = False
                    break
            if match:
                results.append({'key': key, **metadata})
        return results

    def get_by_tag(self, tag: str) -> List[Dict]:
        return [{'key': k, **v} for k, v in self._index.items()
                if tag in v.get('tags', [])]

    def get_stats(self) -> Dict:
        return {
            'total_entries': len(self._index),
            'by_type': defaultdict(int).update(
                {v.get('type', 'unknown'): 1 for v in self._index.values()}
            ),
        }


class SearchEngine:
    """搜索引擎"""

    def __init__(self):
        self._documents = {}
        self._inverted_index = defaultdict(set)
        self._stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on',
                           'at', 'to', 'for', 'of', 'by', 'with', 'is', 'are',
                           'was', 'were', 'be', 'been', 'being', 'have', 'has',
                           'had', 'do', 'does', 'did', 'will', 'would', 'can',
                           'could', 'may', 'might', 'shall', 'should', 'not'}

    def add_document(self, doc_id: str, content: str):
        self._documents[doc_id] = content
        words = self._tokenize(content)
        for word in words:
            self._inverted_index[word].add(doc_id)

    def _tokenize(self, text: str) -> Set[str]:
        words = re.findall(r'\w+', text.lower())
        return {w for w in words if w not in self._stop_words and len(w) >= 2}

    def search(self, query: str, max_results: int = 20) -> List[Dict]:
        query_words = self._tokenize(query)
        if not query_words:
            return []
        results = self._inverted_index.get(query_words[0], set()).copy()
        for word in query_words[1:]:
            results &= self._inverted_index.get(word, set())
        scored = []
        for doc_id in results:
            score = self._calculate_score(doc_id, query_words)
            scored.append((score, doc_id))
        scored.sort(reverse=True)
        return [{'id': doc_id, 'score': score}
                for score, doc_id in scored[:max_results]]

    def _calculate_score(self, doc_id: str, query_words: Set[str]) -> float:
        content = self._documents.get(doc_id, '')
        if not content:
            return 0.0
        content_lower = content.lower()
        score = 0.0
        for word in query_words:
            count = content_lower.count(word)
            score += count * (1.0 / len(content.split()))
        return score

    def remove_document(self, doc_id: str):
        self._documents.pop(doc_id, None)
        for word, docs in self._inverted_index.items():
            docs.discard(doc_id)


class DataIndexer:
    """数据索引器"""

    def __init__(self):
        self._indices = {}

    def create_index(self, name: str, key_field: str):
        self._indices[name] = {
            'key_field': key_field,
            'data': {},
            'index': defaultdict(list),
        }

    def add_record(self, index_name: str, record: Dict):
        idx = self._indices.get(index_name)
        if not idx:
            return
        key = record.get(idx['key_field'])
        if key:
            idx['data'][key] = record
            for field, value in record.items():
                if isinstance(value, (str, int, float)):
                    idx['index'][f'{field}:{value}'].append(key)

    def search(self, index_name: str, field: str, value: Any) -> List[Dict]:
        idx = self._indices.get(index_name)
        if not idx:
            return []
        keys = idx['index'].get(f'{field}:{value}', [])
        return [idx['data'][k] for k in keys if k in idx['data']]

    def get_stats(self) -> Dict:
        return {name: {'total': len(idx['data'])} for name, idx in self._indices.items()}


class RegexIndex:
    """正则表达式索引"""

    def __init__(self):
        self._patterns = {}

    def add_pattern(self, name: str, pattern: str):
        self._patterns[name] = re.compile(pattern)

    def search(self, text: str) -> Dict[str, List[str]]:
        results = {}
        for name, pattern in self._patterns.items():
            matches = pattern.findall(text)
            if matches:
                results[name] = matches[:20]
        return results

    def get_patterns(self) -> List[str]:
        return list(self._patterns.keys())


class FuzzySearch:
    """模糊搜索"""

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return FuzzySearch.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @staticmethod
    def search(query: str, candidates: List[str], max_distance: int = 2) -> List[tuple]:
        results = []
        for candidate in candidates:
            distance = FuzzySearch.levenshtein_distance(query.lower(), candidate.lower())
            if distance <= max_distance:
                results.append((candidate, distance))
        return sorted(results, key=lambda x: x[1])


class TagIndex:
    """标签索引"""

    def __init__(self):
        self._tags = defaultdict(set)
        self._items = {}

    def add(self, item_id: str, tags: List[str], data: Any = None):
        self._items[item_id] = data
        for tag in tags:
            self._tags[tag.lower()].add(item_id)

    def remove(self, item_id: str):
        self._items.pop(item_id, None)
        for tag, items in self._tags.items():
            items.discard(item_id)

    def search_by_tag(self, tag: str) -> List[Dict]:
        item_ids = self._tags.get(tag.lower(), set())
        return [{'id': iid, 'data': self._items.get(iid)} for iid in item_ids]

    def search_by_tags(self, tags: List[str], match_all: bool = True) -> List[Dict]:
        tags_lower = [t.lower() for t in tags]
        if match_all:
            item_ids = set.intersection(*[self._tags.get(t, set()) for t in tags_lower])
        else:
            item_ids = set.union(*[self._tags.get(t, set()) for t in tags_lower])
        return [{'id': iid, 'data': self._items.get(iid)} for iid in item_ids]

    def get_all_tags(self) -> List[str]:
        return sorted(self._tags.keys())

    def get_stats(self) -> Dict:
        return {
            'total_items': len(self._items),
            'total_tags': len(self._tags),
        }


class DateRangeIndex:
    """日期范围索引"""

    def __init__(self):
        self._items = []

    def add(self, item: Dict, date_key: str = 'timestamp'):
        self._items.append(item)
        self._items.sort(key=lambda x: x.get(date_key, 0))

    def search(self, start: float, end: float) -> List[Dict]:
        return [i for i in self._items if start <= i.get('timestamp', 0) <= end]

    def get_range(self) -> tuple:
        if not self._items:
            return (0, 0)
        return (self._items[0].get('timestamp', 0),
                self._items[-1].get('timestamp', 0))


class NumericIndex:
    """数值索引"""

    def __init__(self):
        self._values = {}

    def add(self, key: str, value: float):
        self._values[key] = value

    def get_range(self, min_val: float, max_val: float) -> List[str]:
        return [k for k, v in self._values.items() if min_val <= v <= max_val]

    def get_top(self, n: int = 10) -> List[tuple]:
        return sorted(self._values.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_bottom(self, n: int = 10) -> List[tuple]:
        return sorted(self._values.items(), key=lambda x: x[1])[:n]

    def get_stats(self) -> Dict:
        if not self._values:
            return {}
        vals = list(self._values.values())
        return {
            'count': len(vals),
            'min': min(vals),
            'max': max(vals),
            'avg': sum(vals) / len(vals),
        }