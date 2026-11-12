"""只上传参数结构和摘要哈希，原始参数与工具输出留在产品进程中。"""
import hashlib
import json
import os
import re

MARKER = '[密钥已脱敏]'
PATTERN = re.compile(r'sk-(?:ant-)?[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|Bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY[^\n]*', re.I)
SENSITIVE = re.compile(r'key|token|password|secret|authorization', re.I)
# 只取路径形态的 token：绝对路径或 ~ 开头，避免把普通单词当路径。
PATH_TOKEN = re.compile(r'(?<![\w/.-])((?:~|/)[^\s\'"`;,|&()<>]{2,})')
HOME_PREFIX = re.compile(r'^/(?:home|Users)/[^/]+')
MAX_HINT_LENGTH = 160
MAX_HINTS = 4


def redact(value, secrets=None):
    if secrets is None:
        secrets = [v for k, v in os.environ.items() if SENSITIVE.search(k) and len(v) >= 8]
    if isinstance(value, dict):
        return {str(k): MARKER if SENSITIVE.search(str(k)) else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in sorted(secrets, key=len, reverse=True):
            value = value.replace(secret, MARKER)
        return PATTERN.sub(MARKER, value)
    return value


def resource_hints(params):
    """从参数里提取路径，供控制面做弱关联（只取路径，不取任何内容）。

    为什么要有：归因服务的 TEMPORAL_FEATURE 分支读 summary 里的资源提示，但端侧
    从来不产这个字段——那 0.35 分的弱关联在生产里永远不触发，等于死代码。

    为什么要限制：路径是元数据，但过长的路径会带出项目名、章节名之类的业务信息。
    家目录前缀归一成 ~，超长截断，且最多取前 4 条。
    """
    found: list[str] = []

    def walk(value):
        if isinstance(value, str):
            for match in PATH_TOKEN.finditer(value):
                candidate = HOME_PREFIX.sub('~', match.group(1).rstrip('/.,;:'))
                if len(candidate) > MAX_HINT_LENGTH:
                    candidate = candidate[:MAX_HINT_LENGTH] + '…'
                if candidate != '~' and candidate not in found:
                    found.append(candidate)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(params)
    return found[:MAX_HINTS]


def summarize(params):
    safe = redact(params)
    encoded = json.dumps(safe, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    # Values are deliberately excluded; even unrecognised credentials cannot escape.
    names = [k for k in sorted(safe) if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', k)] if isinstance(safe, dict) else []
    payload = {'parameter_names': names, 'values_omitted': True}
    hints = resource_hints(params)
    if hints:
        payload['resource_hints'] = hints
    summary = json.dumps(payload, sort_keys=True)
    return summary, hashlib.sha256(encoded).hexdigest()
