"""只上传参数结构和摘要哈希，原始参数与工具输出留在产品进程中。"""
import hashlib
import json
import os
import re

MARKER = '[密钥已脱敏]'
PATTERN = re.compile(r'sk-(?:ant-)?[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|Bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY[^\n]*', re.I)
SENSITIVE = re.compile(r'key|token|password|secret|authorization', re.I)


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


def summarize(params):
    safe = redact(params)
    encoded = json.dumps(safe, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    # Values are deliberately excluded; even unrecognised credentials cannot escape.
    names = [k for k in sorted(safe) if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', k)] if isinstance(safe, dict) else []
    summary = json.dumps({'parameter_names': names, 'values_omitted': True}, sort_keys=True)
    return summary, hashlib.sha256(encoded).hexdigest()
