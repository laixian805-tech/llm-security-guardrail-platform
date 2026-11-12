#!/usr/bin/env python3
"""硬编码与重复真值扫描器。

来历：改一处 bug 之后如果只修那一处，同类问题会在下次换个位置复发。本项目
已经踩过两次同一类坑（测试把 ``schema_version == "8"`` 写死、``ADAPTER_VERSION``
定义了却没人用），所以把"同类查询"做成工具，不靠记性。

检查项：

- ``unused_constant``   版本类常量定义后没被引用（改了不生效）
- ``duplicated_version`` 同一版本字符串在非测试代码里出现多次（应提常量）
- ``schema_literal``    ``schema_version`` 与数字字面量比较（升版必红）

用法::

    python scripts/lab/scan_hardcoded.py            # 人类可读
    python scripts/lab/scan_hardcoded.py --json     # 机器可读，便于挂 CI

退出码：0 干净，1 有问题。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# 生产代码。scripts/ 下的实验室脚本会构造 fixture（如 detector_version），
# 那是被测数据不是真值来源，扫进来只会制造噪音。
CODE_DIRS = ("backend", "endpoint")
TEST_DIRS = ("tests",)
LAB_DIRS = ("scripts",)

CONSTANT = re.compile(r'^([A-Z][A-Z0-9_]*(?:VERSION|_VERSION))\s*=\s*["\']([^"\']+)["\']')
VERSION_LITERAL = re.compile(r'["\'](\d+\.\d+(?:\.\d+)?)["\']')
SCHEMA_LITERAL = re.compile(r'schema_version["\']?\s*[)=,].{0,40}?["\'](\d+)["\']')


def python_files(directories: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for name in directories:
        base = ROOT / name
        if not base.exists():
            continue
        files.extend(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)
    return files


def scan_unused_constants(files: list[Path]) -> list[dict]:
    """常量定义后全文只出现一次 = 只有定义行，说明没人用，改了也不生效。"""
    findings = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            match = CONSTANT.match(line.strip())
            if not match:
                continue
            name, value = match.group(1), match.group(2)
            references = len(re.findall(rf"\b{re.escape(name)}\b", text))
            if references <= 1:
                findings.append({
                    "kind": "unused_constant", "file": str(path.relative_to(ROOT)),
                    "line": line_no, "name": name, "value": value,
                    "hint": f"{name} = {value!r} 定义后未被引用，改动不会生效",
                })
    return findings


def scan_duplicated_versions(files: list[Path]) -> list[dict]:
    """同一版本字面量在非测试代码里出现多次：真值散落，迟早对不上。"""
    occurrences: dict[str, list[str]] = defaultdict(list)
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in VERSION_LITERAL.finditer(text):
            occurrences[match.group(1)].append(str(path.relative_to(ROOT)))
    findings = []
    for version, places in sorted(occurrences.items()):
        unique = sorted(set(places))
        if len(unique) > 1:
            findings.append({
                "kind": "duplicated_version", "value": version, "files": unique,
                "hint": f"版本 {version} 出现在 {len(unique)} 个文件里，应收敛到一个常量",
            })
    return findings


def scan_schema_literals(files: list[Path]) -> list[dict]:
    """schema_version 与字面量比较：升一版 schema 就要改测试，属于可预期的连锁。"""
    findings = []
    for path in files:
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if "INSERT INTO schema_meta" in line:
                # 迁移测试故意构造旧版本库，这里的数字是被测输入而不是断言，跳过。
                continue
            if "assert" not in line:
                # 只查断言行：docstring 里写"曾经把 schema_version 写成 8"是说明
                # 文字，把它当代码检出来属于扫描器自己误报。
                continue
            match = SCHEMA_LITERAL.search(line)
            if match and str(path.relative_to(ROOT)).startswith(TEST_DIRS):
                findings.append({
                    "kind": "schema_literal", "file": str(path.relative_to(ROOT)),
                    "line": line_no, "value": match.group(1),
                    "hint": "改比 SCHEMA_VERSION 常量，别写死数字",
                })
    return findings


def run() -> dict:
    code_files = python_files(CODE_DIRS)
    test_files = python_files(TEST_DIRS)
    findings = (scan_unused_constants(code_files)
                + scan_duplicated_versions(code_files)
                + scan_schema_literals(test_files))
    return {
        "scanned": {"code_files": len(code_files), "test_files": len(test_files)},
        "findings": findings,
        "ok": not findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        print(f"扫描 {result['scanned']['code_files']} 个代码文件、"
              f"{result['scanned']['test_files']} 个测试文件")
        if result["ok"]:
            print("未发现硬编码/重复真值问题")
        for item in result["findings"]:
            location = item.get("file") or ",".join(item.get("files", []))
            print(f"  [{item['kind']}] {location}")
            print(f"      {item['hint']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
