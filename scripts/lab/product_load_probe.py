#!/usr/bin/env python3
"""在目标用户家目录里跑一次真实的产品加载验证，输出 JSON 证据。

用法（控制面与产品同机时）：
    python scripts/lab/product_load_probe.py --home /home/agentsec-lab --owner agentsec-lab

它做四件事，每件都有可核对的物理后果：
1. 造一个探针技能，install 到 <home>/.claude/skills/<name>，并 chown 给目标用户；
2. 起一次真实 claude 会话判定产品是否认识该技能（loaded=true/false/None）；
3. remove 掉，确认目录消失；
4. 卸载后再问一次，expect "Unknown command" 作为负面对照。

loaded 为 None 时不得读作已加载：那是"探测环境没给出结论"。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from services.managed_installer import tree_hash  # noqa: E402
from services.product_installer import ProductBinding, ProductInstaller  # noqa: E402

MANIFEST = (
    "---\nname: {name}\ndescription: ASGP admission load probe\n---\n\n"
    "When invoked, reply with exactly: ASGP_ADMISSION_E2E_OK\n"
)


def _refuse_developer_home(home: str) -> None:
    """拒绝在"运行用户自己的家目录"里启动产品 CLI。

    控制面主机往往也是开发主机，装上装着开发主力的 Agent。一个验证脚本顺手
    起一次会话，就可能写 transcript、消耗模型额度、改产品配置——这类影响和
    "验证"本身完全无关，却会真的打断别人的开发。要本机验证必须显式承认风险。
    """
    if os.environ.get("ASGP_ALLOW_LOCAL_PRODUCT_CLI") == "1":
        return
    current = Path.home().resolve()
    target = Path(home).resolve()
    if current == target:
        raise SystemExit(
            "拒绝在运行用户自己的家目录（%s）启动产品 CLI：这通常是开发主力机器。"
            "要本机验证，请显式设置 ASGP_ALLOW_LOCAL_PRODUCT_CLI=1 并自行确认不影响开发环境。"
            % current
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", required=True, help="目标用户家目录")
    parser.add_argument("--owner", default=None, help="安装内容的属主用户")
    parser.add_argument("--product", default="claude-code")
    parser.add_argument("--name", default="asgp-admission-demo")
    parser.add_argument("--work", default="/tmp/asgp-product-probe")
    args = parser.parse_args()
    _refuse_developer_home(args.home)

    work = Path(args.work)
    stage, backup = work / "staging", work / "backup"
    target = Path(args.home) / ".claude" / "skills" / args.name
    for path in (stage, backup, target):
        if path.exists():
            shutil.rmtree(path)
    stage.mkdir(parents=True)
    (stage / "SKILL.md").write_text(MANIFEST.format(name=args.name), encoding="utf-8")

    installer = ProductInstaller(
        [ProductBinding(args.product, args.home, args.owner)], backup_root=backup
    )
    digest = tree_hash(stage)
    evidence = {"product": args.product, "name": args.name, "target": str(target)}
    evidence["install"] = installer.install(args.product, args.name, stage, digest)
    evidence["target_exists_after_install"] = target.exists()
    evidence["verify"] = installer.verify(args.product, args.name, digest, probe=True)
    evidence["remove"] = installer.remove(args.product, args.name, evidence["install"]["rollback_ref"])
    evidence["target_exists_after_remove"] = target.exists()

    cli = Path(args.home) / ".local/npm/node_modules/.bin/claude"
    if cli.is_file() and not target.exists():
        proc = subprocess.run(
            [str(cli), "-p", f"/{args.name}", "--output-format", "text"],
            cwd="/tmp", capture_output=True, text=True, timeout=120,
            env={"HOME": args.home, "PATH": "/usr/local/bin:/usr/bin:/bin",
                 "LANG": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1"},
        )
        evidence["after_remove_output"] = ((proc.stdout or "") + (proc.stderr or "")).strip()[:200]
        evidence["after_remove_denied"] = "unknown command" in evidence["after_remove_output"].lower()
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
