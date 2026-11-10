"""Pytest 配置：把 backend/ 加入 sys.path，使领域包可按目录名导入。"""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
