# -*- coding: utf-8 -*-
"""让 ``ratelimit_kit`` 可被导入。

限流/退避原语已经抽成独立库
`ratelimit-kit <https://github.com/zxyin-dev/ratelimit-kit>`_，
本项目（sign-lab）与 gdzy-collector 共用同一份实现 —— 修一处两边都受益。

正式使用请：

    pip install git+https://github.com/zxyin-dev/ratelimit-kit

这里保留一个"兄弟目录回退"：两个项目在本工作区同期开发，
改完库能立刻生效，不必每次重装。
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import ratelimit_kit  # noqa: F401
except ImportError:  # pragma: no cover - 仅在未安装时走这条
    _sibling = Path(__file__).resolve().parent.parent.parent / "ratelimit-kit"
    if _sibling.is_dir() and str(_sibling) not in sys.path:
        sys.path.insert(0, str(_sibling))
