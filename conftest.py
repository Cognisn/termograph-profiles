"""Repository-root pytest configuration.

``tools/`` is a script directory, not an installable package (this
repository is a data/tooling repository, not a Python distribution) -- this
puts it on ``sys.path`` so ``tests/`` can ``import sign`` directly, the same
way the publish workflow runs ``python3 tools/sign.py`` from the repository
root.
"""

from __future__ import annotations

import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
