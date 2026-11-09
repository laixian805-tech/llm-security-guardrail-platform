from __future__ import annotations

import os
from pathlib import Path


def agentsec_dir() -> Path:
    """Resolve the agentsec state directory at call time.

    ``AGENTSEC_HOME`` overrides the location for tests and non-standard
    installs; otherwise ``~/.agentsec`` is used. Resolution happens per call
    (not at import) so ``HOME``/``AGENTSEC_HOME`` changes are honored.
    """
    env = os.environ.get("AGENTSEC_HOME")
    if env:
        return Path(env)
    return Path.home() / ".agentsec"
