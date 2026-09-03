from __future__ import annotations

import os
import subprocess
from pathlib import Path


def run_hooks(root: Path, event: str, inventory: Path, ansible_inventory: Path) -> int:
    hooks_dir = root / ".hooks"
    candidates = [hooks_dir / event]
    event_dir = hooks_dir / f"{event}.d"
    if event_dir.is_dir():
        candidates.extend(sorted(path for path in event_dir.iterdir() if path.is_file()))

    environment = os.environ.copy()
    environment.update(
        {
            "MEGAPROXY_EVENT": event,
            "MEGAPROXY_INVENTORY": str(inventory.resolve()),
            "MEGAPROXY_ANSIBLE_INVENTORY": str(ansible_inventory.resolve()),
            "MEGAPROXY_ROOT": str(root.resolve()),
        }
    )
    for hook in candidates:
        if not hook.is_file() or not os.access(hook, os.X_OK):
            continue
        print(f"Running hook: {hook}", flush=True)
        result = subprocess.run([str(hook)], cwd=root, env=environment)
        if result.returncode:
            return result.returncode
    return 0
