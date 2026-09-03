from __future__ import annotations

import os
from pathlib import Path

from megaproxy_server.hooks import run_hooks


def test_runs_executable_hook_with_inventory_environment(tmp_path: Path) -> None:
    hooks = tmp_path / ".hooks"
    hooks.mkdir()
    output = tmp_path / "hook-output"
    hook = hooks / "post-config-change"
    hook.write_text(f"#!/bin/sh\nprintf '%s' \"$MEGAPROXY_INVENTORY\" > {output}\n")
    hook.chmod(0o700)
    inventory = tmp_path / "inventory.yml"
    generated = tmp_path / "inventory.ansible.yml"

    assert run_hooks(tmp_path, "post-config-change", inventory, generated) == 0
    assert output.read_text() == str(inventory.resolve())


def test_skips_non_executable_hook(tmp_path: Path) -> None:
    hooks = tmp_path / ".hooks"
    hooks.mkdir()
    hook = hooks / "post-config-change"
    hook.write_text("#!/bin/sh\nexit 42\n")
    hook.chmod(0o600)

    assert not os.access(hook, os.X_OK)
    assert run_hooks(tmp_path, "post-config-change", tmp_path / "one", tmp_path / "two") == 0
