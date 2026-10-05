import os
import subprocess
import sys
from pathlib import Path

from ruamel.yaml import YAML


def test_ssh_validation_notifies_reload(tmp_path):
    root = Path(__file__).resolve().parents[1]
    yaml = YAML(typ="safe")
    tasks, handlers, markers = [], [], []
    for role in ("admin", "ssh_proxy"):
        validation, reload = yaml.load((root / f"roles/{role}/handlers/main.yml").read_text())[:2]
        validation["ansible.builtin.command"] = "true"
        marker = tmp_path / role
        markers.append(marker)
        reload.pop("ansible.builtin.systemd_service")
        reload["ansible.builtin.copy"] = {"dest": str(marker), "content": "reloaded"}
        tasks.append({"ansible.builtin.debug": {"msg": role}, "changed_when": True,
                      "notify": validation["name"]})
        handlers.extend((validation, reload))
    playbook = tmp_path / "handlers.yml"
    with playbook.open("w") as stream:
        yaml.dump([{"hosts": "all", "gather_facts": False, "tasks": tasks,
                    "handlers": handlers}], stream)
    environment = os.environ.copy()
    environment["ANSIBLE_REMOTE_TEMP"] = str(tmp_path / "remote-tmp")
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment["PATH"]
    result = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)],
                            cwd=root, env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(marker.read_text() == "reloaded" for marker in markers)
