from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import questionary
from pydantic import ValidationError

from .export import export_profiles, jump_candidates
from .generate import generate
from .inventory import DEFAULT_INVENTORY, ROOT, discover, load, save, write_ansible_inventory
from .summary import render_summary
from .users import active_users, remove_users
from .wizard import create_inventory


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Configure MegaProxy HTTPS and SSH servers")
    result.add_argument("--inventory", "-i", help="Inventory configuration path")
    sub = result.add_subparsers(dest="command")
    sub.add_parser("inventory", help="Create a new inventory")
    sub.add_parser("validate", help="Validate inventory and Ansible syntax")
    sub.add_parser("check", help="Run the complete local/CI test suite")
    for name in ("plan", "apply", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--limit")
        command.add_argument("--tags")
    export = sub.add_parser("export")
    export.add_argument("--output", default=".generated/megaproxy-profiles.json")
    export.add_argument("--all-jumps", action="store_true")
    configs = sub.add_parser("configs", help="Generate all supported client configuration formats")
    configs.add_argument("--output-dir", default=".generated/configs")
    summary = sub.add_parser("summary", help="Print credentials for a password manager")
    summary.add_argument("login", nargs="?", help="Show only this login")
    sub.add_parser("remove-users", help="Remove one or more proxy user accounts")
    sub.add_parser("jumps", help="List all possible SSH jump chains")
    return result


def choose_inventory(explicit: str | None, force_create: bool = False) -> Path:
    path = discover(explicit)
    if force_create:
        target = Path(explicit).expanduser().resolve() if explicit else DEFAULT_INVENTORY
        create_inventory(target)
        return target
    if path:
        return path
    choice = questionary.select("No inventory was found", choices=["Create inventory.yml in the current directory", "Use another path"]).ask()
    if choice is None:
        raise KeyboardInterrupt
    if choice.startswith("Create"):
        create_inventory(DEFAULT_INVENTORY)
        return DEFAULT_INVENTORY
    selected = questionary.path("Inventory path").ask()
    if not selected:
        raise KeyboardInterrupt
    return Path(selected).expanduser().resolve()


def run_ansible(path: Path, playbook: str, *, check: bool = False, limit: str | None = None, tags: str | None = None) -> int:
    generated = write_ansible_inventory(path, load(path))
    command = ["ansible-playbook", "-i", str(generated), str(ROOT / "playbooks" / playbook)]
    if check:
        command += ["--check", "--diff"]
    if limit:
        command += ["--limit", limit]
    if tags:
        command += ["--tags", tags]
    return subprocess.run(command, cwd=ROOT).returncode


def finish_bootstrap(path: Path, inventory, limit: str | None) -> None:
    names = set(inventory.hosts)
    if limit:
        requested = {part.strip() for part in limit.split(",") if part.strip()}
        if not requested <= names:
            print(
                "Bootstrap completed, but inventory was not switched automatically because --limit uses an Ansible pattern.",
                file=sys.stderr,
            )
            return
        names = requested
    changed = []
    for name in names:
        admin = inventory.hosts[name].admin
        if admin.bootstrap_user:
            admin.bootstrap_user = None
            changed.append(name)
    if changed:
        save(path, inventory)
        print(f"Administrative connection activated for: {', '.join(sorted(changed))}")


def interactive_command() -> str:
    value = questionary.select("MegaProxy Server", choices=[questionary.Choice("Validate configuration", "validate"), questionary.Choice("Plan changes", "plan"), questionary.Choice("Apply configuration", "apply"), questionary.Choice("Verify configured servers (after apply)", "verify"), questionary.Choice("Remove proxy users", "remove-users"), questionary.Choice("Show credential summary", "summary"), questionary.Choice("Generate all client configuration formats", "configs"), questionary.Choice("Export MegaProxy profiles", "export"), questionary.Choice("List possible SSH jump chains", "jumps")]).ask()
    if value is None:
        raise KeyboardInterrupt
    return value


def validate_removals(candidates, selected):
    if not selected:
        return "Select at least one user"
    selected_keys = {(item.service, item.login) for item in selected}
    remaining = [item for item in candidates if (item.service, item.login) not in selected_keys]
    groups = {item.service for item in candidates}
    empty = sorted(service for service in groups if not any(item.service == service for item in remaining))
    if empty:
        return f"Keep at least one user or disable the service explicitly: {', '.join(empty)}"
    return True


def run_checks() -> int:
    checks = [
        ["ruff", "check", "."],
        ["pytest"],
        ["python", "-m", "compileall", "-q", "src"],
        ["ansible-playbook", "--syntax-check", "-i", "localhost,", "playbooks/site.yml"],
        ["ansible-playbook", "--syntax-check", "-i", "localhost,", "playbooks/verify.yml"],
    ]
    for command in checks:
        print(f"+ {' '.join(command)}", flush=True)
        result = subprocess.run(command, cwd=ROOT)
        if result.returncode:
            return result.returncode
    return 0


def main() -> None:
    args = parser().parse_args()
    try:
        if args.command == "check":
            raise SystemExit(run_checks())
        path = choose_inventory(args.inventory, args.command == "inventory")
        if args.command == "inventory":
            print(f"Created {path}")
            return
        command = args.command or interactive_command()
        inventory = load(path)
        if command == "remove-users":
            candidates = active_users(inventory)
            if not candidates:
                print("There are no proxy users to remove.")
                return
            selected = questionary.checkbox(
                "Proxy users to remove",
                choices=[questionary.Choice(item.label, item) for item in candidates],
                validate=lambda values: validate_removals(candidates, values),
            ).ask()
            if selected is None:
                raise KeyboardInterrupt
            remove_users(inventory, selected)
            save(path, inventory)
            print(f"Marked {len(selected)} user(s) for removal. Run 'mega-proxy apply' to update servers.")
            return
        if command == "summary":
            login = getattr(args, "login", None)
            output = render_summary(inventory, login)
            if not output:
                print(f"No credentials found for login: {login}", file=sys.stderr)
                raise SystemExit(2)
            print(output, end="")
            return
        if command == "jumps":
            print(json.dumps(jump_candidates(inventory), indent=2))
            return
        if command == "export":
            output = Path(getattr(args, "output", ".generated/megaproxy-profiles.json"))
            export_profiles(inventory, output, getattr(args, "all_jumps", False))
            print(f"Exported profiles to {output}")
            return
        if command == "configs":
            output_dir = Path(getattr(args, "output_dir", ".generated/configs")).resolve()
            changed = generate(path, output_dir)
            state = "updated" if changed else "already up to date"
            print(f"Client configurations are {state}: {output_dir}")
            return
        if command == "validate":
            generated = write_ansible_inventory(path, inventory)
            print(f"Inventory is valid: {len(inventory.hosts)} host(s)")
            code = subprocess.run(["ansible-inventory", "-i", str(generated), "--graph"], cwd=ROOT).returncode
            if code == 0:
                code = subprocess.run(["ansible-playbook", "-i", str(generated), str(ROOT / "playbooks" / "site.yml"), "--syntax-check"], cwd=ROOT).returncode
            raise SystemExit(code)
        limit = getattr(args, "limit", None)
        code = run_ansible(path, "verify.yml" if command == "verify" else "site.yml", check=command == "plan", limit=limit, tags=getattr(args, "tags", None))
        tags = getattr(args, "tags", None)
        applied_admin = tags is None or "admin" in {tag.strip() for tag in tags.split(",")}
        if code == 0 and command == "apply" and applied_admin:
            finish_bootstrap(path, inventory, limit)
        raise SystemExit(code)
    except (ValidationError, FileNotFoundError, ValueError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        raise SystemExit(130) from None
