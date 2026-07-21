import os
import subprocess
from pathlib import Path

import yaml


class RepoManager:
    def __init__(self, config_path: str = "config.yaml", clone_dir: str = ".repos"):
        self.config_path = Path(config_path)
        self.clone_dir = Path(clone_dir)
        self.tokens: dict[str, str] = {}
        self.repo_configs: dict[str, dict] = {}

    def load_config(self) -> None:
        if not self.config_path.exists():
            return

        with open(self.config_path) as f:
            cfg = yaml.safe_load(f) or {}

        self.tokens = cfg.get("git", {}).get("tokens", {})

        for entry in cfg.get("repositories", []):
            url = entry.get("url", "")
            if url:
                self.repo_configs[url.rstrip("/")] = {
                    "branch": entry.get("branch"),
                    "scan_mode": entry.get("scan_mode", "remote"),
                    "commit": entry.get("commit", ""),
                }

    def get_config(self, repo_url: str) -> dict:
        return self.repo_configs.get(repo_url.rstrip("/"), {})

    def authenticated_url(self, repo_url: str) -> str:
        for host, token in self.tokens.items():
            if token and host in repo_url:
                return repo_url.replace(f"https://{host}", f"https://{token}@{host}")
        return repo_url

    def clone_or_pull(self, repo_url: str, branch: str | None = None) -> str:
        repo_name = repo_url.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        repo_path = self.clone_dir / repo_name
        auth_url = self.authenticated_url(repo_url)

        if repo_path.exists():
            print(f"  updating: {repo_name}")
            subprocess.run(
                ["git", "fetch", "--all"],
                cwd=str(repo_path),
                capture_output=True, text=True, timeout=120,
            )
            subprocess.run(
                ["git", "reset", "--hard", f"origin/{branch}"] if branch
                else ["git", "pull"],
                cwd=str(repo_path),
                capture_output=True, text=True, timeout=120,
            )
        else:
            print(f"  cloning: {repo_name}")
            subprocess.run(
                ["git", "clone", "--depth", "1", auth_url, str(repo_path)],
                capture_output=True, text=True, timeout=300,
            )

        if branch:
            subprocess.run(
                ["git", "checkout", branch],
                cwd=str(repo_path),
                capture_output=True, text=True, timeout=60,
            )

        return str(repo_path)

    def fetch_latest_commit(self, repo_url: str, branch: str | None = None) -> str | None:
        ref = f"refs/heads/{branch}" if branch else "HEAD"
        auth_url = self.authenticated_url(repo_url)
        try:
            proc = subprocess.run(
                ["git", "ls-remote", auth_url, ref],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return None
            parts = proc.stdout.strip().split()
            return parts[0] if parts else None
        except Exception:
            return None

    def update_config_with_commits(self, repo_urls: list[str]) -> None:
        self.load_config()
        if not self.config_path.exists():
            return

        with open(self.config_path) as f:
            cfg = yaml.safe_load(f) or {}

        updated = False
        for entry in cfg.get("repositories", []):
            url = entry.get("url", "")
            if url and url.rstrip("/") in [u.rstrip("/") for u in repo_urls]:
                branch = entry.get("branch")
                print(f"  fetching latest commit for {url}")
                if branch:
                    print(f"    branch: {branch}")
                commit = self.fetch_latest_commit(url, branch)
                if commit:
                    old = entry.get("commit", "")
                    entry["commit"] = commit
                    updated = True
                    status = "same" if old == commit else "updated"
                    print(f"    commit: {commit} ({status})")
                else:
                    print(f"    commit: unable to fetch")

        if updated:
            with open(self.config_path, "w") as f:
                yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
            print(f"  config updated: {self.config_path}")

    def list_remote_branches(self, repo_url: str) -> list[str]:
        """Fetch all remote branch names via git ls-remote --heads."""
        auth_url = self.authenticated_url(repo_url)
        try:
            proc = subprocess.run(
                ["git", "ls-remote", "--heads", auth_url],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return []
            branches = []
            for line in proc.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                # format: <sha> refs/heads/<name>
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1].startswith("refs/heads/"):
                    branches.append(parts[1][len("refs/heads/"):])
            return branches
        except Exception:
            return []

    def interactive_select_branches(self, repo_urls: list[str]) -> None:
        """Show interactive numbered menu to pick a branch for each repo."""
        self.load_config()
        if not self.config_path.exists():
            print(f"error: config file not found: {self.config_path}")
            return

        with open(self.config_path) as f:
            cfg = yaml.safe_load(f) or {}

        changed = False
        for url in repo_urls:
            repo_name = url.rstrip("/").split("/")[-1]
            print(f"\n=== {repo_name} === ({url})")

            branches = self.list_remote_branches(url)
            if not branches:
                print("  no branches found (skipping)")
                continue

            # show current branch
            current = None
            for entry in cfg.get("repositories", []):
                if entry.get("url", "").rstrip("/") == url.rstrip("/"):
                    current = entry.get("branch")
                    break

            if current:
                print(f"  current branch: {current}")

            print("  available branches:")
            for i, b in enumerate(branches, 1):
                marker = "  <-- current" if b == current else ""
                print(f"    {i:3d}. {b}{marker}")

            choice = input(f"  select branch [1-{len(branches)}, Enter=keep current]: ").strip()
            if not choice:
                print(f"  keeping: {current or 'default'}")
                continue

            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(branches):
                    print(f"  invalid choice (skipping)")
                    continue
                selected = branches[idx]
                print(f"  selected: {selected}")

                # update config
                for entry in cfg.get("repositories", []):
                    if entry.get("url", "").rstrip("/") == url.rstrip("/"):
                        entry["branch"] = selected
                        changed = True
                        break
                else:
                    # repo not in config yet — add it
                    cfg.setdefault("repositories", []).append({
                        "url": url,
                        "branch": selected,
                        "scan_mode": "local",
                    })
                    changed = True

            except ValueError:
                print("  invalid input (skipping)")
                continue

        if changed:
            with open(self.config_path, "w") as f:
                yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
            print(f"\nconfig updated: {self.config_path}")

    def prepare_repos(self, repo_urls: list[str]) -> dict[str, str]:
        self.load_config()
        self.clone_dir.mkdir(parents=True, exist_ok=True)

        mapping: dict[str, str] = {}
        for url in repo_urls:
            config = self.get_config(url)
            scan_mode = config.get("scan_mode", "remote")

            if scan_mode == "local":
                branch = config.get("branch")
                local_path = self.clone_or_pull(url, branch)
                mapping[url] = local_path
                print(f"  -> local path: {local_path}")
            else:
                mapping[url] = url

        return mapping
