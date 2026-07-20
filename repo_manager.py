import os
import re
import subprocess
import sys
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
            branch_path = repo_path / f".git/refs/heads/{branch}"
            if not branch_path.exists():
                print(f"  checking out: {branch}")
                subprocess.run(
                    ["git", "checkout", branch],
                    cwd=str(repo_path),
                    capture_output=True, text=True, timeout=60,
                )

        return str(repo_path)

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
