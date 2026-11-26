"""
DevPilot Git Repository Manager
Handles cloning, pulling, branch inspection, and test file discovery for remote Git repositories.
"""
import os
import hashlib
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple


class GitRepoManager:
    def __init__(self, base_storage_dir: str = "devpilot_repos"):
        self.base_storage_dir = os.path.abspath(base_storage_dir)
        os.makedirs(self.base_storage_dir, exist_ok=True)

    def _sanitize_url_for_name(self, git_url: str) -> str:
        clean = git_url.strip().rstrip("/")
        if clean.endswith(".git"):
            clean = clean[:-4]
        # Extract the last path element
        repo_name = clean.split("/")[-1].split("\\")[-1]
        repo_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", repo_name)
        return repo_name or "cloned_repo"

    def clone_repository(
        self,
        git_url: str,
        branch: Optional[str] = None,
        auth_token: Optional[str] = None,
        override_existing: bool = False
    ) -> Dict[str, Any]:
        """Clones a remote Git repository into the managed devpilot_repos workspace."""
        clean_url = git_url.strip().strip("'\"")
        if not clean_url:
            raise ValueError("Git URL cannot be empty.")

        # Embed auth token if provided for private repos
        clone_url = clean_url
        if auth_token and clean_url.startswith("https://"):
            clone_url = clean_url.replace("https://", f"https://{auth_token}@")

        repo_name = self._sanitize_url_for_name(clean_url)
        branch = branch.strip() if branch else ""
        source = self._remote_identity(clean_url)
        cache_key = hashlib.sha256(f"{source}\n{branch}".encode("utf-8")).hexdigest()[:16]
        target_path = os.path.join(self.base_storage_dir, f"{repo_name}-{cache_key}")
        legacy_path = os.path.join(self.base_storage_dir, repo_name)
        if not os.path.exists(target_path) and os.path.exists(os.path.join(legacy_path, ".git")):
            if self._matches_remote(legacy_path, source, branch):
                target_path = legacy_path

        # Handle existing directory
        if os.path.exists(target_path):
            if override_existing:
                shutil.rmtree(target_path, ignore_errors=True)
            else:
                git_dir = os.path.join(target_path, ".git")
                if os.path.exists(git_dir):
                    if not self._matches_remote(target_path, source, branch):
                        raise RuntimeError("Saved clone has a different origin or branch. Re-clone to refresh it.")
                    active_branch = self._active_branch(target_path)
                    command = ["git", "pull", "--ff-only"] if active_branch else ["git", "fetch", "--tags", "origin"]
                    result = subprocess.run(command, cwd=target_path, capture_output=True, timeout=30)
                    if result.returncode:
                        raise RuntimeError("The saved clone could not be refreshed from its origin.")
                    meta = self.get_repo_metadata(target_path)
                    meta["status"] = "reused_existing"
                    meta["message"] = f"Refreshed existing repository '{repo_name}'."
                    return meta

        cmd = ["git", "clone", "--depth", "1"]
        if branch and branch.strip():
            cmd.extend(["-b", branch.strip()])
        cmd.extend(["--", clone_url, target_path])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                # Fallback without depth if shallow clone fails on branch/tag
                cmd_full = ["git", "clone"]
                if branch and branch.strip():
                    cmd_full.extend(["-b", branch.strip()])
                cmd_full.extend(["--", clone_url, target_path])
                res2 = subprocess.run(cmd_full, capture_output=True, text=True, timeout=120)
                if res2.returncode != 0:
                    err = res2.stderr.strip() or result.stderr.strip()
                    # Sanitize any token from error output
                    if auth_token:
                        err = err.replace(auth_token, "***")
                    raise RuntimeError(f"Git clone failed: {err}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Git clone timed out after 120 seconds.")

        meta = self.get_repo_metadata(target_path)
        meta["status"] = "newly_cloned"
        meta["message"] = f"Successfully cloned '{repo_name}' into DevPilot workspace."
        return meta

    @staticmethod
    def _remote_identity(url: str) -> str:
        url = url.strip()
        if os.path.exists(url):
            return os.path.normcase(os.path.realpath(url))
        return re.sub(r"^(https?://)[^/]*@", r"\1", url).rstrip("/")

    @staticmethod
    def _active_branch(path: str) -> str:
        active = subprocess.run(
            ["git", "branch", "--show-current"], cwd=path, capture_output=True, text=True, timeout=5
        )
        return active.stdout.strip() if active.returncode == 0 else ""

    def _matches_remote(self, path: str, source: str, branch: str) -> bool:
        origin = subprocess.run(
            ["git", "remote", "get-url", "origin"], cwd=path, capture_output=True, text=True, timeout=5
        )
        if origin.returncode or self._remote_identity(origin.stdout) != source:
            return False
        active = self._active_branch(path)
        if not branch:
            default = subprocess.run(
                ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
                cwd=path, capture_output=True, text=True, timeout=5,
            )
            return default.returncode == 0 and default.stdout.strip() == f"origin/{active}"
        if active == branch:
            return True
        if not active:
            tag = subprocess.run(
                ["git", "tag", "--points-at", "HEAD"], cwd=path, capture_output=True, text=True, timeout=5
            )
            return tag.returncode == 0 and branch in tag.stdout.splitlines()
        return False

    def get_repo_metadata(self, repo_path: str) -> Dict[str, Any]:
        """Inspects cloned repo branch, commit hash, and discovers python test suites."""
        abs_path = os.path.abspath(repo_path)
        repo_name = os.path.basename(abs_path)

        LANG_MAP = {
            ".py": ("Python", "#3572A5"),
            ".pyw": ("Python", "#3572A5"),
            ".js": ("JavaScript", "#f1e05a"),
            ".jsx": ("JavaScript", "#f1e05a"),
            ".mjs": ("JavaScript", "#f1e05a"),
            ".cjs": ("JavaScript", "#f1e05a"),
            ".ts": ("TypeScript", "#3178c6"),
            ".tsx": ("TypeScript", "#3178c6"),
            ".html": ("HTML", "#e34c26"),
            ".htm": ("HTML", "#e34c26"),
            ".css": ("CSS", "#563d7c"),
            ".scss": ("SCSS", "#c6538c"),
            ".less": ("Less", "#1d365d"),
            ".ejs": ("EJS", "#a91e50"),
            ".java": ("Java", "#b07219"),
            ".c": ("C", "#555555"),
            ".h": ("C", "#555555"),
            ".cpp": ("C++", "#f34b7d"),
            ".cc": ("C++", "#f34b7d"),
            ".cxx": ("C++", "#f34b7d"),
            ".hpp": ("C++", "#f34b7d"),
            ".sh": ("Shell", "#89e051"),
            ".bash": ("Shell", "#89e051"),
            ".zsh": ("Shell", "#89e051"),
            ".json": ("JSON/Config", "#292929"),
            ".md": ("Markdown", "#083fa1"),
            ".rst": ("reStructuredText", "#141414"),
            ".yml": ("YAML", "#cb171e"),
            ".yaml": ("YAML", "#cb171e"),
            ".sql": ("SQL", "#e38c00"),
            ".go": ("Go", "#00ADD8"),
            ".rs": ("Rust", "#dea584"),
            ".php": ("PHP", "#4F5D95"),
            ".rb": ("Ruby", "#701516")
        }

        if os.path.isfile(abs_path):
            ext = os.path.splitext(abs_path)[1].lower()
            lang_info = LANG_MAP.get(ext, ("Code", "#3b82f6"))
            return {
                "repo_name": repo_name,
                "repo_path": abs_path,
                "branch": "single_file",
                "commit_hash": "local",
                "total_python_files": 1,
                "test_files": [],
                "languages": [{"lang": lang_info[0], "pct": 100.0, "color": lang_info[1]}]
            }

        # Get active branch
        branch = "unknown"
        commit_hash = "unknown"
        try:
            res_b = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=abs_path, capture_output=True, text=True, timeout=5
            )
            if res_b.returncode == 0:
                branch = res_b.stdout.strip()

            res_c = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=abs_path, capture_output=True, text=True, timeout=5
            )
            if res_c.returncode == 0:
                commit_hash = res_c.stdout.strip()[:8]
        except Exception:
            pass

        # Discover source files & test suites across Python, JavaScript, TypeScript, Java, and C/C++
        test_files: List[str] = []
        source_files_count = 0
        lang_bytes: Dict[str, Tuple[int, str]] = {}
        total_lang_bytes = 0
        supported_exts = tuple(LANG_MAP.keys())

        for root, dirs, files in os.walk(abs_path):
            if any(ign in root for ign in [".git", "__pycache__", ".venv", "venv", "node_modules", "target", "build", "dist"]):
                continue
            for f in files:
                lower_f = f.lower()
                full_f = os.path.join(root, f)
                try:
                    f_size = os.path.getsize(full_f)
                except Exception:
                    f_size = 0

                lang_found = None
                color_found = "#3b82f6"

                if lower_f == "dockerfile":
                    lang_found = "Dockerfile"
                    color_found = "#384d54"
                elif lower_f == "makefile":
                    lang_found = "Makefile"
                    color_found = "#427819"
                else:
                    for ext, (l_name, l_color) in LANG_MAP.items():
                        if lower_f.endswith(ext):
                            lang_found = l_name
                            color_found = l_color
                            break

                if lang_found and f_size > 0:
                    prev_bytes, _ = lang_bytes.get(lang_found, (0, color_found))
                    lang_bytes[lang_found] = (prev_bytes + f_size, color_found)
                    total_lang_bytes += f_size

                if lower_f.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")):
                    source_files_count += 1
                    rel = os.path.relpath(full_f, abs_path).replace("\\", "/")
                    if (
                        lower_f.startswith("test_") or
                        lower_f.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts", "test.java", "_test.cpp")) or
                        "tests/" in rel or
                        "test/" in rel
                    ):
                        test_files.append(rel)

        languages_list = []
        if total_lang_bytes > 0:
            for l_name, (b_count, color) in lang_bytes.items():
                pct = round((b_count / total_lang_bytes) * 100, 1)
                if pct >= 0.1:
                    languages_list.append({"lang": l_name, "pct": pct, "color": color})
            languages_list.sort(key=lambda x: x["pct"], reverse=True)
        if not languages_list:
            languages_list = [{"lang": "Code", "pct": 100.0, "color": "#3b82f6"}]

        return {
            "repo_name": repo_name,
            "repo_path": abs_path,
            "branch": branch,
            "commit_hash": commit_hash,
            "total_python_files": source_files_count,  # backward-compatible key name
            "total_source_files": source_files_count,
            "test_files": sorted(test_files),
            "languages": languages_list
        }

    def list_saved_repositories(self) -> List[Dict[str, Any]]:
        """Lists all Git repositories currently saved under devpilot_repos."""
        if not os.path.exists(self.base_storage_dir):
            return []

        repos = []
        for item in os.listdir(self.base_storage_dir):
            full = os.path.join(self.base_storage_dir, item)
            if os.path.isdir(full) and os.path.exists(os.path.join(full, ".git")):
                try:
                    meta = self.get_repo_metadata(full)
                    repos.append(meta)
                except Exception:
                    pass
        return repos


git_manager = GitRepoManager()

