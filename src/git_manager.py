"""
DevPilot Git Repository Manager
Handles cloning, pulling, branch inspection, and test file discovery for remote Git repositories.
"""
import os
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional


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
        target_path = os.path.join(self.base_storage_dir, repo_name)

        # Handle existing directory
        if os.path.exists(target_path):
            if override_existing:
                shutil.rmtree(target_path, ignore_errors=True)
            else:
                # Try git pull or reuse
                git_dir = os.path.join(target_path, ".git")
                if os.path.exists(git_dir):
                    try:
                        subprocess.run(["git", "pull"], cwd=target_path, capture_output=True, timeout=30)
                    except Exception:
                        pass
                    meta = self.get_repo_metadata(target_path)
                    meta["status"] = "reused_existing"
                    meta["message"] = f"Using existing repository '{repo_name}' (pulled latest)."
                    return meta

        cmd = ["git", "clone", "--depth", "1"]
        if branch and branch.strip():
            cmd.extend(["-b", branch.strip()])
        cmd.extend([clone_url, target_path])

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
                cmd_full.extend([clone_url, target_path])
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

    def get_repo_metadata(self, repo_path: str) -> Dict[str, Any]:
        """Inspects cloned repo branch, commit hash, and discovers python test suites."""
        abs_path = os.path.abspath(repo_path)
        repo_name = os.path.basename(abs_path)

        if os.path.isfile(abs_path):
            return {
                "repo_name": repo_name,
                "repo_path": abs_path,
                "branch": "single_file",
                "commit_hash": "local",
                "total_python_files": 1,
                "test_files": []
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
        supported_exts = (".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")

        for root, dirs, files in os.walk(abs_path):
            if any(ign in root for ign in [".git", "__pycache__", ".venv", "venv", "node_modules", "target", "build", "dist"]):
                continue
            for f in files:
                lower_f = f.lower()
                if lower_f.endswith(supported_exts):
                    source_files_count += 1
                    rel = os.path.relpath(os.path.join(root, f), abs_path).replace("\\", "/")
                    if (
                        lower_f.startswith("test_") or
                        lower_f.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts", "test.java", "_test.cpp")) or
                        "tests/" in rel or
                        "test/" in rel
                    ):
                        test_files.append(rel)

        return {
            "repo_name": repo_name,
            "repo_path": abs_path,
            "branch": branch,
            "commit_hash": commit_hash,
            "total_python_files": source_files_count,  # backward-compatible key name
            "total_source_files": source_files_count,
            "test_files": sorted(test_files)
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

