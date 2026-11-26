"""
DevPilot 3.0 Python Language Adapter
Integrates Python AST analysis, Ruff linter diagnostics, Bandit security scanning, and Pytest.
"""
from typing import List, Dict, Any, Optional, Tuple
import os
import ast
import shutil
import subprocess
import json
from src.analysis.languages.base import BaseLanguageAdapter
from src.analysis.ast_scanner import ASTCodeScanner
from src.blackboard.schema import CodeIssue


class PythonAdapter(BaseLanguageAdapter):
    """Specialized adapter for Python source inspection, security, and testing."""

    def __init__(self):
        super().__init__(
            language_name="Python",
            file_extensions=[".py", ".pyw"],
            manifest_files=["requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "environment.yml"]
        )
        self.ast_scanner = ASTCodeScanner()
        self._cached_toolchain: Optional[Dict[str, Any]] = None

    def check_toolchain(self) -> Dict[str, Any]:
        if self._cached_toolchain:
            return self._cached_toolchain

        tools: Dict[str, str] = {}
        py_bin = shutil.which("python") or shutil.which("python3")
        if py_bin:
            tools["python"] = py_bin

        ruff_bin = shutil.which("ruff")
        if ruff_bin:
            tools["ruff"] = ruff_bin

        bandit_bin = shutil.which("bandit")
        if bandit_bin:
            tools["bandit"] = bandit_bin

        pytest_bin = shutil.which("pytest")
        if pytest_bin:
            tools["pytest"] = pytest_bin

        status = "fully_supported" if ("python" in tools and "pytest" in tools) else "partially_supported"
        self._cached_toolchain = {
            "available": "python" in tools,
            "status": status,
            "tools": tools,
            "limitations": [] if status == "fully_supported" else ["Missing pytest or core python binary"]
        }
        return self._cached_toolchain

    def scan_file(self, file_path: str, repo_root: str) -> List[CodeIssue]:
        """Runs high-performance ASTCodeScanner in-memory."""
        issues = self.ast_scanner.scan_file(file_path, repo_root=repo_root)

        # Tag all issues with language = "Python"
        for issue in issues:
            if hasattr(issue, "language"):
                issue.language = "Python"

        return issues

    def verify_syntax(self, code: str, file_path: Optional[str] = None) -> Tuple[bool, List[str]]:
        try:
            ast.parse(code)
            compile(code, file_path or "<string>", "exec")
            return True, []
        except SyntaxError as e:
            return False, [f"SyntaxError at line {e.lineno}: {e.msg}"]
        except Exception as e:
            return False, [str(e)]

    def run_tests(
        self,
        repo_dir: str,
        test_target: Optional[str] = None,
        candidate_patch_diff: Optional[str] = None
    ) -> Dict[str, Any]:
        toolchain = self.check_toolchain()
        if "pytest" not in toolchain["tools"]:
            return {"testable": False, "reason": "pytest is not installed"}

        cmd = [toolchain["tools"]["pytest"], "-v", "--tb=short"]
        if test_target and os.path.exists(os.path.join(repo_dir, test_target)):
            cmd.append(test_target)

        try:
            res = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True, timeout=30)
            passed = res.returncode == 0
            return {
                "testable": True,
                "all_passed": passed,
                "exit_code": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr
            }
        except subprocess.TimeoutExpired:
            return {"testable": True, "all_passed": False, "exit_code": -1, "stdout": "", "stderr": "Test execution timed out (30s)"}
        except Exception as e:
            return {"testable": True, "all_passed": False, "exit_code": -1, "stdout": "", "stderr": str(e)}

