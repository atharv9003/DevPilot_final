"""
DevPilot 3.0 Base Language Adapter
Defines the standard interface that every language-specific inspection adapter must implement.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple
import os
import shutil
from src.blackboard.schema import CodeIssue


class BaseLanguageAdapter(ABC):
    """Abstract base class for all language-specific analysis adapters."""

    def __init__(self, language_name: str, file_extensions: List[str], manifest_files: List[str]):
        self.language_name = language_name
        self.file_extensions = [ext.lower() for ext in file_extensions]
        self.manifest_files = [m.lower() for m in manifest_files]

    @abstractmethod
    def check_toolchain(self) -> Dict[str, Any]:
        """
        Detects available toolchains (compilers, linters, runtimes) on host.
        Returns a dict:
        {
            "available": bool,
            "status": "fully_supported" | "partially_supported" | "unavailable",
            "tools": {"tool_name": "path_or_version", ...},
            "limitations": List[str]
        }
        """
        pass

    def matches_extension(self, file_path: str) -> bool:
        """Checks if file extension matches this language."""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.file_extensions

    def matches_manifest(self, file_name: str) -> bool:
        """Checks if manifest file belongs to this language."""
        return os.path.basename(file_name).lower() in self.manifest_files

    def detect_file(self, file_path: str, content: Optional[str] = None) -> bool:
        """Detects if a file belongs to this language based on extension, manifest, or shebang/content."""
        if self.matches_extension(file_path) or self.matches_manifest(file_path):
            return True
        if content:
            first_line = content.splitlines()[0] if content.splitlines() else ""
            if first_line.startswith("#!") and self.language_name.lower() in first_line.lower():
                return True
        return False

    @abstractmethod
    def scan_file(self, file_path: str, repo_root: str) -> List[CodeIssue]:
        """
        Executes language-specific static analysis, compilation diagnostics,
        security vulnerability checks, and runtime risk detection on the file.
        """
        pass

    @abstractmethod
    def verify_syntax(self, code: str, file_path: Optional[str] = None) -> Tuple[bool, List[str]]:
        """
        Verifies whether code is syntactically valid in this language.
        Returns (is_valid, list_of_error_strings).
        """
        pass

    @abstractmethod
    def run_tests(
        self,
        repo_dir: str,
        test_target: Optional[str] = None,
        candidate_patch_diff: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes language-specific test runner (pytest, node:test, jest, junit, etc.).
        Returns execution results. If no test runner is available, returns testable=False.
        """
        pass

