"""
DevPilot 3.0 Multi-Language Manager
Coordinates language detection, toolchain health discovery, and dispatching across
Python, JavaScript, TypeScript, Java, and C/C++ analysis adapters.
"""
from typing import List, Dict, Any, Optional, Tuple
import os
from src.analysis.languages.base import BaseLanguageAdapter
from src.analysis.languages.python_adapter import PythonAdapter
from src.analysis.languages.javascript_adapter import JavaScriptAdapter
from src.analysis.languages.typescript_adapter import TypeScriptAdapter
from src.analysis.languages.java_adapter import JavaAdapter
from src.analysis.languages.cpp_adapter import CppAdapter
from src.blackboard.schema import CodeIssue


class MultiLanguageManager:
    """Central orchestrator for multi-language detection, inspection, and verification."""

    def __init__(self):
        self.adapters: Dict[str, BaseLanguageAdapter] = {
            "Python": PythonAdapter(),
            "JavaScript": JavaScriptAdapter(),
            "TypeScript": TypeScriptAdapter(),
            "Java": JavaAdapter(),
            "C/C++": CppAdapter()
        }

    def get_toolchain_summary(self) -> Dict[str, Any]:
        """Returns the operational readiness and toolchain availability for every supported language."""
        summary = {}
        for name, adapter in self.adapters.items():
            summary[name] = adapter.check_toolchain()
        return summary

    def detect_file_language(self, file_path: str, content: Optional[str] = None) -> Optional[str]:
        """Identifies language using extension, manifest filename, and deep content inspection."""
        basename = os.path.basename(file_path).lower()

        # TypeScript priority over JavaScript for .ts / .tsx / tsconfig
        if basename.endswith(".ts") or basename.endswith(".tsx"):
            return "TypeScript"
        if basename == "tsconfig.json":
            return "TypeScript"

        # Check manifests first
        for name, adapter in self.adapters.items():
            if adapter.matches_manifest(basename):
                return name

        # Check extensions
        for name, adapter in self.adapters.items():
            if adapter.matches_extension(file_path):
                return name

        # Read sample content from disk if not explicitly passed
        if content is None and os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(4096)
            except Exception:
                content = None

        # Deep content / shebang / keyword inspection
        if content:
            first_line = content.splitlines()[0] if content.splitlines() else ""
            if first_line.startswith("#!"):
                lower_first = first_line.lower()
                if "python" in lower_first:
                    return "Python"
                if "node" in lower_first or "deno" in lower_first:
                    return "JavaScript"
                if "bash" in lower_first or "sh" in lower_first:
                    return "Shell"

            lower_content = content.lower()

            # C / C++ content heuristics
            if any(sig in content for sig in ("#include <iostream>", "#include <vector>", "#include <stdio.h>", "#include <stdlib.h>", "using namespace std", "std::cout", "int main(")):
                return "C/C++"

            # Java content heuristics
            if any(sig in content for sig in ("package com.", "public class ", "public interface ", "import java.", "public static void main(String")):
                return "Java"

            # TypeScript content heuristics
            if any(sig in content for sig in ("interface ", "type ", "export default ", "import React from")):
                if any(ts_sig in content for ts_sig in (": string", ": number", ": boolean", ": any", "as const", "readonly ")):
                    return "TypeScript"
                return "JavaScript"

            # Python content heuristics
            if any(sig in content for sig in ("def ", "import ", "from ", "if __name__ ==")):
                if ":" in content and ("self" in content or "print(" in content or "class " in content):
                    return "Python"

        return None

    def inspect_project_structure(self, repo_path: str) -> Dict[str, Any]:
        """
        Inspects project directory or file, discovers manifests, determines languages,
        counts lines of code, and groups files by language.
        """
        files_by_lang: Dict[str, List[str]] = {name: [] for name in self.adapters.keys()}
        manifests_found: List[str] = []
        total_loc = 0
        all_scannable_files: List[str] = []

        clean_path = os.path.abspath(repo_path.strip(' "\''))

        if os.path.isfile(clean_path):
            all_scannable_files.append(clean_path)
            lang = self.detect_file_language(clean_path)
            if lang and lang in files_by_lang:
                files_by_lang[lang].append(clean_path)
            elif not lang:
                # Default to Python if unknown single file
                files_by_lang["Python"].append(clean_path)
            try:
                with open(clean_path, "r", encoding="utf-8", errors="replace") as f:
                    total_loc += len(f.readlines())
            except Exception:
                pass
        elif os.path.isdir(clean_path):
            for root, dirs, files in os.walk(clean_path):
                # Prune common non-source directories
                dirs[:] = [
                    d for d in dirs
                    if not d.startswith(".") and d not in (
                        "venv", ".venv", "node_modules", "__pycache__", "target", "build",
                        "dist", "out", ".idea", ".vscode", ".git"
                    )
                ]

                for f in files:
                    full_p = os.path.join(root, f)

                    # Check for recognized manifests
                    lower_f = f.lower()
                    if lower_f in (
                        "requirements.txt", "pyproject.toml", "package.json", "tsconfig.json",
                        "pom.xml", "build.gradle", "cmakelists.txt", "makefile"
                    ):
                        manifests_found.append(f)

                    lang = self.detect_file_language(full_p)
                    if lang and lang in files_by_lang:
                        files_by_lang[lang].append(full_p)
                        all_scannable_files.append(full_p)
                        try:
                            with open(full_p, "r", encoding="utf-8", errors="replace") as fh:
                                total_loc += len(fh.readlines())
                        except Exception:
                            pass

        detected_languages = [name for name, flist in files_by_lang.items() if len(flist) > 0]
        if not detected_languages:
            detected_languages = ["Python"]

        return {
            "total_files": len(all_scannable_files),
            "total_loc": total_loc,
            "languages_detected": detected_languages,
            "files_by_language": files_by_lang,
            "all_scannable_files": all_scannable_files,
            "manifests_found": sorted(list(set(manifests_found))),
            "toolchain_status": self.get_toolchain_summary()
        }

    def scan_all_files(self, files: List[str], repo_root: str) -> List[CodeIssue]:
        """Scans all files using their respective language adapters and merges findings."""
        all_issues: List[CodeIssue] = []

        for fpath in files:
            lang = self.detect_file_language(fpath)
            adapter = self.adapters.get(lang or "Python")
            if adapter:
                file_issues = adapter.scan_file(fpath, repo_root=repo_root)
                target_lang = getattr(adapter, "language_name", lang or "Python")
                for iss in file_issues:
                    iss.language = target_lang
                all_issues.extend(file_issues)

        return self.deduplicate_issues(all_issues)

    def scan_static_files(self, files: List[str], repo_root: str) -> List[CodeIssue]:
        """Extracts static (syntax, logic, quality) issues across all languages."""
        all_issues = self.scan_all_files(files, repo_root)
        return [iss for iss in all_issues if iss.category in ("syntax", "logic", "quality")]

    def scan_security_files(self, files: List[str], repo_root: str) -> List[CodeIssue]:
        """Extracts security issues across all languages."""
        all_issues = self.scan_all_files(files, repo_root)
        return [iss for iss in all_issues if iss.category == "security"]

    def scan_runtime_files(self, files: List[str], repo_root: str) -> List[CodeIssue]:
        """Extracts runtime and configuration issues across all languages."""
        all_issues = self.scan_all_files(files, repo_root)
        return [iss for iss in all_issues if iss.category in ("runtime", "config")]

    def deduplicate_issues(self, issues: List[CodeIssue]) -> List[CodeIssue]:
        """Deduplicates overlapping findings on identical file and line numbers."""
        seen = set()
        deduped: List[CodeIssue] = []
        for iss in issues:
            key = (iss.file_path, iss.line_number, iss.category, iss.title)
            if key not in seen:
                seen.add(key)
                deduped.append(iss)
        return deduped

    def verify_syntax_for_file(self, file_path: str, code: str) -> Tuple[bool, List[str]]:
        """Verifies syntax using the matching language adapter."""
        lang = self.detect_file_language(file_path)
        adapter = self.adapters.get(lang or "Python")
        if adapter:
            return adapter.verify_syntax(code, file_path=file_path)
        return True, []

    def run_tests_for_language(
        self,
        language: str,
        repo_dir: str,
        test_target: Optional[str] = None,
        candidate_patch_diff: Optional[str] = None
    ) -> Dict[str, Any]:
        """Executes test runner for given language adapter."""
        adapter = self.adapters.get(language)
        if adapter:
            return adapter.run_tests(repo_dir, test_target, candidate_patch_diff)
        return {"testable": False, "reason": f"No test runner configured for {language}"}
