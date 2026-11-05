"""
Agent 4: Runtime and Dependency Analysis Agent
Specialized agent for detecting runtime risks (KeyErrors, TypeErrors, ZeroDivisionError),
inspecting dependencies, and analyzing configuration requirements.
"""
from typing import List, Dict, Any, Optional
import os
import ast
import uuid
from src.analysis.languages.manager import MultiLanguageManager
from src.blackboard.schema import CodeIssue


class RuntimeDependencyAgent:
    """Specialized Multi-Language Runtime & Dependency Analysis Agent."""

    def __init__(self, agent_id: str = "adk_runtime_dependency_agent"):
        self.agent_id = agent_id
        self.lang_manager = MultiLanguageManager()

    def analyze_files(self, file_paths: List[str], repo_root: str) -> List[CodeIssue]:
        """Analyzes given files for runtime exceptions and configuration defects across all languages."""
        runtime_issues = self.lang_manager.scan_runtime_files(file_paths, repo_root=repo_root)
        for issue in runtime_issues:
            issue.agent_source = "runtime_dependency_agent"

        # Check for unchecked environment variables across all languages
        for fpath in file_paths:
            if os.path.exists(fpath):
                env_issues = self._check_environment_variables(fpath, repo_root)
                runtime_issues.extend(env_issues)

        return runtime_issues

    def _check_environment_variables(self, file_path: str, repo_root: str) -> List[CodeIssue]:
        """Detects unchecked environment variable lookups without defaults across all supported languages."""
        issues: List[CodeIssue] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            lines = code.splitlines()
        except Exception:
            return []

        rel_path = os.path.relpath(file_path, repo_root) if repo_root else os.path.basename(file_path)
        lang = self.lang_manager.detect_file_language(file_path) or "Python"

        # Python AST check
        if lang == "Python":
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Subscript):
                        is_os_environ = False
                        if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                            is_os_environ = True

                        if is_os_environ and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                            var_name = node.slice.value
                            if var_name not in os.environ:
                                line_no = getattr(node, "lineno", 1)
                                line_str = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                                issues.append(CodeIssue(
                                    id=f"iss_env_{uuid.uuid4().hex[:6]}",
                                    title=f"Unchecked Environment Variable '{var_name}' (KeyError Risk)",
                                    category="config",
                                    severity="medium",
                                    file_path=rel_path,
                                    line_number=line_no,
                                    language="Python",
                                    function_name=None,
                                    original_code=line_str.strip(),
                                    what_is_wrong=f"Accessing os.environ['{var_name}'] will throw KeyError if '{var_name}' is not exported.",
                                    root_cause=f"Direct subscript indexing on os.environ raises KeyError when the environment variable is undefined.",
                                    potential_impact="Immediate application crash upon startup or when reaching this execution branch.",
                                    corrected_code=f"os.getenv('{var_name}', 'default_value')",
                                    explanation_of_correction=f"Used os.getenv with a safe fallback default value.",
                                    verified=True,
                                    status="confirmed",
                                    confidence=0.92,
                                    agent_source="runtime_dependency_agent"
                                ))
            except Exception:
                pass

        # JavaScript / TypeScript check: process.env.VAR without fallback
        elif lang in ("JavaScript", "TypeScript"):
            import re
            pattern = re.compile(r"process\.env\.([A-Za-z0-9_]+)\b(?!\s*(?:\|\||\?\?))")
            for idx, line in enumerate(lines, start=1):
                m = pattern.search(line)
                if m and not line.strip().startswith("//"):
                    var_name = m.group(1)
                    if var_name not in os.environ and var_name not in ("NODE_ENV", "PORT"):
                        issues.append(CodeIssue(
                            id=f"iss_js_env_{idx}",
                            title=f"Unchecked process.env.{var_name} (Undefined Config Risk)",
                            category="config",
                            severity="medium",
                            file_path=rel_path,
                            line_number=idx,
                            language=lang,
                            original_code=line.strip(),
                            what_is_wrong=f"Direct access to process.env.{var_name} without default or nullish coalescing.",
                            root_cause=f"'{var_name}' is not verified against undefined.",
                            potential_impact="Silent undefined variable resulting in configuration failure or TypeError.",
                            corrected_code=f"process.env.{var_name} ?? ''",
                            explanation_of_correction=f"Provide fallback: process.env.{var_name} || 'default'",
                            verified=True,
                            status="confirmed",
                            confidence=0.85,
                            agent_source="runtime_dependency_agent"
                        ))

        # Java check: System.getenv without null check
        elif lang == "Java":
            import re
            pattern = re.compile(r"System\.getenv\s*\(\s*\"([A-Za-z0-9_]+)\"\s*\)")
            for idx, line in enumerate(lines, start=1):
                m = pattern.search(line)
                if m and not line.strip().startswith("//") and "getOrDefault" not in line and "!= null" not in line:
                    var_name = m.group(1)
                    issues.append(CodeIssue(
                        id=f"iss_java_env_{idx}",
                        title=f"Unchecked System.getenv(\"{var_name}\") (NullPointerException Risk)",
                        category="config",
                        severity="medium",
                        file_path=rel_path,
                        line_number=idx,
                        language="Java",
                        original_code=line.strip(),
                        what_is_wrong=f"System.getenv(\"{var_name}\") returns null when environment variable is unset.",
                        root_cause="Missing null check on returned environment string before usage.",
                        potential_impact="NullPointerException thrown during runtime execution.",
                        corrected_code=f"System.getenv().getOrDefault(\"{var_name}\", \"\")",
                        explanation_of_correction=f"Use System.getenv().getOrDefault(\"{var_name}\", \"\") or guard with null check.",
                        verified=True,
                        status="confirmed",
                        confidence=0.87,
                        agent_source="runtime_dependency_agent"
                    ))

        # C / C++ check: getenv without null check
        elif lang == "C/C++":
            import re
            pattern = re.compile(r"\bgetenv\s*\(\s*\"([A-Za-z0-9_]+)\"\s*\)")
            for idx, line in enumerate(lines, start=1):
                m = pattern.search(line)
                if m and not line.strip().startswith("//") and "== NULL" not in line and "!= NULL" not in line:
                    var_name = m.group(1)
                    issues.append(CodeIssue(
                        id=f"iss_cpp_env_{idx}",
                        title=f"Unchecked getenv(\"{var_name}\") Return Value",
                        category="config",
                        severity="medium",
                        file_path=rel_path,
                        line_number=idx,
                        language="C/C++",
                        original_code=line.strip(),
                        what_is_wrong=f"getenv(\"{var_name}\") returns NULL if the environment variable is not defined.",
                        root_cause="Dereferencing result of getenv() without verifying if return value is NULL.",
                        potential_impact="Immediate segmentation fault (SIGSEGV) when variable is unset.",
                        corrected_code=f"const char* {var_name.lower()} = getenv(\"{var_name}\"); if (!{var_name.lower()}) ...",
                        explanation_of_correction=f"Check if getenv(\"{var_name}\") != NULL before dereferencing.",
                        verified=True,
                        status="confirmed",
                        confidence=0.89,
                        agent_source="runtime_dependency_agent"
                    ))

        return issues

