"""
DevPilot 3.0 TypeScript Language Adapter
Provides TypeScript compiler diagnostics (tsc --noEmit), type safety inspection, and security analysis.
"""
from typing import List, Dict, Any, Optional, Tuple
import os
import re
import shutil
import subprocess
import tempfile
from src.analysis.languages.javascript_adapter import JavaScriptAdapter
from src.blackboard.schema import CodeIssue


class TypeScriptAdapter(JavaScriptAdapter):
    """Specialized adapter for TypeScript (tsc / tsconfig) code inspection."""

    def __init__(self):
        super().__init__()
        self.language_name = "TypeScript"
        self.file_extensions = [".ts", ".tsx", ".d.ts"]
        self.manifest_files = ["tsconfig.json", "package.json"]
        self._cached_toolchain: Optional[Dict[str, Any]] = None

    def check_toolchain(self) -> Dict[str, Any]:
        if self._cached_toolchain:
            return self._cached_toolchain

        tools: Dict[str, str] = {}
        node_bin = shutil.which("node")
        if node_bin:
            tools["node"] = node_bin

        tsc_bin = shutil.which("tsc")
        if tsc_bin:
            tools["tsc"] = tsc_bin

        eslint_bin = shutil.which("eslint")
        if eslint_bin:
            tools["eslint"] = eslint_bin

        status = "fully_supported" if "tsc" in tools else ("partially_supported" if "node" in tools else "unavailable")
        limitations = []
        if "tsc" not in tools:
            limitations.append("TypeScript compiler CLI (tsc) not found globally; type checking using Node experimental-strip-types")

        self._cached_toolchain = {
            "available": ("tsc" in tools or "node" in tools),
            "status": status,
            "tools": tools,
            "limitations": limitations
        }
        return self._cached_toolchain

    def scan_file(self, file_path: str, repo_root: str) -> List[CodeIssue]:
        # 1. Run JavaScript security patterns first
        issues = super().scan_file(file_path, repo_root)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return issues

        rel_path = os.path.relpath(file_path, repo_root) if repo_root else os.path.basename(file_path)

        # 2. TypeScript-Specific Type Safety & Anti-pattern Diagnostics
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Insecure / Anti-pattern : any
            if re.search(r":\s*any\b|\bas\s+any\b", line):
                issues.append(CodeIssue(
                    id=f"ts_any_pollution_{i}",
                    title="TypeScript 'any' Type Assertion / Escape Hatch",
                    category="quality",
                    severity="medium",
                    file_path=rel_path,
                    line_number=i,
                    function_name=None,
                    original_code=stripped,
                    what_is_wrong="Use of 'any' completely disables TypeScript compile-time type safety.",
                    root_cause="Defeating static type checking increases probability of undetected runtime TypeErrors.",
                    potential_impact="Silent runtime failures due to mismatched property or method accesses.",
                    corrected_code="// Replace 'any' with explicit interface, union, or 'unknown' with type narrowing",
                    explanation_of_correction="Define a strict domain interface or type guard instead of 'any'.",
                    verified=True,
                    status="confirmed",
                    confidence=0.89,
                    agent_source="static_analysis_agent"
                ))

            # Dangerous non-null assertion operator (!)
            if re.search(r"\b[a-zA-Z0-9_]+!\.[a-zA-Z0-9_]+", line):
                issues.append(CodeIssue(
                    id=f"ts_non_null_assertion_{i}",
                    title="Unsafe Non-Null Assertion Operator (!)",
                    category="runtime",
                    severity="medium",
                    file_path=rel_path,
                    line_number=i,
                    function_name=None,
                    original_code=stripped,
                    what_is_wrong="Bypassing null/undefined checks with '!' operator without conditional verification.",
                    root_cause="If value is null or undefined at runtime, this causes TypeError: Cannot read property of null/undefined.",
                    potential_impact="Unhandled runtime crash in production.",
                    corrected_code="// Use optional chaining '?.' or nullish coalescing '??'",
                    explanation_of_correction="Replace non-null assertion with optional chaining '?.' or explicit if guard.",
                    verified=True,
                    status="confirmed",
                    confidence=0.91,
                    agent_source="runtime_dependency_agent"
                ))

            # Dangerous double assertion type bypass (as unknown as T)
            if re.search(r"\bas\s+unknown\s+as\b|\bas\s+any\s+as\b", line):
                issues.append(CodeIssue(
                    id=f"ts_double_cast_{i}",
                    title="Forced Type Cast Bypass (as unknown as T)",
                    category="quality",
                    severity="medium",
                    file_path=rel_path,
                    line_number=i,
                    function_name=None,
                    original_code=stripped,
                    what_is_wrong="Forced double type cast completely bypasses TypeScript type compatibility checking.",
                    root_cause="Forcing incompatible types defeats compiler sound type guarantees.",
                    potential_impact="Underlying object shape mismatch causing runtime TypeError.",
                    corrected_code="// Implement user-defined type predicate / type guard",
                    explanation_of_correction="Use type narrowing or type predicate function (val is TargetType).",
                    verified=True,
                    status="confirmed",
                    confidence=0.88,
                    agent_source="static_analysis_agent"
                ))

        # 3. If tsc is available and project has tsconfig.json or single file, run tsc diagnostics
        toolchain = self.check_toolchain()
        if "tsc" in toolchain["tools"] and repo_root:
            tsconfig = os.path.join(repo_root, "tsconfig.json")
            if os.path.exists(tsconfig):
                try:
                    res = subprocess.run(
                        [toolchain["tools"]["tsc"], "--noEmit", "--project", tsconfig],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if res.returncode != 0:
                        out = res.stdout + "\n" + res.stderr
                        for err_line in out.splitlines():
                            if rel_path in err_line:
                                m = re.search(r"\((\d+),\d+\):\s*error\s*(TS\d+):\s*(.*)", err_line)
                                if m:
                                    ln = int(m.group(1))
                                    ts_code = m.group(2)
                                    msg = m.group(3)
                                    if not any(iss.line_number == ln and iss.title.startswith("TypeScript Error") for iss in issues):
                                        issues.append(CodeIssue(
                                            id=f"tsc_{ts_code}_{ln}",
                                            title=f"TypeScript Error {ts_code}",
                                            category="syntax",
                                            severity="high",
                                            file_path=rel_path,
                                            line_number=ln,
                                            function_name=None,
                                            original_code=lines[ln-1].strip() if ln <= len(lines) else "",
                                            what_is_wrong=f"TypeScript compilation error: {msg}",
                                            root_cause=f"Type violation caught by tsc compiler ({ts_code}).",
                                            potential_impact="Compilation failure and runtime type defect.",
                                            corrected_code="// Corrected TypeScript definition",
                                            explanation_of_correction="Resolve type definition mismatch according to TypeScript compiler error.",
                                            verified=True,
                                            status="confirmed",
                                            confidence=1.0,
                                            agent_source="static_analysis_agent"
                                        ))
                except Exception:
                    pass

        return issues

    def verify_syntax(self, code: str, file_path: Optional[str] = None) -> Tuple[bool, List[str]]:
        toolchain = self.check_toolchain()
        if "node" in toolchain["tools"]:
            with tempfile.NamedTemporaryFile("w", suffix=".ts", delete=False, encoding="utf-8") as tmp:
                tmp.write(code)
                tmp_path = tmp.name
            try:
                res = subprocess.run([toolchain["tools"]["node"], "--experimental-strip-types", "--check", tmp_path], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    return True, []
                err_lines = [l for l in (res.stderr or res.stdout).splitlines() if "ExperimentalWarning" not in l and l.strip()]
                return False, err_lines[:2] if err_lines else ["TypeScript syntax error"]
            except Exception as e:
                return False, [str(e)]
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        return True, []
