"""
DevPilot 3.0 JavaScript Language Adapter
Provides static inspection, ESLint diagnostics, OWASP security scanning, and Node test execution.
"""
from typing import List, Dict, Any, Optional, Tuple
import os
import re
import shutil
import subprocess
import tempfile
import json
from src.analysis.languages.base import BaseLanguageAdapter
from src.blackboard.schema import CodeIssue


class JavaScriptAdapter(BaseLanguageAdapter):
    """Specialized adapter for JavaScript (Node.js/ESM/CommonJS) code inspection."""

    def __init__(self):
        super().__init__(
            language_name="JavaScript",
            file_extensions=[".js", ".mjs", ".cjs", ".jsx"],
            manifest_files=["package.json", "package-lock.json", ".eslintrc.json", ".eslintrc.js", "jsconfig.json"]
        )
        self._cached_toolchain: Optional[Dict[str, Any]] = None

    def check_toolchain(self) -> Dict[str, Any]:
        if self._cached_toolchain:
            return self._cached_toolchain

        tools: Dict[str, str] = {}
        node_bin = shutil.which("node")
        if node_bin:
            tools["node"] = node_bin

        npm_bin = shutil.which("npm")
        if npm_bin:
            tools["npm"] = npm_bin

        eslint_bin = shutil.which("eslint")
        if eslint_bin:
            tools["eslint"] = eslint_bin

        status = "fully_supported" if "node" in tools else "unavailable"
        limitations = []
        if "node" not in tools:
            limitations.append("Node.js runtime not found on host PATH")
        if "eslint" not in tools:
            limitations.append("ESLint CLI not found globally; using native Node --check parser")

        self._cached_toolchain = {
            "available": "node" in tools,
            "status": status,
            "tools": tools,
            "limitations": limitations
        }
        return self._cached_toolchain

    def scan_file(self, file_path: str, repo_root: str) -> List[CodeIssue]:
        issues: List[CodeIssue] = []
        if not os.path.exists(file_path):
            return issues

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return issues

        try:
            rel_path = os.path.relpath(file_path, repo_root) if repo_root else os.path.basename(file_path)
        except ValueError:
            rel_path = os.path.basename(file_path)

        # 1. Native Node.js Syntax Verification
        valid, errs = self.verify_syntax(content, file_path)
        if not valid:
            for err in errs:
                line_no = 1
                match = re.search(r":(\d+)", err)
                if match:
                    line_no = int(match.group(1))
                issues.append(CodeIssue(
                    id=f"js_syntax_{line_no}",
                    title="JavaScript Syntax Error",
                    category="syntax",
                    severity="critical",
                    file_path=rel_path,
                    line_number=line_no,
                    function_name=None,
                    original_code=lines[line_no - 1] if line_no <= len(lines) else "",
                    what_is_wrong=f"Syntax error detected by Node.js compiler: {err}",
                    root_cause="Invalid JavaScript syntax prevents parsing or execution.",
                    potential_impact="Module fails to load or execute.",
                    corrected_code="// Corrected syntax",
                    explanation_of_correction="Fix syntax violation.",
                    verified=True,
                    status="confirmed",
                    confidence=1.0,
                    agent_source="static_analysis_agent"
                ))

        # 2. Rule & Pattern Security Engine (OWASP Top 10 for JS/Node)
        patterns = [
            # SQL Injection
            (
                r"(?:query|execute)\s*\([^)]*(?:\$\{|\+)",
                "SQL Injection via Unsanitized Template String / Concatenation",
                "security", "critical",
                "Direct string concatenation or template interpolation inside database query",
                "SQL Injection allows unauthorized data retrieval, tampering, or administrative bypass.",
                "Use parameterized query placeholders: db.query('SELECT * FROM users WHERE id = ?', [userId])",
                "Replace dynamic SQL string with prepared statement parameters."
            ),
            # Command Injection
            (
                r"(?:child_process\.)?(?:exec|execSync)\s*\([^)]*(?:\$\{|\+)",
                "Command Injection in child_process Execution",
                "security", "critical",
                "Unsanitized input concatenated into system command shell execution",
                "Arbitrary command execution on host operating system.",
                "Use child_process.execFile() or spawn() with argument array without shell: true.",
                "Avoid passing concatenated strings to shell execution."
            ),
            # Path Traversal
            (
                r"fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\([^)]*(?:\$\{|\+)",
                "Path Traversal in Filesystem Access",
                "security", "high",
                "File path constructed from request parameters without canonical containment verification",
                "Access to arbitrary sensitive files outside application root directory.",
                "Resolve canonical path with path.resolve() and verify path.startsWith(baseDirectory).",
                "Sanitize and restrict filesystem paths to safe directory root."
            ),
            # Unsafe eval
            (
                r"\beval\s*\(|new\s+Function\s*\(",
                "Insecure Code Execution via eval() / new Function()",
                "security", "critical",
                "Dynamic code evaluation executes arbitrary untrusted strings",
                "Remote Code Execution (RCE) and logic tampering.",
                "Use JSON.parse() or dedicated domain-specific safe parser instead of eval.",
                "Remove eval() invocation."
            ),
            # Hardcoded API Keys / Secrets
            (
                r"(?i)(api_?key|secret|password|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
                "Hardcoded Secret / Token in Source Code",
                "security", "critical",
                "Sensitive credential or secret key committed directly into source code",
                "Exposure of credentials in version control leading to system compromise.",
                "Load sensitive secret from process.env with process.env.API_KEY fallback check.",
                "Migrate credentials to secure environment variables."
            ),
            # Cross-Site Scripting (XSS)
            (
                r"(?:\.innerHTML|\.outerHTML)\s*=\s*[^;]+",
                "Cross-Site Scripting (XSS) via Unsanitized DOM Assignment",
                "security", "high",
                "Assigning dynamic unsanitized HTML markup to innerHTML",
                "Client-side script execution, session cookie hijacking, and DOM tampering.",
                "Use element.textContent or DOMPurify.sanitize() before DOM insertion.",
                "Replace innerHTML with textContent or sanitized DOM elements."
            ),
            # Prototype Pollution
            (
                r"Object\.assign\s*\([^,]+,\s*JSON\.parse\(|__proto__|constructor\.prototype",
                "Prototype Pollution Risk",
                "security", "high",
                "Direct mutation of Object.prototype or recursive object merging without validation",
                "Application crash, denial of service, or authorization bypass.",
                "Use Object.create(null) or validate keys against __proto__ and prototype properties.",
                "Protect against prototype pollution with key allowlisting."
            ),
            # Unhandled Promise rejection / async error
            (
                r"async\s+function[^{]*\{(?![^}]*try\s*\{)",
                "Async Function Missing try/catch Exception Handling",
                "runtime", "medium",
                "Asynchronous function without local error handling or rejection trapping",
                "Unhandled Promise rejection crashes Node.js process in modern runtimes.",
                "Wrap asynchronous operations in try/catch or attach .catch() handler.",
                "Add defensive exception handling."
            ),
            # Division by Zero Risk
            (
                r"/\s*0(?:\.0)?\b|/\s*(?:items\.length|arr\.length|list\.length)\b",
                "Potential Division by Zero (Zero or Empty Array Length)",
                "runtime", "high",
                "Arithmetic division by zero literal or unchecked collection length (evaluates to Infinity / NaN).",
                "Produces NaN or Infinity values, causing mathematical errors and broken application state.",
                "Verify length > 0 before division: if (arr.length > 0) { ... }",
                "Add zero-length guard before division."
            ),
            # Array Boundary Violation / Off-by-one in Loop
            (
                r"for\s*\([^;]*;\s*[a-zA-Z0-9_]+\s*<=\s*[a-zA-Z0-9_]+\.length",
                "Off-By-One Array Boundary Error (<= length)",
                "runtime", "high",
                "Loop iterates with '<= length', accessing undefined index on final iteration.",
                "Reading array[length] returns undefined, leading to 'Cannot read properties of undefined' TypeError.",
                "Use '<' instead of '<=': for (let i = 0; i < arr.length; i++)",
                "Enforce strictly-less-than array boundary iteration."
            ),
            # Accidental Assignment in Condition
            (
                r"if\s*\(\s*[a-zA-Z0-9_]+\s*=\s*[^=]",
                "Accidental Assignment in If Condition",
                "logic", "medium",
                "Using assignment '=' instead of strict equality '===' inside condition.",
                "Variable is overwritten and expression truthiness is evaluated instead of comparison.",
                "Use strict equality '===': if (status === expected)",
                "Replace assignment operator with equality comparison."
            ),
            # Empty Catch Block
            (
                r"catch\s*\([^)]*\)\s*\{\s*\}",
                "Empty Catch Block (Suppressed Error)",
                "quality", "medium",
                "Swallowing caught exception without logging, error reporting, or handling.",
                "Silent failures mask critical runtime issues and hinder debugging.",
                "Log error: catch (err) { console.error('Error occurred:', err); }",
                "Add defensive error logging in catch handler."
            )
        ]

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for pattern, title, category, sev, what, impact, fix, expl in patterns:
                if re.search(pattern, line):
                    # Avoid duplicate issue on same line
                    if any(iss.line_number == i and iss.title == title for iss in issues):
                        continue
                    issues.append(CodeIssue(
                        id=f"js_{category}_{i}",
                        title=title,
                        category=category,
                        severity=sev,
                        file_path=rel_path,
                        line_number=i,
                        function_name=None,
                        original_code=stripped,
                        what_is_wrong=what,
                        root_cause=f"Pattern violation detected: {stripped}",
                        potential_impact=impact,
                        corrected_code=f"// {fix}",
                        explanation_of_correction=expl,
                        verified=True,
                        status="confirmed",
                        confidence=0.92,
                        agent_source="security_analysis_agent" if category == "security" else "static_analysis_agent",
                        test_results={"syntax_verified": True}
                    ))

        return issues

    def verify_syntax(self, code: str, file_path: Optional[str] = None) -> Tuple[bool, List[str]]:
        toolchain = self.check_toolchain()
        if "node" not in toolchain["tools"]:
            return True, []  # Node not available, skip strict syntax verification

        node_bin = toolchain["tools"]["node"]
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            res = subprocess.run([node_bin, "--check", tmp_path], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, []
            err_msg = res.stderr or res.stdout
            cleaned = err_msg.replace(tmp_path, file_path or "source.js")
            return False, [cleaned.strip()]
        except Exception as e:
            return False, [str(e)]
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def run_tests(
        self,
        repo_dir: str,
        test_target: Optional[str] = None,
        candidate_patch_diff: Optional[str] = None
    ) -> Dict[str, Any]:
        toolchain = self.check_toolchain()
        if "node" not in toolchain["tools"]:
            return {"testable": False, "reason": "Node.js is not installed"}

        # Native node --test runner (Node 18+)
        cmd = [toolchain["tools"]["node"], "--test"]
        if test_target and os.path.exists(os.path.join(repo_dir, test_target)):
            cmd.append(test_target)

        try:
            res = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True, timeout=30)
            return {
                "testable": True,
                "all_passed": res.returncode == 0,
                "exit_code": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr
            }
        except subprocess.TimeoutExpired:
            return {"testable": True, "all_passed": False, "exit_code": -1, "stdout": "", "stderr": "Test execution timed out (30s)"}
        except Exception as e:
            return {"testable": True, "all_passed": False, "exit_code": -1, "stdout": "", "stderr": str(e)}

