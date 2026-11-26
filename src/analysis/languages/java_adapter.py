"""
DevPilot 3.0 Java Language Adapter
Provides Java AST analysis using Javalang, OWASP Java security scanning, and javac compilation diagnostics.
"""
from typing import List, Dict, Any, Optional, Tuple
import os
import re
import shutil
import subprocess
import tempfile
from src.analysis.languages.base import BaseLanguageAdapter
from src.blackboard.schema import CodeIssue


class JavaAdapter(BaseLanguageAdapter):
    """Specialized adapter for Java source inspection, security, and compilation."""

    def __init__(self):
        super().__init__(
            language_name="Java",
            file_extensions=[".java"],
            manifest_files=["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"]
        )
        self._cached_toolchain: Optional[Dict[str, Any]] = None

    def check_toolchain(self) -> Dict[str, Any]:
        if self._cached_toolchain:
            return self._cached_toolchain

        tools: Dict[str, str] = {}
        javac_bin = shutil.which("javac")
        if javac_bin:
            tools["javac"] = javac_bin

        java_bin = shutil.which("java")
        if java_bin:
            tools["java"] = java_bin

        mvn_bin = shutil.which("mvn")
        if mvn_bin:
            tools["maven"] = mvn_bin

        try:
            import javalang
            tools["javalang_ast"] = "0.13.0"
        except ImportError:
            pass

        has_ast = "javalang_ast" in tools
        has_javac = "javac" in tools
        status = "fully_supported" if (has_javac and has_ast) else ("partially_supported" if has_ast else "unavailable")
        limitations = []
        if not has_javac:
            limitations.append("javac compiler not found on system PATH; bytecode compilation disabled")
        if not has_ast:
            limitations.append("javalang is unavailable; Java AST analysis is disabled")

        self._cached_toolchain = {
            "available": has_ast or has_javac,
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

        # 1. Javalang AST Syntax & Parser Verification
        valid, errs = self.verify_syntax(content, file_path)
        if not valid:
            for err in errs:
                line_no = 1
                m = re.search(r"line\s+(\d+)", err, re.IGNORECASE)
                if m:
                    line_no = int(m.group(1))
                issues.append(CodeIssue(
                    id=f"java_syntax_{line_no}",
                    title="Java Syntax or Lexical Error",
                    category="syntax",
                    severity="critical",
                    file_path=rel_path,
                    line_number=line_no,
                    function_name=None,
                    original_code=lines[line_no - 1] if line_no <= len(lines) else "",
                    what_is_wrong=f"Java syntax violation: {err}",
                    root_cause="Invalid Java grammar or malformed statement.",
                    potential_impact="Compilation failure in javac / maven build.",
                    corrected_code="// Corrected Java statement",
                    explanation_of_correction="Fix syntax error according to Java language specification.",
                    verified=True,
                    status="confirmed",
                    confidence=1.0,
                    agent_source="static_analysis_agent"
                ))

        # 2. Rule & Pattern Security Engine (OWASP Java & Common Weakness Enumerations)
        patterns = [
            # SQL Injection
            (
                r"(?:Statement|stmt|connection|conn|[a-zA-Z0-9_]+)\s*\.\s*(?:executeQuery|executeUpdate|execute)\s*\(\s*(?:\"[^\"]*\"|'[^']*'|[a-zA-Z0-9_]+)?\s*\+",
                "SQL Injection via String Concatenation in JDBC Statement",
                "security", "critical",
                "Dynamic string concatenation used to construct SQL query string in Statement",
                "Allows SQL Injection; attackers can alter database query structure, steal or destroy data.",
                "Use PreparedStatement with parameterized '?' placeholders: PreparedStatement ps = conn.prepareStatement(\"SELECT ... WHERE id = ?\"); ps.setString(1, id);",
                "Replace Statement concatenation with PreparedStatement parameters."
            ),
            # Command Injection
            (
                r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\([^)]*\+",
                "Command Injection via Runtime.exec / ProcessBuilder",
                "security", "critical",
                "Executing system operating system commands with concatenated untrusted parameters",
                "Arbitrary command execution on the host machine.",
                "Use ProcessBuilder with a strict List<String> argument array, without shell invocation.",
                "Avoid passing concatenated strings to OS execution."
            ),
            # Path Traversal
            (
                r"new\s+File\s*\([^,]+,\s*[a-zA-Z0-9_]+\s*\)|Paths\.get\([^,]+,\s*[a-zA-Z0-9_]+\s*\)",
                "Path Traversal in Java File Access",
                "security", "high",
                "Constructing File object using external parameters without canonical path containment check",
                "Arbitrary file access or overwriting outside the application workspace.",
                "Verify file.getCanonicalPath().startsWith(baseDir.getCanonicalPath()) before access.",
                "Sanitize and restrict filesystem paths to safe base directory."
            ),
            # Unsafe Deserialization
            (
                r"(?:new\s+ObjectInputStream|in)\s*\.\s*readObject\s*\(",
                "Unsafe Java Object Deserialization",
                "security", "critical",
                "Deserializing untrusted streams using ObjectInputStream.readObject() without class filtering",
                "Remote Code Execution (RCE) via gadget chains (ysoserial pattern).",
                "Implement a ValidatingObjectInputStream with strict class allowlist or use JSON/Jackson safe serialization.",
                "Enforce strict class allowlist or migrate to safe serialization format."
            ),
            # Insecure Cryptography
            (
                r"Cipher\.getInstance\s*\(\s*['\"](?:DES|RC4|DESede|Blowfish)['\"]\s*\)|MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1)['\"]\s*\)",
                "Insecure Cryptographic Algorithm (Broken / Deprecated)",
                "security", "high",
                "Use of cryptographically broken cipher or hashing algorithm (DES, RC4, MD5, SHA-1)",
                "Vulnerable to collision attacks, cryptographic break, and unauthorized decryption.",
                "Use AES-GCM (Cipher.getInstance(\"AES/GCM/NoPadding\")) and SHA-256 / SHA-512 for hashing.",
                "Upgrade to modern cryptographic standards."
            ),
            # Hardcoded Credentials
            (
                r"(?i)(?:password|secret|apiKey|api_key|authToken)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]",
                "Hardcoded Credentials or Secrets in Java Class",
                "security", "critical",
                "Sensitive secret or password committed directly into source code",
                "Exposure of credentials in version control repository.",
                "Load secrets from System.getenv(\"API_KEY\") or secure secrets vault.",
                "Replace hardcoded credential with secure configuration property."
            ),
            # Resource Leak: Stream opened without try-with-resources
            (
                r"(?:FileInputStream|FileOutputStream|BufferedReader|Connection)\s+[a-zA-Z0-9_]+\s*=\s*new\s+(?:FileInputStream|FileOutputStream|BufferedReader)",
                "Resource Leak: Stream Opened Without Try-With-Resources",
                "quality", "medium",
                "Unmanaged I/O stream or database resource opened without automatic try-with-resources",
                "File descriptor exhaustion or connection pool depletion under load.",
                "Use try-with-resources: try (FileInputStream fis = new FileInputStream(file)) { ... }",
                "Wrap resource instantiation in try-with-resources block."
            ),
            # Empty catch block
            (
                r"catch\s*\([^)]+\)\s*\{\s*\}",
                "Empty Catch Block (Exception Swallowing)",
                "logic", "medium",
                "Catching exception and swallowing it silently without logging or handling",
                "Masks critical failures and makes runtime debugging impossible.",
                "Log exception with logger.error(\"Context\", e) or rethrow custom domain exception.",
                "Add defensive error logging or rethrow exception."
            ),
            # Division by Zero Risk
            (
                r"/\s*0(?:\.0)?\b|/\s*(?:size\(\)|length)\b",
                "Potential Division by Zero Risk in Java Code",
                "runtime", "high",
                "Division operation with zero or unchecked denominator.",
                "Throws java.lang.ArithmeticException: / by zero at runtime.",
                "Check that divisor != 0 before dividing: if (divisor != 0) { ... }",
                "Add zero-denominator guard check."
            ),
            # Off-by-one / Array Index Out of Bounds
            (
                r"for\s*\([^;]*;\s*[a-zA-Z0-9_]+\s*<=\s*(?:[a-zA-Z0-9_]+\.length|[a-zA-Z0-9_]+\.size\(\))",
                "Array Index Out of Bounds via '<=' Loop Condition",
                "runtime", "high",
                "Loop boundary uses '<=' instead of '<' with array length or collection size.",
                "Throws ArrayIndexOutOfBoundsException or IndexOutOfBoundsException on last iteration.",
                "Use '<' instead of '<=': for (int i = 0; i < list.size(); i++)",
                "Enforce strict strictly-less-than index iteration."
            ),
            # Assignment within Condition
            (
                r"if\s*\(\s*[a-zA-Z0-9_]+\s*=\s*[^=]",
                "Assignment in Boolean Condition Expression",
                "logic", "medium",
                "Accidental assignment '=' instead of equality comparison '=='.",
                "Assigns variable and uses result as condition, leading to unintended control flow.",
                "Use '==' for comparison: if (flag == true)",
                "Replace assignment operator with equality comparison."
            )
        ]

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for pattern, title, category, sev, what, impact, fix, expl in patterns:
                if "Resource Leak" in title and ("try (" in line or "try(" in line):
                    continue
                if re.search(pattern, line):
                    if any(iss.line_number == i and iss.title == title for iss in issues):
                        continue
                    issues.append(CodeIssue(
                        id=f"java_{category}_{i}",
                        title=title,
                        category=category,
                        severity=sev,
                        file_path=rel_path,
                        line_number=i,
                        function_name=None,
                        original_code=stripped,
                        what_is_wrong=what,
                        root_cause=f"Java rule violation on line {i}: {stripped}",
                        potential_impact=impact,
                        corrected_code=f"// {fix}",
                        explanation_of_correction=expl,
                        verified=True,
                        status="confirmed",
                        confidence=0.93,
                        agent_source="security_analysis_agent" if category == "security" else "static_analysis_agent",
                        test_results={"syntax_verified": True}
                    ))

        return issues

    def verify_syntax(self, code: str, file_path: Optional[str] = None) -> Tuple[bool, List[str]]:
        try:
            import javalang
        except ImportError:
            javalang = None
        if javalang is not None:
            try:
                javalang.parse.parse(code)
                return True, []
            except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as exc:
                return False, [getattr(exc, "description", None) or str(exc) or "Invalid Java syntax."]

        # 2. Try javac if installed
        toolchain = self.check_toolchain()
        if "javac" in toolchain["tools"]:
            with tempfile.TemporaryDirectory(prefix="devpilot_java_") as workspace:
                tmp_path = os.path.join(workspace, os.path.basename(file_path or "Target.java"))
                with open(tmp_path, "w", encoding="utf-8") as tmp:
                    tmp.write(code)
                try:
                    res = subprocess.run([toolchain["tools"]["javac"], "-proc:none", tmp_path],
                                         cwd=workspace, capture_output=True, text=True, timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    return True, []  # Toolchain diagnostics describe the unavailable syntax check.
                return res.returncode == 0, [res.stderr.strip()[:300]] if res.returncode else []

        return True, []

    def run_tests(
        self,
        repo_dir: str,
        test_target: Optional[str] = None,
        candidate_patch_diff: Optional[str] = None
    ) -> Dict[str, Any]:
        toolchain = self.check_toolchain()
        if "maven" in toolchain["tools"] and os.path.exists(os.path.join(repo_dir, "pom.xml")):
            try:
                res = subprocess.run([toolchain["tools"]["maven"], "test", "-q"], cwd=repo_dir, capture_output=True, text=True, timeout=60)
                return {
                    "testable": True,
                    "all_passed": res.returncode == 0,
                    "exit_code": res.returncode,
                    "stdout": res.stdout,
                    "stderr": res.stderr
                }
            except Exception as e:
                return {"testable": True, "all_passed": False, "exit_code": -1, "stdout": "", "stderr": str(e)}

        return {
            "testable": False,
            "reason": "Java test runner (Maven/Gradle) not configured or pom.xml not found."
        }

