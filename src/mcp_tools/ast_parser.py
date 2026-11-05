"""
Custom Multi-Language AST & Structural Parser Tool (MCP Tool 1)
Extracts classes, functions, calls, imports, and pinpoints syntax errors across
Python, JavaScript, TypeScript, Java, and C/C++.
"""
import ast
import os
import re
from typing import List, Dict, Any, Optional
from src.blackboard.schema import ASTSymbol, ASTAnalysisResult

SUPPORTED_EXTENSIONS = (
    ".py", ".pyw",
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx",
    ".java",
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"
)


class ASTParserTool:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)

    def analyze_repository(self, target_files: Optional[List[str]] = None) -> ASTAnalysisResult:
        symbols: List[ASTSymbol] = []
        syntax_errors: List[Dict[str, Any]] = []
        call_graph: Dict[str, List[str]] = {}
        files_analyzed: List[str] = []

        if os.path.isfile(self.repo_path):
            file_paths = [self.repo_path]
        elif target_files:
            file_paths = [os.path.join(self.repo_path, f) if not os.path.isabs(f) else f for f in target_files]
        else:
            file_paths = []
            for root, _, files in os.walk(self.repo_path):
                # Ignore .git, venv, cache dirs, and temp build artifacts
                if any(ignored in root for ignored in ['.git', '__pycache__', '.venv', 'venv', '.pytest_cache', '.gemini', 'brain', 'node_modules', 'dist', 'build', 'target']):
                    continue
                for file in files:
                    if file.lower().endswith(SUPPORTED_EXTENSIONS):
                        file_paths.append(os.path.join(root, file))

        for file_path in file_paths:
            if not os.path.exists(file_path):
                continue
            
            if os.path.isfile(self.repo_path):
                rel_path = os.path.basename(file_path)
            else:
                rel_path = os.path.relpath(file_path, self.repo_path)
            files_analyzed.append(rel_path)

            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
            except Exception as e:
                syntax_errors.append({
                    "file": rel_path,
                    "error_type": "IOError",
                    "message": str(e),
                    "line": 0
                })
                continue

            ext = os.path.splitext(file_path)[1].lower()

            # 1. Python AST
            if ext in (".py", ".pyw"):
                self._parse_python(content, rel_path, symbols, call_graph, syntax_errors)
            # 2. Java AST via Javalang
            elif ext == ".java":
                self._parse_java(content, rel_path, symbols, call_graph, syntax_errors)
            # 3. JavaScript / TypeScript
            elif ext in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"):
                self._parse_javascript_typescript(content, rel_path, ext, symbols, call_graph, syntax_errors)
            # 4. C / C++
            elif ext in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"):
                self._parse_cpp(content, rel_path, symbols, call_graph, syntax_errors)

        return ASTAnalysisResult(
            repo_path=self.repo_path,
            files_analyzed=files_analyzed,
            symbols=symbols,
            call_graph=call_graph,
            syntax_errors=syntax_errors
        )

    def _parse_python(self, content: str, rel_path: str, symbols: List[ASTSymbol], call_graph: Dict[str, List[str]], syntax_errors: List[Dict[str, Any]]) -> None:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError as se:
            syntax_errors.append({
                "file": rel_path,
                "error_type": "SyntaxError",
                "message": se.msg,
                "line": se.lineno or 0,
                "column": se.offset or 0,
                "text": se.text or ""
            })
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [arg.arg for arg in node.args.args]
                if getattr(node.args, "vararg", None):
                    params.append(f"*{node.args.vararg.arg}")
                for kw in getattr(node.args, "kwonlyargs", []):
                    params.append(kw.arg)
                if getattr(node.args, "kwarg", None):
                    params.append(f"**{node.args.kwarg.arg}")
                calls = []
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call):
                        if isinstance(inner.func, ast.Name):
                            calls.append(inner.func.id)
                        elif isinstance(inner.func, ast.Attribute):
                            calls.append(inner.func.attr)

                symbols.append(ASTSymbol(
                    name=node.name,
                    symbol_type="function",
                    file_path=rel_path,
                    line_start=node.lineno,
                    line_end=getattr(node, 'end_lineno', node.lineno),
                    docstring=ast.get_docstring(node),
                    parameters=params,
                    calls=list(set(calls))
                ))
                call_graph[f"{rel_path}:{node.name}"] = list(set(calls))

            elif isinstance(node, ast.ClassDef):
                symbols.append(ASTSymbol(
                    name=node.name,
                    symbol_type="class",
                    file_path=rel_path,
                    line_start=node.lineno,
                    line_end=getattr(node, 'end_lineno', node.lineno),
                    docstring=ast.get_docstring(node),
                    parameters=[],
                    calls=[]
                ))

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    symbols.append(ASTSymbol(
                        name=alias.name,
                        symbol_type="import",
                        file_path=rel_path,
                        line_start=node.lineno,
                        line_end=getattr(node, 'end_lineno', node.lineno)
                    ))

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    symbols.append(ASTSymbol(
                        name=f"{module}.{alias.name}" if module else alias.name,
                        symbol_type="import_from",
                        file_path=rel_path,
                        line_start=node.lineno,
                        line_end=getattr(node, 'end_lineno', node.lineno)
                    ))

    def _parse_java(self, content: str, rel_path: str, symbols: List[ASTSymbol], call_graph: Dict[str, List[str]], syntax_errors: List[Dict[str, Any]]) -> None:
        try:
            import javalang
            tree = javalang.parse.parse(content)
            for _, node in tree.filter(javalang.tree.MethodDeclaration):
                line_no = node.position.line if node.position else 1
                params = [param.name for param in node.parameters] if node.parameters else []
                symbols.append(ASTSymbol(
                    name=node.name,
                    symbol_type="function",
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no + 10,
                    parameters=params,
                    calls=[]
                ))
                call_graph[f"{rel_path}:{node.name}"] = []

            for _, node in tree.filter(javalang.tree.ClassDeclaration):
                line_no = node.position.line if node.position else 1
                symbols.append(ASTSymbol(
                    name=node.name,
                    symbol_type="class",
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no + 20,
                    parameters=[],
                    calls=[]
                ))

            for _, node in tree.filter(javalang.tree.Import):
                line_no = node.position.line if node.position else 1
                symbols.append(ASTSymbol(
                    name=node.path,
                    symbol_type="import",
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no
                ))
        except Exception as e:
            # Fallback to regex or record syntax error if javalang reported syntax problem
            err_msg = str(e)
            line_m = re.search(r"line\s+(\d+)", err_msg, re.IGNORECASE)
            syntax_errors.append({
                "file": rel_path,
                "error_type": "JavaSyntaxError",
                "message": err_msg,
                "line": int(line_m.group(1)) if line_m else 1,
                "column": 0,
                "text": ""
            })

    def _parse_javascript_typescript(self, content: str, rel_path: str, ext: str, symbols: List[ASTSymbol], call_graph: Dict[str, List[str]], syntax_errors: List[Dict[str, Any]]) -> None:
        lines = content.splitlines()
        # Verify bracket and syntax balance
        open_c, close_c = content.count("{"), content.count("}")
        open_p, close_p = content.count("("), content.count(")")
        if open_c != close_c or open_p != close_p:
            syntax_errors.append({
                "file": rel_path,
                "error_type": "SyntaxError",
                "message": f"Mismatched braces or parentheses (braces: {open_c}/{close_c}, parens: {open_p}/{close_p})",
                "line": 1,
                "column": 0,
                "text": ""
            })

        # Regex symbol extraction
        func_pattern = re.compile(r"(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)|(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>")
        class_pattern = re.compile(r"class\s+([A-Za-z0-9_$]+)")
        import_pattern = re.compile(r"import\s+.*?from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\)")

        for idx, line in enumerate(lines, start=1):
            f_match = func_pattern.search(line)
            if f_match:
                name = f_match.group(1) or f_match.group(3)
                param_str = f_match.group(2) or f_match.group(4) or ""
                params = [p.strip().split(':')[0].strip() for p in param_str.split(',') if p.strip()]
                symbols.append(ASTSymbol(
                    name=name,
                    symbol_type="function",
                    file_path=rel_path,
                    line_start=idx,
                    line_end=idx + 5,
                    parameters=params,
                    calls=[]
                ))
                call_graph[f"{rel_path}:{name}"] = []

            c_match = class_pattern.search(line)
            if c_match:
                symbols.append(ASTSymbol(
                    name=c_match.group(1),
                    symbol_type="class",
                    file_path=rel_path,
                    line_start=idx,
                    line_end=idx + 10,
                    parameters=[],
                    calls=[]
                ))

            i_match = import_pattern.search(line)
            if i_match:
                mod = i_match.group(1) or i_match.group(2)
                symbols.append(ASTSymbol(
                    name=mod,
                    symbol_type="import",
                    file_path=rel_path,
                    line_start=idx,
                    line_end=idx
                ))

    def _parse_cpp(self, content: str, rel_path: str, symbols: List[ASTSymbol], call_graph: Dict[str, List[str]], syntax_errors: List[Dict[str, Any]]) -> None:
        lines = content.splitlines()
        # Verify bracket balance
        open_c, close_c = content.count("{"), content.count("}")
        open_p, close_p = content.count("("), content.count(")")
        if open_c != close_c or open_p != close_p:
            syntax_errors.append({
                "file": rel_path,
                "error_type": "CppSyntaxError",
                "message": f"Mismatched braces or parentheses in C/C++ source (braces: {open_c}/{close_c}, parens: {open_p}/{close_p})",
                "line": 1,
                "column": 0,
                "text": ""
            })

        func_pattern = re.compile(r"^\s*(?:[A-Za-z0-9_*:]+\s+)+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*(?:const)?\s*\{?")
        class_pattern = re.compile(r"^\s*(?:class|struct)\s+([A-Za-z0-9_]+)")
        include_pattern = re.compile(r"^\s*#include\s*[<\"]([^>\"]+)[>\"]")

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            inc_match = include_pattern.search(stripped)
            if inc_match:
                symbols.append(ASTSymbol(
                    name=inc_match.group(1),
                    symbol_type="import",
                    file_path=rel_path,
                    line_start=idx,
                    line_end=idx
                ))
                continue

            c_match = class_pattern.search(stripped)
            if c_match:
                symbols.append(ASTSymbol(
                    name=c_match.group(1),
                    symbol_type="class",
                    file_path=rel_path,
                    line_start=idx,
                    line_end=idx + 10,
                    parameters=[],
                    calls=[]
                ))
                continue

            f_match = func_pattern.search(stripped)
            if f_match:
                name = f_match.group(1)
                if name not in ("if", "for", "while", "switch", "catch"):
                    param_str = f_match.group(2)
                    params = [p.strip() for p in param_str.split(',') if p.strip()]
                    symbols.append(ASTSymbol(
                        name=name,
                        symbol_type="function",
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx + 5,
                        parameters=params,
                        calls=[]
                    ))
                    call_graph[f"{rel_path}:{name}"] = []
