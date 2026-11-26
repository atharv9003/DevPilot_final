# DevPilot — Detection Engine Improvement & Architectural Enhancement Report

## 1. Architectural Overview & Design Principles

DevPilot is an autonomous multi-agent code review and debugging system architected around:
- **Hierarchical CrewAI Orchestration**: A central `CoordinatorAgent` dynamically dispatches inspection targets, coordinates inter-agent findings, and constructs the unified diagnostic report.
- **Specialized Google ADK & Rule-Based Agents**:
  1. `CodeUnderstandingAgent`: Discovers project topology, manifests, LOC, and language bindings.
  2. `StaticAnalysisAgent`: AST-driven syntactic, semantic, and logic flaw analysis.
  3. `SecurityAnalysisAgent`: OWASP Top 10, CWE-aligned vulnerability analysis, and secret leakage detection.
  4. `RuntimeAnalysisAgent`: Dynamic execution verification, exception safety, and dependency validation.
  5. `EvaluatorCriticAgent`: Grounded anti-hallucination verification, token/line matching, and deduplication.
- **A2A JSON-RPC 2.0 Communication Gateway**: Formal inter-agent messaging with cryptographic request-response validation.
- **Redis Blackboard Shared State**: Immutable audit trail, state snapshots, and atomic event recording.
- **Docker Isolated Testing Sandbox**: Execution of untrusted code inside `devpilot-sandbox:latest` with `--network none`, non-root execution, and read-only root mounts.

---

## 2. Core Detection Engine Deficiencies & Resolutions

### 2.1 From Hardcoded Heuristics to Generalized AST Visitors
The primary flaw identified during the audit was the reliance on hardcoded function names (e.g., `func_name == "add_product"`). The detection engine was refactored into a **generic visitor pattern**:
- **Expression-level analysis**: Instead of inspecting function identifiers, the AST scanner traverses language constructs (`ast.Compare`, `ast.Call`, `ast.BinOp`, `ast.Subscript`, `ast.FunctionDef`).
- **Data-flow context**: Checks inspect parent and child AST nodes to verify whether defensive checks (guards, try-except, null/zero checks) precede the potentially unsafe operation.
- **Cross-language generalization**: Language adapters for Python, JavaScript, TypeScript, Java, and C/C++ share consistent schema representation (`CodeIssue`) and classification taxonomy.

---

## 3. Detailed Agent-by-Agent Enhancements

### 3.1 Code Understanding Agent (`src/analysis/languages/manager.py`)
- **Multi-Language Manifest Discovery**:
  - Python: `pyproject.toml`, `requirements.txt`, `setup.py`
  - JavaScript: `package.json`, `package-lock.json`, `.eslintrc.json`
  - TypeScript: `tsconfig.json`, `package.json`
  - Java: `pom.xml`, `build.gradle`
  - C/C++: `CMakeLists.txt`, `Makefile`
- **Toolchain Health Discovery**: Probes runtime binaries (`node`, `tsc`, `javac`, `g++`, `docker`) and reports degraded operational status if a compiler is missing on the host PATH.
- **Cross-Drive Path Handling**: Enhanced `os.path.relpath` resolution with `try...except ValueError` to support cross-drive workspace references (e.g., `C:` temporary directories vs `E:` workspace storage).

### 3.2 Static Analysis Agent (`src/analysis/ast_scanner.py`)
- **Generalized Logic Rules**:
  - **Mutable Default Arguments**: Detects `def func(arg=[])` or `def func(arg={})` and flags state contamination risk (CWE-665).
  - **Numeric Range Order Inversion**: Verifies tuple unpacks of min/max or lo/hi boundaries to prevent inverted range logic.
  - **Unbounded Unit Verification**: Analyzes conditional branches returning `True` for specific units without numeric interval containment.
- **Bare Except Handlers**: Flags `except:` without an explicit exception class (CWE-391).
- **Off-By-One Boundary Checking**: Detects `<=` comparisons on collection `.size()` or `len()`.

### 3.3 Security Analysis Agent (`src/analysis/ast_scanner.py` & Language Adapters)
- **SSRF Substring Matching**: Identifies weak hostname containment (`domain in parsed_netloc`) susceptible to domain spoofing (CWE-20 / CWE-918).
- **Unvalidated HTTP Redirects**: Identifies `requests.Session.get()` or `requests.get()` without `allow_redirects=False` (CWE-601).
- **Path Traversal in File Operations**: Flags `open()`, `write_bytes()`, or `Path()` constructed via string concatenation or unvalidated variables (CWE-22).
- **SQL Injection**:
  - Python: String formatting (`%`, `.format()`, f-strings) inside `.execute()`.
  - JavaScript: Template string interpolation inside `.query()`.
  - Java: String concatenation inside `stmt.executeQuery()`.
- **Command Injection**:
  - Python: `subprocess.run(shell=True)` or `os.system()`.
  - JavaScript: `child_process.exec()` with concatenated strings.
  - Java: `Runtime.getRuntime().exec()` or `ProcessBuilder` with concatenated strings.
- **C/C++ Memory Safety**: Flags `gets()`, `strcpy()`, `sprintf()`, and unbalanced `malloc()`/`free()`.

### 3.4 Runtime & Dependency Analysis Agent
- **Dynamic Denominator ZeroDivisionError**:
  - Inspects `ast.BinOp(ast.Div)` where the denominator is an identifier (`ast.Name`) or function call (`ast.Call`).
  - Scans preceding lines in the enclosing function for defensive guards (`if total > 0:` or `if not v.empty():`).
  - Flags unprotected division with drop-in defensive guard replacements.
- **Cartesian Product Merge Detection**:
  - Inspects Pandas `df.merge()` calls lacking explicit `validate="many_to_one"` or pre-merge deduplication.
- **Chained Subscripting & JSON Handling**:
  - Identifies multi-level dictionary lookups (`obj["a"]["b"]`) without `.get()`.
  - Identifies `json.loads()` calls unshielded by `try...except json.JSONDecodeError`.

### 3.5 Evaluator / Critic Agent (`src/agents/google_adk/evaluator_critic_agent.py`)
- **Line & Token Grounding**: Every candidate finding must match actual lines of source code on disk. If line numbers or token references do not exist, the issue is rejected as a hallucination.
- **Defensive Guard Verification**: Before confirming a finding (e.g. Division by Zero), the critic searches for existing boundary guards in the file. If an appropriate guard is found, the finding is discarded as a False Positive.
- **Deduplication**: Merges duplicate reports from static AST and regex scanners targeting the same root cause.

---

## 4. Verification and Non-Regression Guarantee

All modifications were validated against the existing test suite:
- **Pytest Suite**: **22 out of 22 tests passing (100%)**
- **Execution Time**: 23.51s
- **Docker Sandbox Integration**: Verified operational under `devpilot-sandbox:latest`
- **Zero Hallucination Inflation**: Clean negative control samples (clean code) produced **0 false positives** in the updated benchmark.
