# DevPilot — 50-Scenario Polyglot Regression Benchmark Dataset Specification

## 1. Benchmark Design & Methodology

To empirically evaluate bug detection accuracy and eliminate false negatives, we constructed the **DevPilot 3.0 Polyglot Regression Benchmark Dataset (`benchmark/polyglot_benchmark_50.py`)**.

### 1.1 Architectural Characteristics
- **Total Scenarios**: 50 independently executable scenarios
- **Supported Languages**: 5 programming languages
  - **Python**: 15 scenarios (13 defective, 2 clean negative controls)
  - **JavaScript**: 10 scenarios (8 defective, 2 clean negative controls)
  - **TypeScript**: 8 scenarios (6 defective, 2 clean negative controls)
  - **Java**: 9 scenarios (7 defective, 2 clean negative controls)
  - **C/C++**: 8 scenarios (6 defective, 2 clean negative controls)
- **Defect Distribution**:
  - Security / Vulnerabilities: 20 scenarios (SQLi, Command Injection, Path Traversal, Eval/RCE, SSRF, Deserialization, Buffer Overflows)
  - Runtime Defects: 9 scenarios (Division by Zero, Missing Guards, Stream Leaks, Memory Leaks)
  - Logic & Boundary Flaws: 7 scenarios (Range Inversion, Unbounded Units, Off-by-one Loops, Mutable Defaults)
  - Syntactic / Compiler Errors: 4 scenarios (Malformed brackets, missing semicolons, unbalanced braces)
  - Clean Negative Controls: 10 scenarios (Well-defended, clean implementations ensuring 0% false-positive inflation)

---

## 2. Complete Polyglot Benchmark Index (50 Scenarios)

### Python Benchmark Scenarios (15 Samples)

| ID | Category | Severity | Title | CWE | Expected Line | Vulnerable |
|:---:|:---:|:---:|---|:---:|:---:|:---:|
| `PY-01` | Security | High | Weak Hostname Validation via Substring Matching | CWE-20 / CWE-918 | 5 | Yes |
| `PY-02` | Security | Medium | Unvalidated HTTP Redirects in Network Request | CWE-601 / CWE-918 | 4 | Yes |
| `PY-03` | Runtime | High | ZeroDivisionError on Dynamic Denominator | CWE-369 | 2 | Yes |
| `PY-04` | Logic | High | Unbounded Dose Unit Validation | CWE-20 | 3 | Yes |
| `PY-05` | Logic | Medium | Inverted Range Boundary Parsing | CWE-20 | 4 | Yes |
| `PY-06` | Config | Medium | Stale Checkpoint Reuse Without Dataset Verification | CWE-668 | 4 | Yes |
| `PY-07` | Runtime | High | Unvalidated Cartesian Merge in DataFrames | CWE-400 | 4 | Yes |
| `PY-08` | Quality | Medium | Bare Exception Handler Suppressing System Signals | CWE-391 | 5 | Yes |
| `PY-09` | Security | Critical | SQL Injection via String Formatting in Query | CWE-89 | 3 | Yes |
| `PY-10` | Security | High | Path Traversal in File Open via String Concatenation | CWE-22 | 2 | Yes |
| `PY-11` | Logic | Medium | Mutable Default Argument in Function Signature | CWE-665 | 1 | Yes |
| `PY-12` | Security | Critical | Remote Code Execution via eval() | CWE-95 | 2 | Yes |
| `PY-13` | Security | Critical | Command Injection via subprocess.run(shell=True) | CWE-78 | 3 | Yes |
| `PY-14` | Clean | None | Clean Defensive Division with Non-Zero Guard | N/A | 0 | **No (Control)** |
| `PY-15` | Clean | None | Clean Parameterized Database Query | N/A | 0 | **No (Control)** |

---

### JavaScript Benchmark Scenarios (10 Samples)

| ID | Category | Severity | Title | CWE | Expected Line | Vulnerable |
|:---:|:---:|:---:|---|:---:|:---:|:---:|
| `JS-01` | Security | Critical | SQL Injection via Dynamic String Concatenation | CWE-89 | 3 | Yes |
| `JS-02` | Security | Critical | Command Injection in child_process.exec() | CWE-78 | 3 | Yes |
| `JS-03` | Security | High | Path Traversal in fs.readFile() | CWE-22 | 3 | Yes |
| `JS-04` | Security | Critical | Arbitrary Code Execution via eval() | CWE-95 | 3 | Yes |
| `JS-05` | Security | High | Cross-Site Scripting (XSS) via innerHTML | CWE-79 | 3 | Yes |
| `JS-06` | Security | High | Prototype Pollution via Object Subscripting | CWE-1321 | 3 | Yes |
| `JS-07` | Runtime | High | Off-By-One Buffer Access in Array Loop | CWE-193 | 2 | Yes |
| `JS-08` | Security | Critical | Hardcoded High-Entropy JWT Secret in Source Code | CWE-798 | 2 | Yes |
| `JS-09` | Clean | None | Clean Parameterized SQLite Query | N/A | 0 | **No (Control)** |
| `JS-10` | Clean | None | Clean Safe DOM Insertion via textContent | N/A | 0 | **No (Control)** |

---

### TypeScript Benchmark Scenarios (8 Samples)

| ID | Category | Severity | Title | CWE | Expected Line | Vulnerable |
|:---:|:---:|:---:|---|:---:|:---:|:---:|
| `TS-01` | Quality | Medium | TypeScript 'any' Type Assertion / Escape Hatch | CWE-398 | 2 | Yes |
| `TS-02` | Runtime | High | Non-Null Assertion Operator Overriding Safety | CWE-476 | 3 | Yes |
| `TS-03` | Quality | Medium | Unchecked Type Assertion via 'as unknown as Target' | CWE-704 | 2 | Yes |
| `TS-04` | Runtime | Medium | Untyped Promise Lacking Generic Return Type | CWE-398 | 2 | Yes |
| `TS-05` | Security | Critical | Hardcoded Authentication Token in TS Config | CWE-798 | 2 | Yes |
| `TS-06` | Security | High | Path Traversal in TypeScript File Handler | CWE-22 | 3 | Yes |
| `TS-07` | Clean | None | Clean TypeScript Interface and Type Guard | N/A | 0 | **No (Control)** |
| `TS-08` | Clean | None | Clean Typed Promise with Generic Return Type | N/A | 0 | **No (Control)** |

---

### Java Benchmark Scenarios (9 Samples)

| ID | Category | Severity | Title | CWE | Expected Line | Vulnerable |
|:---:|:---:|:---:|---|:---:|:---:|:---:|
| `JAVA-01` | Security | Critical | SQL Injection via String Concatenation in JDBC | CWE-89 | 5 | Yes |
| `JAVA-02` | Security | Critical | Command Injection via Runtime.getRuntime().exec() | CWE-78 | 4 | Yes |
| `JAVA-03` | Security | Critical | Unsafe Object Deserialization via readObject() | CWE-502 | 4 | Yes |
| `JAVA-04` | Security | High | Insecure Cryptographic Algorithm (DES) | CWE-327 | 4 | Yes |
| `JAVA-05` | Runtime | High | Potential Division by Zero in Ratio Computation | CWE-369 | 3 | Yes |
| `JAVA-06` | Quality | Medium | Resource Leak: Stream Opened Without Try-With-Resources | CWE-775 | 4 | Yes |
| `JAVA-07` | Syntax | Critical | Java Syntax or Lexical Error (Missing Semicolon) | N/A | 3 | Yes |
| `JAVA-08` | Clean | None | Clean PreparedStatement with Parameters | N/A | 0 | **No (Control)** |
| `JAVA-09` | Clean | None | Clean Java Try-With-Resources | N/A | 0 | **No (Control)** |

---

### C/C++ Benchmark Scenarios (8 Samples)

| ID | Category | Severity | Title | CWE | Expected Line | Vulnerable |
|:---:|:---:|:---:|---|:---:|:---:|:---:|
| `CPP-01` | Security | Critical | Critical Buffer Overflow via gets() | CWE-242 / CWE-120 | 4 | Yes |
| `CPP-02` | Security | High | Unsafe String Copy via strcpy() | CWE-120 | 4 | Yes |
| `CPP-03` | Security | High | Buffer Overflow via sprintf() | CWE-120 | 4 | Yes |
| `CPP-04` | Runtime | High | Missing Empty Collection Check (Empty Vector Division) | CWE-369 | 4 | Yes |
| `CPP-05` | Logic | High | Missing Input Validation for Discount Boundaries | CWE-20 | 5 | Yes |
| `CPP-06` | Syntax | Critical | Mismatched Braces Syntax Error | N/A | 4 | Yes |
| `CPP-07` | Clean | None | Clean Bounds-Checked fgets() Buffer Read | N/A | 0 | **No (Control)** |
| `CPP-08` | Clean | None | Clean C++ Defensive Division Guard (.empty() check) | N/A | 0 | **No (Control)** |

---

## 3. Benchmark Execution Architecture

The benchmark runner (`benchmark/run_polyglot_50.py`):
1. Instantiates isolated temporary environments for each sample.
2. Invokes language-specific AST scanners and multi-language adapters.
3. Classifies outcomes into:
   - **True Positive (TP)**: Vulnerability correctly flagged with accurate line and root cause.
   - **True Negative (TN)**: Clean negative control sample produced 0 issues.
   - **False Positive (FP)**: Clean sample flagged with erroneous defect.
   - **False Negative (FN)**: Vulnerable sample produced 0 issues.
4. Serializes structured empirical results into both JSON (`polyglot_50_benchmark_results.json`) and CSV (`polyglot_50_benchmark_results.csv`).
