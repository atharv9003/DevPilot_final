"""
DevPilot 3.0 Polyglot Regression Benchmark Dataset (50 Curated Scenarios)
Comprehensive ground-truth benchmark across all 5 supported programming languages:
- Python (15 scenarios: security, runtime, logic, boundary, config, plus clean samples)
- JavaScript (10 scenarios: SQLi, cmd injection, path traversal, eval, XSS, prototype pollution, off-by-one, clean)
- TypeScript (8 scenarios: any escape hatch, non-null assertion, forced cast, untyped promise, clean)
- Java (9 scenarios: JDBC concatenation, Runtime.exec, stream leaks, division by zero, hardcoded secrets, clean)
- C/C++ (8 scenarios: gets, strcpy, buffer overflow, empty vector division, discount boundary, clean)

Total: 50 Scenarios with Ground Truth Labels, Expected Vulnerabilities, and Clean Baselines.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class PolyglotBenchmarkSample(BaseModel):
    id: str
    language: str
    category: str  # 'security', 'runtime', 'logic', 'config', 'clean'
    title: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'none'
    cwe: Optional[str] = None
    expected_line: int
    is_vulnerable: bool  # True for defect samples, False for clean negative control samples
    code_content: str
    description: str
    expected_root_cause: str


def get_50_polyglot_benchmark_samples() -> List[PolyglotBenchmarkSample]:
    samples: List[PolyglotBenchmarkSample] = []

    # ==========================================
    # 1. PYTHON BENCHMARK SAMPLES (15 Samples)
    # ==========================================
    # PY-01: Weak Hostname Substring Validation (SSRF)
    samples.append(PolyglotBenchmarkSample(
        id="PY-01", language="Python", category="security", severity="high",
        cwe="CWE-20 / CWE-918", expected_line=5, is_vulnerable=True,
        title="Weak Hostname Validation via Substring Matching",
        code_content="from urllib.parse import urlparse\ndef is_trusted(url):\n    parsed = urlparse(url).netloc\n    for domain in ['health.org', 'ayur.gov']:\n        if domain in parsed:\n            return True\n    return False\n",
        description="Uses substring containment ('domain in parsed') allowing evil-health.org to pass validation.",
        expected_root_cause="Substring check on netloc allows attacker-controlled domain suffixes."
    ))

    # PY-02: Unvalidated HTTP Redirects
    samples.append(PolyglotBenchmarkSample(
        id="PY-02", language="Python", category="security", severity="medium",
        cwe="CWE-601 / CWE-918", expected_line=4, is_vulnerable=True,
        title="Unvalidated HTTP Redirects in Network Request",
        code_content="import requests\ndef safe_get(url):\n    session = requests.Session()\n    return session.get(url, timeout=10).text\n",
        description="Session.get called without allow_redirects=False or redirect target validation.",
        expected_root_cause="Defaulting allow_redirects=True allows silent SSRF off trusted host."
    ))

    # PY-03: Zero Division on Dynamic Denominator
    samples.append(PolyglotBenchmarkSample(
        id="PY-03", language="Python", category="runtime", severity="high",
        cwe="CWE-369", expected_line=4, is_vulnerable=True,
        title="ZeroDivisionError on Empty Total Count",
        code_content="def compute_accuracy(correct, total):\n    ratio = correct / total\n    return ratio * 100\n",
        description="Direct division by 'total' parameter without checking total > 0.",
        expected_root_cause="Empty input or 0 total raises ZeroDivisionError."
    ))

    # PY-04: Unbounded Quantity Extraction
    samples.append(PolyglotBenchmarkSample(
        id="PY-04", language="Python", category="logic", severity="high",
        cwe="CWE-20", expected_line=3, is_vulnerable=True,
        title="Unbounded Dose Unit Validation",
        code_content="def validate_dose(val, unit):\n    if unit == 'tsp':\n        return True\n    return 0 < val <= 50\n",
        description="Returns True unconditionally for 'tsp' unit without upper bounds.",
        expected_root_cause="Absurd quantities like 500 tsp are accepted as valid dosage."
    ))

    # PY-05: Range Boundary Ordering Inversion
    samples.append(PolyglotBenchmarkSample(
        id="PY-05", language="Python", category="logic", severity="medium",
        cwe="CWE-20", expected_line=4, is_vulnerable=True,
        title="Inverted Range Boundary Parsing",
        code_content="def parse_range(groups):\n    lo, hi = float(groups[0]), float(groups[1])\n    return f'{lo}-{hi} mg'\n",
        description="Unpacks range boundaries without asserting lo <= hi.",
        expected_root_cause="Inverted input text produces invalid negative or upside-down range."
    ))

    # PY-06: Unvalidated DataFrame Merge
    samples.append(PolyglotBenchmarkSample(
        id="PY-06", language="Python", category="runtime", severity="high",
        cwe="CWE-400", expected_line=4, is_vulnerable=True,
        title="Unvalidated DataFrame Merge on Non-Unique Keys",
        code_content="import pandas as pd\ndef merge_datasets(base_df, enriched_df):\n    return base_df.merge(enriched_df, on='name', how='left')\n",
        description="Performs left merge without validate='many_to_one'.",
        expected_root_cause="Duplicate keys trigger Cartesian row multiplication."
    ))

    # PY-07: SQL Injection via String Format
    samples.append(PolyglotBenchmarkSample(
        id="PY-07", language="Python", category="security", severity="critical",
        cwe="CWE-89", expected_line=3, is_vulnerable=True,
        title="SQL Injection via Format String",
        code_content="def find_user(cursor, user_id):\n    query = f'SELECT * FROM users WHERE id = {user_id}'\n    cursor.execute(query)\n",
        description="Dynamic string formatting used inside database query.",
        expected_root_cause="User input concatenated directly into SQL statement."
    ))

    # PY-08: Command Injection via os.system
    samples.append(PolyglotBenchmarkSample(
        id="PY-08", language="Python", category="security", severity="critical",
        cwe="CWE-78", expected_line=3, is_vulnerable=True,
        title="Command Injection via os.system",
        code_content="import os\ndef ping_host(host):\n    os.system('ping -c 1 ' + host)\n",
        description="Unsanitized host string passed to system shell.",
        expected_root_cause="Arbitrary shell command execution."
    ))

    # PY-09: Unsafe Deserialization via pickle
    samples.append(PolyglotBenchmarkSample(
        id="PY-09", language="Python", category="security", severity="critical",
        cwe="CWE-502", expected_line=3, is_vulnerable=True,
        title="Unsafe Deserialization via pickle",
        code_content="import pickle\ndef load_data(raw_bytes):\n    return pickle.loads(raw_bytes)\n",
        description="Direct unpickling of untrusted bytes.",
        expected_root_cause="Arbitrary code execution on deserialization."
    ))

    # PY-10: Path Traversal in File Open
    samples.append(PolyglotBenchmarkSample(
        id="PY-10", language="Python", category="security", severity="high",
        cwe="CWE-22", expected_line=3, is_vulnerable=True,
        title="Path Traversal in File Open",
        code_content="def read_report(filename):\n    with open('/var/reports/' + filename, 'r') as f:\n        return f.read()\n",
        description="Concatenating unverified filename to base directory path.",
        expected_root_cause="Directory traversal via '../' characters."
    ))

    # PY-11: Mutable Default Argument
    samples.append(PolyglotBenchmarkSample(
        id="PY-11", language="Python", category="logic", severity="medium",
        cwe="CWE-665", expected_line=1, is_vulnerable=True,
        title="Mutable Default Argument in Function Signature",
        code_content="def append_item(val, target=[]):\n    target.append(val)\n    return target\n",
        description="Default list argument is evaluated once at module load.",
        expected_root_cause="Shared state across independent calls."
    ))

    # PY-12: Hardcoded API Secret
    samples.append(PolyglotBenchmarkSample(
        id="PY-12", language="Python", category="security", severity="critical",
        cwe="CWE-798", expected_line=1, is_vulnerable=True,
        title="Hardcoded API Secret in Source Code",
        code_content="API_KEY = 'AIzaSyD-1234567890abcdefghijklmn'\ndef get_key():\n    return API_KEY\n",
        description="Sensitive API key committed directly to file.",
        expected_root_cause="Credential harvesting risk."
    ))

    # PY-13: Stale Checkpoint Reuse Without Fingerprint
    samples.append(PolyglotBenchmarkSample(
        id="PY-13", language="Python", category="config", severity="medium",
        cwe="CWE-345", expected_line=3, is_vulnerable=True,
        title="Stale Checkpoint Loading Without Validation",
        code_content="import json, os\ndef load_checkpoint():\n    if os.path.exists('checkpoint.json'):\n        with open('checkpoint.json') as f: return json.load(f)\n    return {}\n",
        description="Loads checkpoint without verifying source hash or schema.",
        expected_root_cause="Stale data reused across modified configurations."
    ))

    # PY-14: Clean Python Negative Control Sample (No Defect)
    samples.append(PolyglotBenchmarkSample(
        id="PY-14", language="Python", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean Python Safe Function (Negative Control)",
        code_content="def calculate_total(prices: list[float]) -> float:\n    if not prices:\n        return 0.0\n    return sum(prices)\n",
        description="Safe, defensive aggregation with empty list guard.",
        expected_root_cause="No defect present."
    ))

    # PY-15: Clean Python Secure Hostname Validation (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="PY-15", language="Python", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean Python Strict Domain Check (Negative Control)",
        code_content="from urllib.parse import urlparse\nTRUSTED = {'example.com', 'api.example.com'}\ndef is_safe_domain(url: str) -> bool:\n    netloc = urlparse(url).netloc.split(':')[0].lower()\n    return netloc in TRUSTED\n",
        description="Strict set containment on parsed netloc.",
        expected_root_cause="No defect present."
    ))

    # ==========================================
    # 2. JAVASCRIPT BENCHMARK SAMPLES (10 Samples)
    # ==========================================
    # JS-01: SQL Injection
    samples.append(PolyglotBenchmarkSample(
        id="JS-01", language="JavaScript", category="security", severity="critical",
        cwe="CWE-89", expected_line=3, is_vulnerable=True,
        title="SQL Injection via Template Concatenation in Node.js",
        code_content="function getUser(req, db) {\n    const id = req.body.id;\n    return db.query('SELECT * FROM users WHERE id = ' + id);\n}\n",
        description="Concatenating user input directly into SQL query.",
        expected_root_cause="SQL injection vulnerability."
    ))

    # JS-02: Command Injection
    samples.append(PolyglotBenchmarkSample(
        id="JS-02", language="JavaScript", category="security", severity="critical",
        cwe="CWE-78", expected_line=3, is_vulnerable=True,
        title="Command Injection via child_process.exec",
        code_content="const { exec } = require('child_process');\nfunction runScript(param) {\n    exec('sh run.sh ' + param);\n}\n",
        description="Untrusted parameter passed to shell execution.",
        expected_root_cause="Arbitrary shell execution."
    ))

    # JS-03: Path Traversal
    samples.append(PolyglotBenchmarkSample(
        id="JS-03", language="JavaScript", category="security", severity="high",
        cwe="CWE-22", expected_line=3, is_vulnerable=True,
        title="Path Traversal in fs.readFileSync",
        code_content="const fs = require('fs');\nfunction readData(filename) {\n    return fs.readFileSync('/data/' + filename);\n}\n",
        description="Direct concatenation into file read operation.",
        expected_root_cause="Path traversal outside safe folder."
    ))

    # JS-04: Insecure eval()
    samples.append(PolyglotBenchmarkSample(
        id="JS-04", language="JavaScript", category="security", severity="critical",
        cwe="CWE-95", expected_line=2, is_vulnerable=True,
        title="Insecure Dynamic Code Execution via eval()",
        code_content="function calculate(expression) {\n    return eval(expression);\n}\n",
        description="Dynamic string evaluation with eval.",
        expected_root_cause="Remote code execution."
    ))

    # JS-05: DOM XSS
    samples.append(PolyglotBenchmarkSample(
        id="JS-05", language="JavaScript", category="security", severity="high",
        cwe="CWE-79", expected_line=2, is_vulnerable=True,
        title="Cross-Site Scripting via innerHTML",
        code_content="function renderUser(name) {\n    document.getElementById('profile').innerHTML = '<h1>' + name + '</h1>';\n}\n",
        description="Direct assignment to innerHTML.",
        expected_root_cause="Client-side DOM XSS."
    ))

    # JS-06: Hardcoded Token
    samples.append(PolyglotBenchmarkSample(
        id="JS-06", language="JavaScript", category="security", severity="critical",
        cwe="CWE-798", expected_line=1, is_vulnerable=True,
        title="Hardcoded API Secret in JavaScript",
        code_content="const apiKey = 'AIzaSyD-9876543210zyxwvutsrqp';\nfunction getKey() { return apiKey; }\n",
        description="Hardcoded credential in source file.",
        expected_root_cause="Key compromise."
    ))

    # JS-07: Off-By-One Array Boundary Loop
    samples.append(PolyglotBenchmarkSample(
        id="JS-07", language="JavaScript", category="runtime", severity="high",
        cwe="CWE-125", expected_line=2, is_vulnerable=True,
        title="Off-By-One Array Boundary Violation in Loop",
        code_content="function printItems(arr) {\n    for (let i = 0; i <= arr.length; i++) {\n        console.log(arr[i]);\n    }\n}\n",
        description="Loop condition iterates up to <= length accessing undefined index.",
        expected_root_cause="Reading arr[length] yields undefined."
    ))

    # JS-08: Prototype Pollution
    samples.append(PolyglotBenchmarkSample(
        id="JS-08", language="JavaScript", category="security", severity="high",
        cwe="CWE-1321", expected_line=2, is_vulnerable=True,
        title="Prototype Pollution Vulnerability",
        code_content="function setProp(target, key, val) {\n    target.__proto__[key] = val;\n}\n",
        description="Direct mutation of __proto__ object.",
        expected_root_cause="Prototype pollution leading to logic bypass."
    ))

    # JS-09: Clean JavaScript Function (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="JS-09", language="JavaScript", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean JavaScript Parameterized DB Query (Negative Control)",
        code_content="function getUser(db, userId) {\n    return db.query('SELECT * FROM users WHERE id = ?', [userId]);\n}\n",
        description="Parameterized database query placeholder.",
        expected_root_cause="No defect present."
    ))

    # JS-10: Clean JavaScript Safe DOM Update (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="JS-10", language="JavaScript", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean JavaScript textContent Rendering (Negative Control)",
        code_content="function renderSafe(element, text) {\n    element.textContent = text;\n}\n",
        description="Safe assignment to textContent preventing HTML execution.",
        expected_root_cause="No defect present."
    ))

    # ==========================================
    # 3. TYPESCRIPT BENCHMARK SAMPLES (8 Samples)
    # ==========================================
    # TS-01: 'any' Type Assertion Escape Hatch
    samples.append(PolyglotBenchmarkSample(
        id="TS-01", language="TypeScript", category="quality", severity="medium",
        cwe="CWE-699", expected_line=1, is_vulnerable=True,
        title="TypeScript 'any' Type Escape Hatch",
        code_content="function processData(payload: any): any {\n    return payload.user.id;\n}\n",
        description="Using 'any' disables compile-time type safety.",
        expected_root_cause="Type safety evasion leading to runtime TypeError."
    ))

    # TS-02: Unsafe Non-Null Assertion Operator (!)
    samples.append(PolyglotBenchmarkSample(
        id="TS-02", language="TypeScript", category="quality", severity="medium",
        cwe="CWE-476", expected_line=2, is_vulnerable=True,
        title="Unsafe Non-Null Assertion Operator (!)",
        code_content="interface User { profile?: { email: string } }\nfunction getEmail(u: User): string {\n    return u.profile!.email;\n}\n",
        description="Non-null assertion on optional property.",
        expected_root_cause="Dereferencing undefined profile raises TypeError."
    ))

    # TS-03: Forced Type Cast Bypass (as unknown as T)
    samples.append(PolyglotBenchmarkSample(
        id="TS-03", language="TypeScript", category="quality", severity="medium",
        cwe="CWE-704", expected_line=2, is_vulnerable=True,
        title="Forced Type Cast Bypass (as unknown as T)",
        code_content="function coerceType(val: number): string {\n    return (val as unknown as string);\n}\n",
        description="Double casting defeats TypeScript type checks.",
        expected_root_cause="Invalid runtime type assumptions."
    ))

    # TS-04: TypeScript SQL Injection
    samples.append(PolyglotBenchmarkSample(
        id="TS-04", language="TypeScript", category="security", severity="critical",
        cwe="CWE-89", expected_line=3, is_vulnerable=True,
        title="SQL Injection via Template String in TypeScript",
        code_content="import { Database } from './db';\nfunction findOrder(db: Database, orderId: string) {\n    return db.query(`SELECT * FROM orders WHERE id = '${orderId}'`);\n}\n",
        description="Template literal interpolation in database query.",
        expected_root_cause="SQL injection."
    ))

    # TS-05: TypeScript Command Injection
    samples.append(PolyglotBenchmarkSample(
        id="TS-05", language="TypeScript", category="security", severity="critical",
        cwe="CWE-78", expected_line=3, is_vulnerable=True,
        title="Command Injection in TypeScript child_process",
        code_content="import { exec } from 'child_process';\nfunction execute(cmd: string) {\n    exec('bash ' + cmd);\n}\n",
        description="Concatenating command line arguments.",
        expected_root_cause="Arbitrary shell command execution."
    ))

    # TS-06: TypeScript Insecure eval
    samples.append(PolyglotBenchmarkSample(
        id="TS-06", language="TypeScript", category="security", severity="critical",
        cwe="CWE-95", expected_line=2, is_vulnerable=True,
        title="Insecure Code Execution via eval in TypeScript",
        code_content="function runCode(code: string): void {\n    eval(code);\n}\n",
        description="Direct invocation of eval.",
        expected_root_cause="Remote code execution."
    ))

    # TS-07: Clean TypeScript Typed Interface (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="TS-07", language="TypeScript", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean TypeScript Strict Type Safety (Negative Control)",
        code_content="interface Config { host: string; port: number }\nfunction init(c: Config): string {\n    return `${c.host}:${c.port}`;\n}\n",
        description="Well-typed configuration structure with zero any escapes.",
        expected_root_cause="No defect present."
    ))

    # TS-08: Clean TypeScript Safe Null Check (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="TS-08", language="TypeScript", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean TypeScript Optional Chaining Guard (Negative Control)",
        code_content="interface Profile { email?: string }\nfunction getEmailSafe(p?: Profile): string {\n    return p?.email ?? 'no-email';\n}\n",
        description="Defensive optional chaining and nullish coalescing.",
        expected_root_cause="No defect present."
    ))

    # ==========================================
    # 4. JAVA BENCHMARK SAMPLES (9 Samples)
    # ==========================================
    # JAVA-01: SQL Injection via Statement Concatenation
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-01", language="Java", category="security", severity="critical",
        cwe="CWE-89", expected_line=4, is_vulnerable=True,
        title="SQL Injection via String Concatenation in JDBC Statement",
        code_content="import java.sql.*;\npublic class UserDAO {\n    public void findUser(Connection conn, String id) throws Exception {\n        Statement stmt = conn.createStatement();\n        ResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE id = '\" + id + \"'\");\n    }\n}\n",
        description="Direct concatenation of variable in JDBC Statement query.",
        expected_root_cause="SQL injection."
    ))

    # JAVA-02: Command Injection via Runtime.exec
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-02", language="Java", category="security", severity="critical",
        cwe="CWE-78", expected_line=3, is_vulnerable=True,
        title="Command Injection via Runtime.exec",
        code_content="public class SystemRunner {\n    public void execute(String param) throws Exception {\n        Runtime.getRuntime().exec(\"sh -c \" + param);\n    }\n}\n",
        description="Concatenating untrusted parameter into shell execution.",
        expected_root_cause="Arbitrary command execution on host."
    ))

    # JAVA-03: Resource Leak (Unclosed FileInputStream)
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-03", language="Java", category="runtime", severity="medium",
        cwe="CWE-775", expected_line=4, is_vulnerable=True,
        title="Resource Leak: Stream Opened Without Try-With-Resources",
        code_content="import java.io.*;\npublic class FileLoader {\n    public void readData(File file) throws Exception {\n        FileInputStream fis = new FileInputStream(file);\n        fis.read();\n    }\n}\n",
        description="Stream opened without try-with-resources or close block.",
        expected_root_cause="File descriptor exhaustion under high load."
    ))

    # JAVA-04: Path Traversal in File Constructor
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-04", language="Java", category="security", severity="high",
        cwe="CWE-22", expected_line=3, is_vulnerable=True,
        title="Path Traversal in Java File Access",
        code_content="import java.io.File;\npublic class StorageService {\n    public File getFile(String filename) {\n        return new File(\"/var/data/\", filename);\n    }\n}\n",
        description="File object constructed from external string without canonical verification.",
        expected_root_cause="Arbitrary filesystem read/write outside base directory."
    ))

    # JAVA-05: Hardcoded Secret
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-05", language="Java", category="security", severity="critical",
        cwe="CWE-798", expected_line=2, is_vulnerable=True,
        title="Hardcoded Credentials or Secrets in Java Class",
        code_content="public class AuthService {\n    private static final String secret = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\";\n}\n",
        description="Static final hardcoded credential.",
        expected_root_cause="Token leakage."
    ))

    # JAVA-06: Off-by-one Loop Boundary
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-06", language="Java", category="runtime", severity="high",
        cwe="CWE-125", expected_line=3, is_vulnerable=True,
        title="Off-By-One Array Boundary in Java Loop",
        code_content="public class ArrayIter {\n    public void iterate(int[] arr) {\n        for (int i = 0; i <= arr.length; i++) {\n            System.out.println(arr[i]);\n        }\n    }\n}\n",
        description="Iterating with <= arr.length.",
        expected_root_cause="ArrayIndexOutOfBoundsException."
    ))

    # JAVA-07: Java Syntax Error
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-07", language="Java", category="syntax", severity="critical",
        cwe="CWE-699", expected_line=2, is_vulnerable=True,
        title="Java Syntax or Lexical Error",
        code_content="public class BrokenClass {\n    public void test() {\n        int x = 5\n    }\n}\n",
        description="Missing semicolon in Java statement.",
        expected_root_cause="Compilation error."
    ))

    # JAVA-08: Clean Java PreparedStatement (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-08", language="Java", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean Java Parameterized PreparedStatement (Negative Control)",
        code_content="import java.sql.*;\npublic class SafeUserDAO {\n    public void findUser(Connection conn, String id) throws Exception {\n        PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n        ps.setString(1, id);\n        ResultSet rs = ps.executeQuery();\n    }\n}\n",
        description="Safe PreparedStatement with parameter placeholder.",
        expected_root_cause="No defect present."
    ))

    # JAVA-09: Clean Java Try-With-Resources (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="JAVA-09", language="Java", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean Java Try-With-Resources (Negative Control)",
        code_content="import java.io.*;\npublic class SafeFileLoader {\n    public void readData(File file) throws Exception {\n        try (FileInputStream fis = new FileInputStream(file)) {\n            fis.read();\n        }\n    }\n}\n",
        description="Automatic stream closure via try-with-resources block.",
        expected_root_cause="No defect present."
    ))

    # ==========================================
    # 5. C/C++ BENCHMARK SAMPLES (8 Samples)
    # ==========================================
    # CPP-01: Dangerous gets() buffer overflow
    samples.append(PolyglotBenchmarkSample(
        id="CPP-01", language="C/C++", category="security", severity="critical",
        cwe="CWE-120", expected_line=3, is_vulnerable=True,
        title="Buffer Overflow via Deprecated gets() Function",
        code_content="#include <stdio.h>\nvoid read_user() {\n    char buf[32];\n    gets(buf);\n}\n",
        description="Unbounded input read using gets().",
        expected_root_cause="Buffer overflow and stack corruption."
    ))

    # CPP-02: Unsafe strcpy()
    samples.append(PolyglotBenchmarkSample(
        id="CPP-02", language="C/C++", category="security", severity="critical",
        cwe="CWE-120", expected_line=4, is_vulnerable=True,
        title="Unsafe Memory Copy via strcpy()",
        code_content="#include <string.h>\nvoid copy_data(const char* src) {\n    char dest[16];\n    strcpy(dest, src);\n}\n",
        description="Memory copy without bounds checking.",
        expected_root_cause="Heap/stack buffer overwrite."
    ))

    # CPP-03: Division by Empty Collection size()
    samples.append(PolyglotBenchmarkSample(
        id="CPP-03", language="C/C++", category="runtime", severity="high",
        cwe="CWE-369", expected_line=5, is_vulnerable=True,
        title="Missing Empty Collection Check Before Division",
        code_content="#include <vector>\n#include <numeric>\ndouble average(const std::vector<double>& prices) {\n    double sum = std::accumulate(prices.begin(), prices.end(), 0.0);\n    return sum / prices.size();\n}\n",
        description="Dividing by prices.size() without prices.empty() check.",
        expected_root_cause="Division by zero producing NaN."
    ))

    # CPP-04: Missing Input Boundary Validation for Discount
    samples.append(PolyglotBenchmarkSample(
        id="CPP-04", language="C/C++", category="logic", severity="high",
        cwe="CWE-20", expected_line=2, is_vulnerable=True,
        title="Missing Input Validation for Discount and Price Boundaries",
        code_content="double calculate_discounted_price(double price, double discount_percent) {\n    return price * (1.0 - (discount_percent / 100.0));\n}\n",
        description="Lacks validation for negative price or discount > 100.",
        expected_root_cause="Negative billing and revenue loss."
    ))

    # CPP-05: Command Injection via system()
    samples.append(PolyglotBenchmarkSample(
        id="CPP-05", language="C/C++", category="security", severity="critical",
        cwe="CWE-78", expected_line=4, is_vulnerable=True,
        title="Command Injection via system() Call",
        code_content="#include <cstdlib>\nvoid run_backup(const char* cmd) {\n    char command[128];\n    system(cmd);\n}\n",
        description="Passing unverified command to system().",
        expected_root_cause="Arbitrary command execution."
    ))

    # CPP-06: Mismatched Bracket Syntax Error
    samples.append(PolyglotBenchmarkSample(
        id="CPP-06", language="C/C++", category="syntax", severity="critical",
        cwe="CWE-699", expected_line=3, is_vulnerable=True,
        title="Mismatched Braces or Parentheses Syntax Error",
        code_content="#include <iostream>\nint main() {\n    std::cout << \"Hello World\";\n",
        description="Unclosed curly brace in C++ file.",
        expected_root_cause="Compilation syntax failure."
    ))

    # CPP-07: Clean C++ Safe String Copy (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="CPP-07", language="C/C++", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean C++ Safe snprintf Copy (Negative Control)",
        code_content="#include <cstdio>\nvoid copy_safe(const char* src) {\n    char dest[32];\n    snprintf(dest, sizeof(dest), \"%s\", src);\n}\n",
        description="Bounded string formatting using sizeof(dest).",
        expected_root_cause="No defect present."
    ))

    # CPP-08: Clean C++ Empty Vector Guard (Negative Control)
    samples.append(PolyglotBenchmarkSample(
        id="CPP-08", language="C/C++", category="clean", severity="none",
        cwe=None, expected_line=0, is_vulnerable=False,
        title="Clean C++ Defensive Division Guard (Negative Control)",
        code_content="#include <vector>\n#include <numeric>\ndouble average_safe(const std::vector<double>& v) {\n    if (v.empty()) return 0.0;\n    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();\n}\n",
        description="Defensive guard returning 0.0 before division.",
        expected_root_cause="No defect present."
    ))

    return samples
