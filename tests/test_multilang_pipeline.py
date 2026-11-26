"""
DevPilot Multi-Language Inspection & Verification Test Suite
Tests language detection, manifests, toolchains, and multi-agent pipeline across
Python, JavaScript, TypeScript, Java, and C/C++.
"""
import pytest
import os
import shutil
from src.analysis.languages.manager import MultiLanguageManager
from src.agents.crewai.coordinator import CoordinatorAgent
from src.mcp_tools.ast_parser import ASTParserTool
from src.analysis.corrector import AutonomousCodeCorrector
from src.agents.google_adk.runtime_dependency_agent import RuntimeDependencyAgent


def test_toolchain_discovery():
    """Verifies that all 5 language adapters report accurate toolchains without fabrication."""
    mgr = MultiLanguageManager()
    summary = mgr.get_toolchain_summary()

    assert "Python" in summary
    assert "JavaScript" in summary
    assert "TypeScript" in summary
    assert "Java" in summary
    assert "C/C++" in summary

    assert summary["Python"]["available"] is True
    assert summary["JavaScript"]["available"] is True
    assert summary["TypeScript"]["available"] is True
    assert summary["Java"]["available"] is True
    assert summary["C/C++"]["available"] is True


def test_language_and_manifest_detection(tmp_path):
    """Verifies language identification using extensions, manifests, and deep content inspection."""
    mgr = MultiLanguageManager()

    assert mgr.detect_file_language("server.js") == "JavaScript"
    assert mgr.detect_file_language("handler.ts") == "TypeScript"
    assert mgr.detect_file_language("App.tsx") == "TypeScript"
    assert mgr.detect_file_language("Service.java") == "Java"
    assert mgr.detect_file_language("main.cpp") == "C/C++"
    assert mgr.detect_file_language("header.h") == "C/C++"
    assert mgr.detect_file_language("script.py") == "Python"

    # Manifest detection
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text('{"name": "test-app"}', encoding="utf-8")
    assert mgr.detect_file_language(str(pkg_json)) == "JavaScript"

    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text('flask>=2.0', encoding="utf-8")
    assert mgr.detect_file_language(str(req_txt)) == "Python"

    # Deep content inspection without extension
    cpp_no_ext = tmp_path / "cpp_source"
    cpp_no_ext.write_text('#include <iostream>\nint main() { std::cout << "Hello"; return 0; }', encoding="utf-8")
    assert mgr.detect_file_language(str(cpp_no_ext)) == "C/C++"

    java_no_ext = tmp_path / "java_source"
    java_no_ext.write_text('package com.devpilot;\npublic class Worker { public static void main(String[] args) {} }', encoding="utf-8")
    assert mgr.detect_file_language(str(java_no_ext)) == "Java"


def test_ast_parser_multilang_no_false_syntax_errors():
    """Verifies ASTParserTool extracts symbols from C++ and Java without raising Python SyntaxError."""
    cpp_path = os.path.abspath("devpilot_repos/devpilot_fixture_cpp_parser.cpp")
    tool = ASTParserTool(cpp_path)
    res = tool.analyze_repository()
    assert len(res.syntax_errors) == 0
    assert len(res.symbols) >= 5

    java_path = os.path.abspath("devpilot_repos/devpilot_fixture_java_service.java")
    tool_java = ASTParserTool(java_path)
    res_java = tool_java.analyze_repository()
    assert len(res_java.syntax_errors) == 0
    assert len(res_java.symbols) >= 5


def test_non_python_patch_generation_no_python_imports():
    """Verifies that generated patches for C++, Java, and JS never inject Python imports or Python syntax."""
    corrector = AutonomousCodeCorrector()
    coord = CoordinatorAgent()

    # 1. C++
    cpp_path = os.path.abspath("devpilot_repos/devpilot_fixture_cpp_parser.cpp")
    report_cpp = coord.run_full_inspection(cpp_path)
    with open(cpp_path, "r", encoding="utf-8") as f:
        cpp_orig = f.read()
    cpp_corrected = corrector.generate_corrected_file(cpp_orig, report_cpp.issues)
    assert "import os" not in cpp_corrected
    assert "import ast" not in cpp_corrected
    assert "os.getenv" not in cpp_corrected

    # 2. JavaScript
    js_path = os.path.abspath("devpilot_repos/devpilot_fixture_js_ecommerce.js")
    report_js = coord.run_full_inspection(js_path)
    with open(js_path, "r", encoding="utf-8") as f:
        js_orig = f.read()
    js_corrected = corrector.generate_corrected_file(js_orig, report_js.issues)
    assert "import os" not in js_corrected
    assert "import ast" not in js_corrected
    assert "os.getenv" not in js_corrected

    # 3. Java
    java_path = os.path.abspath("devpilot_repos/devpilot_fixture_java_service.java")
    report_java = coord.run_full_inspection(java_path)
    with open(java_path, "r", encoding="utf-8") as f:
        java_orig = f.read()
    java_corrected = corrector.generate_corrected_file(java_orig, report_java.issues)
    assert "import os" not in java_corrected
    assert "import ast" not in java_corrected


def test_multi_agent_inspection_javascript():
    """Executes full multi-agent inspection on JavaScript benchmark fixture."""
    coord = CoordinatorAgent()
    js_path = os.path.abspath("devpilot_repos/devpilot_fixture_js_ecommerce.js")
    report = coord.run_full_inspection(js_path)

    assert report.total_issues >= 4
    categories = {i.category for i in report.issues}
    assert "security" in categories

    for issue in report.issues:
        assert issue.language == "JavaScript"
        assert len(issue.what_is_wrong) > 0
        assert len(issue.corrected_code) > 0


def test_multi_agent_inspection_typescript():
    """Executes full multi-agent inspection on TypeScript benchmark fixture."""
    coord = CoordinatorAgent()
    ts_path = os.path.abspath("devpilot_repos/devpilot_fixture_ts_api.ts")
    report = coord.run_full_inspection(ts_path)

    assert report.total_issues >= 3
    for issue in report.issues:
        assert issue.language == "TypeScript"


def test_multi_agent_inspection_java():
    """Executes full multi-agent inspection on Java benchmark fixture."""
    coord = CoordinatorAgent()
    java_path = os.path.abspath("devpilot_repos/devpilot_fixture_java_service.java")
    report = coord.run_full_inspection(java_path)

    assert report.total_issues >= 5
    for issue in report.issues:
        assert issue.language == "Java"


def test_multi_agent_inspection_cpp():
    """Executes full multi-agent inspection on C/C++ benchmark fixture."""
    coord = CoordinatorAgent()
    cpp_path = os.path.abspath("devpilot_repos/devpilot_fixture_cpp_parser.cpp")
    report = coord.run_full_inspection(cpp_path)

    assert report.total_issues >= 5
    for issue in report.issues:
        assert issue.language == "C/C++"


def test_apply_fixes_to_copy_multilang(tmp_path):
    """Verifies that apply_fixes_to_copy copies and patches non-Python files properly."""
    corrector = AutonomousCodeCorrector()
    coord = CoordinatorAgent()

    cpp_path = os.path.abspath("devpilot_repos/devpilot_fixture_cpp_parser.cpp")
    report = coord.run_full_inspection(cpp_path)

    dest_file = str(tmp_path / "cpp_corrected.cpp")
    verified_issues = [issue.model_copy(update={"verified": True}) for issue in report.issues]
    out = corrector.apply_fixes_to_copy(cpp_path, verified_issues, destination_path=dest_file)
    assert os.path.exists(out)
    with open(out, "r", encoding="utf-8") as f:
        patched = f.read()
    assert "import os" not in patched
    assert "fgets" in patched or "strncpy" in patched


def test_cplusplus_code_review_two_bugs_e2e():
    """Verifies that code_review_two_bugs.cpp detects both defects and verifies both patches."""
    coord = CoordinatorAgent()
    cpp_path = os.path.abspath("devpilot_repos/code_review_two_bugs.cpp")
    report = coord.run_full_inspection(cpp_path)

    assert report.total_issues == 2
    if report.tests_summary["sandbox_tested"]:
        assert report.verified_patches == 2
    else:
        assert report.verified_patches == 0
        assert report.tests_summary["overall_passed"] is False

    titles = [i.title for i in report.issues]
    assert any("Empty Collection" in t or "Division" in t for t in titles)
    assert any("Discount" in t or "Boundary" in t for t in titles)

    for issue in report.issues:
        assert issue.language == "C/C++"
        assert issue.verified is report.tests_summary["sandbox_tested"]

    # Verify corrected code content
    corrector = AutonomousCodeCorrector()
    with open(cpp_path, "r", encoding="utf-8") as f:
        orig = f.read()
    corr = corrector.generate_corrected_file(orig, report.issues)

    assert "#include <stdexcept>" in corr
    assert "prices.empty()" in corr
    assert "discount_percent > 100" in corr
    assert "import os" not in corr
