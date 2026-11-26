"""
Unit tests for the 4 MCP tools.
"""
import pytest
import os
import tempfile
from pathlib import Path
from src.analysis.corrector import AutonomousCodeCorrector
from src.mcp_tools.ast_parser import ASTParserTool
from src.mcp_tools.vector_store import VectorCodebaseTool
from src.mcp_tools.web_search import WebSearchTool
from src.mcp_tools.docker_sandbox import DockerSandboxTool


def test_ast_parser_tool():
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_file = os.path.join(tmpdir, "sample.py")
        with open(sample_file, "w") as f:
            f.write(
                "import os\n\n"
                "def calculate_total(items, *args, **kwargs):\n"
                "    '''Calculate sum.'''\n"
                "    return sum(items)\n\n"
                "class User:\n"
                "    def __init__(self, name):\n"
                "        self.name = name\n"
            )
        parser = ASTParserTool(repo_path=tmpdir)
        res = parser.analyze_repository()
        
        assert len(res.files_analyzed) == 1
        assert len(res.syntax_errors) == 0
        names = [s.name for s in res.symbols]
        assert "calculate_total" in names
        assert "User" in names
        assert "os" in names

        calc_sym = next(s for s in res.symbols if s.name == "calculate_total")
        assert "*args" in calc_sym.parameters
        assert "**kwargs" in calc_sym.parameters


def test_vector_codebase_tool():
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_file = os.path.join(tmpdir, "math_utils.py")
        with open(sample_file, "w") as f:
            f.write(
                "def binary_search(arr, target):\n"
                "    low = 0\n"
                "    high = len(arr) - 1\n"
                "    while low <= high:\n"
                "        mid = (low + high) // 2\n"
                "        if arr[mid] == target: return mid\n"
                "    return -1\n"
            )
        tool = VectorCodebaseTool(collection_name="test_vectordb")
        count = tool.index_files(tmpdir, ["math_utils.py"])
        assert count > 0

        search_res = tool.search_codebase("binary search target", top_k=1)
        assert len(search_res) >= 1
        assert "binary_search" in search_res[0]["content"]


def test_web_search_tool():
    tool = WebSearchTool(api_key=None)  # Test offline mode
    results = tool.search("IndexError list index out of range")
    assert len(results) > 0
    assert any("IndexError" in r["title"] or "IndexError" in r["snippet"] for r in results)


def test_docker_sandbox_tool():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test_dummy.py")
        with open(test_file, "w") as f:
            f.write(
                "def test_passing():\n"
                "    assert 1 + 1 == 2\n\n"
                "def test_failing():\n"
                "    assert 2 + 2 == 5\n"
            )
        sandbox = DockerSandboxTool()
        if not sandbox.docker_available:
            pytest.skip("Docker daemon required for sandbox integration tests")
        res = sandbox.run_tests(repo_dir=tmpdir, test_file_path="test_dummy.py")
        assert res.total_tests == 2
        assert res.passed_tests == 1
        assert res.failed_tests == 1
        assert res.all_passed is False

        # Generate the diff with the line endings used by the checkout.
        original = Path(test_file).read_bytes().decode("utf-8")
        patch_diff = AutonomousCodeCorrector().generate_unified_patch(
            original, original.replace("2 + 2 == 5", "2 + 2 == 4"), "test_dummy.py"
        )
        res_patched = sandbox.run_tests(
            repo_dir=tmpdir,
            test_file_path="test_dummy.py",
            candidate_patch_diff=patch_diff
        )
        assert res_patched.all_passed is True
        assert res_patched.passed_tests == 2
        assert res_patched.failed_tests == 0

