"""Regression coverage for inspection, export, patch, and service behavior."""

import io
from pathlib import Path
import subprocess
import sys
import zipfile
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from config.settings import settings
from src.a2a.http import app as worker_app
from src.agents.google_adk.evaluator_critic_agent import EvaluatorCriticAgent
from src.analysis.corrector import AutonomousCodeCorrector
from src.blackboard.schema import CandidatePatch, CodeIssue
from src.blackboard.store import BlackboardStore
from src.git_manager import GitRepoManager
from src.mcp_tools.ast_parser import ASTParserTool
from src.mcp_tools.docker_sandbox import DockerSandboxTool
from src.web.app import app


def _issue(path, function="calculate_average", verified=False):
    return CodeIssue(
        id=path, title="Example correction", category="logic", severity="low",
        file_path=path, line_number=1, function_name=function, original_code="x = 1",
        corrected_code="x = 2", what_is_wrong="Wrong initial value", root_cause="Typo",
        potential_impact="Wrong value", explanation_of_correction="Set the expected value",
        verified=verified,
    )


def test_exports_preserve_binary_and_target_exact_file(tmp_path, monkeypatch):
    project = tmp_path / "project"
    nested = project / "nested"
    nested.mkdir(parents=True)
    binary = b"\x89PNG\r\n\x1a\n\xff"
    (project / "icon.png").write_bytes(binary)
    (project / "module.py").write_bytes(b"x = 1\r\n")
    (nested / "module.py").write_bytes(b"x = 1\r\n")
    corrector = AutonomousCodeCorrector()
    monkeypatch.setattr(corrector, "generate_corrected_file", lambda content, issues: content.replace("1", "2"))
    archive = tmp_path / "corrected.zip"
    issues = [_issue("nested/module.py", verified=True)]
    corrector.create_corrected_zip(str(project), issues, str(archive))
    with zipfile.ZipFile(archive) as result:
        assert result.read("icon.png") == binary
        assert result.read("module.py") == b"x = 1\r\n"
        assert result.read("nested/module.py") == b"x = 2\r\n"

    destination = tmp_path / "copy"
    corrector.apply_fixes_to_copy(str(project), issues, str(destination))
    assert (destination / "nested" / "module.py").read_bytes() == b"x = 2\r\n"
    with pytest.raises(FileExistsError):
        corrector.apply_fixes_to_copy(str(project), issues, str(destination))


def test_insert_only_patch_and_stale_approval(tmp_path):
    source = tmp_path / "module.py"
    before = "x = 1\n"
    after = "x = 1\ny = 2\n"
    source.write_bytes(before.encode())
    diff = AutonomousCodeCorrector().generate_unified_patch(before, after, source.name)
    blackboard = BlackboardStore(uuid4().hex, backend="memory")
    blackboard.update_input("test", "", "", "constructive", str(tmp_path), "")
    blackboard.post_candidate_patch("test", CandidatePatch(
        id="patch", hypothesis_id="hypothesis", file_path=source.name,
        original_code_snippet=before, patched_code_snippet=after, diff=diff,
    ))
    blackboard.record_human_approval("test", True)
    assert blackboard.apply_approved_patch("test") is True
    assert source.read_bytes() == after.encode()
    with pytest.raises(ValueError, match="could not be applied"):
        DockerSandboxTool._apply_patch(str(tmp_path), diff.replace("x = 1", "x = 3"))
    assert source.read_bytes() == after.encode()


def test_runtime_verification_follows_each_file(tmp_path, monkeypatch):
    for name in ("first.py", "second.py"):
        (tmp_path / name).write_bytes(b"x = 1\n")
    evaluator = EvaluatorCriticAgent()
    monkeypatch.setattr(evaluator.corrector, "generate_corrected_file", lambda source, issues: source.replace("1", "2"))
    issued_files = []

    class Sandbox:
        def verify_python_correction(self, filename, code):
            issued_files.append((filename, code))
            return {
                "sandbox_tested": True, "overall_passed": True, "total_checks": 1,
                "passed_checks": 1, "tests": {"calculate_average": {"passed": True}},
            }

    evaluator._sandbox = Sandbox()
    issues = [_issue("first.py"), _issue("second.py", function="unrelated")]
    summary = evaluator._run_dynamic_verification(issues, str(tmp_path))
    assert issued_files == [("first.py", "x = 2\n"), ("second.py", "x = 2\n")]
    assert summary["total_checks"] == 2
    assert [issue.verified for issue in issues] == [True, False]


def test_no_docker_means_no_python_execution(monkeypatch):
    monkeypatch.setattr(DockerSandboxTool, "_check_docker_daemon", lambda self: False)
    sandbox = DockerSandboxTool()
    monkeypatch.setattr(sandbox, "_run_in_docker", lambda *args, **kwargs: pytest.fail("Docker is unavailable"))
    assert sandbox.verify_python_correction("module.py", "x = 1")["status"] == "skipped"


def test_python_runtime_stages_source_for_docker(monkeypatch):
    monkeypatch.setattr(DockerSandboxTool, "_check_docker_daemon", lambda self: True)
    sandbox = DockerSandboxTool()

    def run(*args, **kwargs):
        command = args[0]
        assert command.index("--network") + 1 == command.index("none")
        mount = command[command.index("--mount") + 1]
        directory = Path(mount.removeprefix("type=bind,source=").removesuffix(",target=/workspace,readonly"))
        assert (directory / "source" / "module.py").read_text(encoding="utf-8") == "x = 1"
        assert (directory / "verifier.py").is_file()
        assert command[-2:] == ["/workspace/verifier.py", "/workspace/source/module.py"]
        return subprocess.CompletedProcess(command, 0, '{"total_checks":1,"tests":{},"overall_passed":true}', "")

    monkeypatch.setattr(subprocess, "run", run)
    assert sandbox.verify_python_correction("module.py", "x = 1")["sandbox_tested"] is True


def test_http_registry_and_empty_inspection(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "a2a_token", "integration-token")
    worker = TestClient(worker_app)
    discovery = worker.get("/api/a2a/agents").json()
    assert "analyze_codebase" in discovery["methods"]
    ping = worker.post("/rpc", json={"id": "check", "method": "ping"}).json()
    assert ping["result"] == {"status": "ok"}
    run = BlackboardStore(uuid4().hex, backend="memory")
    run.update_input("test", "", "", "constructive", str(tmp_path), "")
    request = {"id": "analysis", "method": "analyze_codebase", "params": {"run_id": run.run_id}}
    assert worker.post("/rpc", json=request).json()["error"]["code"] == -32001
    analysis = worker.post("/rpc", json=request, headers={"Authorization": "Bearer integration-token"}).json()
    assert analysis["result"]["files_analyzed"] == 0
    web = TestClient(app)
    report = web.post("/api/inspect", json={"repo_path": str(tmp_path)}).json()
    assert report["tests_summary"]["sandbox_tested"] is False
    assert report["tests_summary"]["overall_passed"] is False
    assert report["tests_summary"]["total_checks"] == 0
    response = web.get(f"/api/download-corrected/{report['run_id']}")
    assert response.status_code == 200
    assert zipfile.is_zipfile(io.BytesIO(response.content))


def test_missing_java_parser_is_a_warning(tmp_path, monkeypatch):
    source = tmp_path / "Example.java"
    source.write_text("class Example {}", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "javalang", None)
    analysis = ASTParserTool(str(source)).analyze_repository()
    assert analysis.syntax_errors == []
    assert "javalang" in analysis.analysis_warnings[0]["message"]


def test_git_cache_uses_origin_and_branch(tmp_path):
    def git(root, *args):
        return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)

    roots = [tmp_path / owner / "demo" for owner in ("one", "two")]
    for root in roots:
        root.mkdir(parents=True)
        git(root, "init", "--initial-branch=main")
        git(root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-m", "Initial")
        git(root, "branch", "release")
    manager = GitRepoManager(str(tmp_path / "clones"))
    main = manager.clone_repository(str(roots[0]))
    release = manager.clone_repository(str(roots[0]), branch="release")
    other = manager.clone_repository(str(roots[1]))
    assert len({main["repo_path"], release["repo_path"], other["repo_path"]}) == 3
    assert release["branch"] == "release"
    assert manager.clone_repository(str(roots[0]))["status"] == "reused_existing"
