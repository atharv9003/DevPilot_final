"""
Containerized Pytest Runner Tool (MCP Tool 4)
Executes test suites inside disposable Docker containers with strict network isolation (--network none),
resource throttling (RAM/CPU limits), and timeouts, with a sandboxed subprocess fallback.
"""
import os
import json
import subprocess
import time
import shutil
import tempfile
import re
import base64
import io
import urllib.request
import urllib.error
import zipfile
from pathlib import Path
from typing import Optional, List
from uuid import uuid4
from config.settings import settings
from src.blackboard.schema import SandboxTestExecution, TestCaseResult


class DockerSandboxTool:
    def __init__(
        self,
        docker_image: Optional[str] = None,
        timeout_seconds: int = 30,
        memory_limit: str = "512m",
        cpus: float = 1.0
    ):
        self.docker_image = docker_image or settings.docker_image
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.cpus = cpus
        self.docker_available = self._check_docker_daemon()

    def _check_docker_daemon(self) -> bool:
        """Verifies if docker binary exists AND daemon is responsive."""
        broker = os.getenv("SANDBOX_BROKER_URL")
        if broker:
            try:
                with urllib.request.urlopen(broker.rstrip("/") + "/health", timeout=12) as response:
                    return response.status == 200
            except Exception:
                return False
        try:
            res = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            return res.returncode == 0
        except Exception:
            return False

    def run_tests(
        self,
        repo_dir: str,
        test_file_path: Optional[str] = None,
        candidate_patch_diff: Optional[str] = None
    ) -> SandboxTestExecution:
        start_time = time.time()
        exec_id = f"exec_{int(start_time * 1000)}"

        # Create isolated temporary workspace copy
        temp_dir = tempfile.mkdtemp(prefix="devpilot_sandbox_")
        try:
            # Prepare isolated workspace
            target_repo = os.path.join(temp_dir, "repo")
            os.makedirs(target_repo, exist_ok=True)
            if os.path.isfile(repo_dir):
                shutil.copy2(repo_dir, os.path.join(target_repo, os.path.basename(repo_dir)))
            else:
                ignore_func = shutil.ignore_patterns('.git', '.venv', 'venv', '__pycache__', '.pytest_cache', 'brain', 'node_modules', '*.png', '*.csv')
                shutil.copytree(repo_dir, target_repo, dirs_exist_ok=True, ignore=ignore_func)

            # Apply candidate diff if provided
            if candidate_patch_diff:
                try:
                    self._apply_patch(target_repo, candidate_patch_diff)
                except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                    return SandboxTestExecution(
                        execution_id=exec_id, exit_code=-1, all_passed=False,
                        total_tests=0, passed_tests=0, failed_tests=0, stderr=str(exc),
                    )

            # Run only a project test target or pytest's normal test discovery.
            test_target = test_file_path if test_file_path else ""
            if test_target:
                target_path = Path(target_repo, test_target).resolve()
                if not target_path.is_relative_to(Path(target_repo).resolve()) or not target_path.exists():
                    raise ValueError(f"Test target is outside the copied project or does not exist: {test_target}")
                test_target = target_path.relative_to(Path(target_repo).resolve()).as_posix()

            # Strict Docker Sandbox Execution (Host fallback strictly prohibited for untrusted code)
            if not self.docker_available:
                duration = time.time() - start_time
                error_msg = "Security Alert: Docker Engine is unavailable. Untrusted test execution on host is strictly blocked by DevPilot sandbox policy."
                return SandboxTestExecution(
                    execution_id=exec_id,
                    exit_code=-1,
                    all_passed=False,
                    total_tests=0,
                    passed_tests=0,
                    failed_tests=1,
                    regression_detected=False,
                    stdout="",
                    stderr=error_msg,
                    test_cases=[TestCaseResult(
                        test_name="Docker Sandbox Security Guard",
                        status="error",
                        duration_seconds=round(duration, 3),
                        error_message=error_msg
                    )],
                    execution_duration_sec=round(duration, 3)
                )

            # Execute in hardened Docker container
            result = self._execute_in_docker(target_repo, test_target)

            duration = time.time() - start_time
            parsed_cases, total, passed, failed = self._parse_pytest_output(result["stdout"] + "\n" + result["stderr"])
            return SandboxTestExecution(
                execution_id=exec_id,
                exit_code=result["exit_code"],
                all_passed=(result["exit_code"] == 0 and failed == 0 and total > 0),
                total_tests=total,
                passed_tests=passed,
                failed_tests=failed,
                regression_detected=(failed > 0 and passed > 0),
                stdout=result["stdout"],
                stderr=result["stderr"],
                test_cases=parsed_cases,
                execution_duration_sec=round(duration, 3)
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @staticmethod
    def _apply_patch(repo_dir: str, patch_diff: str) -> None:
        """Apply a unified diff atomically and raise if it cannot be applied."""
        root = os.path.abspath(repo_dir)
        env = os.environ.copy()
        env["GIT_CEILING_DIRECTORIES"] = os.path.dirname(root)
        result = subprocess.run(
            ["git", "-c", "core.autocrlf=false", "apply", "--unidiff-zero", "--whitespace=nowarn", "-"],
            cwd=root,
            env=env,
            input=patch_diff.encode("utf-8"),
            capture_output=True,
            timeout=15,
        )
        if result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"Patch could not be applied: {detail}")

    def verify_python_correction(self, filename: str, corrected_code: str) -> dict:
        if not self.docker_available:
            return {"status": "skipped", "reason": "Docker is required for Python runtime verification."}

        with tempfile.TemporaryDirectory(prefix="devpilot_verify_") as workspace:
            root = Path(workspace) / "inputs"
            source_dir = root / "source"
            source_dir.mkdir(parents=True)
            (source_dir / filename).write_text(corrected_code, encoding="utf-8")
            verifier = Path(__file__).resolve().parents[1] / "analysis" / "runtime_verifier.py"
            shutil.copyfile(verifier, root / "verifier.py")
            result = self._run_in_docker(
                str(root), ["python", "-I", "-B", "/workspace/verifier.py", f"/workspace/source/{filename}"]
            )

        if result["exit_code"]:
            return {"status": "error", "reason": result["stderr"].strip() or "Python sandbox failed."}
        try:
            summary = json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"status": "error", "reason": "Python sandbox returned invalid verification results."}
        if not isinstance(summary, dict) or not isinstance(summary.get("tests"), dict):
            return {"status": "error", "reason": "Python sandbox returned invalid verification results."}
        if "error" in summary:
            return {"status": "error", "reason": summary["error"]}
        summary["sandbox_tested"] = summary.get("total_checks", 0) > 0
        return summary

    def _execute_in_docker(self, repo_dir: str, test_target: str) -> dict:
        args = ["python", "-m", "pytest", "-v", "--no-header", "-p", "no:cacheprovider"]
        if test_target:
            args.extend(["--", test_target])
        return self._run_in_docker(repo_dir, args)

    def _run_in_docker(self, repo_dir: str, args: List[str], *, allow_temp_execution: bool = False) -> dict:
        broker = os.getenv("SANDBOX_BROKER_URL")
        if broker:
            try:
                archive_bytes = io.BytesIO()
                with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
                    for root, dirs, files in os.walk(repo_dir):
                        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(root, name))]
                        for name in files:
                            path = os.path.join(root, name)
                            if not os.path.islink(path):
                                archive.write(path, os.path.relpath(path, repo_dir))
                payload = json.dumps({
                    "archive": base64.b64encode(archive_bytes.getvalue()).decode("ascii"),
                    "args": args,
                    "image": self.docker_image,
                }).encode("utf-8")
                request = urllib.request.Request(
                    broker.rstrip("/") + "/run", data=payload,
                    headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.getenv("SANDBOX_BROKER_TOKEN", "")},
                )
                with urllib.request.urlopen(request, timeout=self.timeout_seconds + 35) as response:
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                try:
                    detail = json.load(exc).get("stderr") or str(exc)
                except (ValueError, OSError):
                    detail = str(exc)
                return {"exit_code": -1, "stdout": "", "stderr": f"Sandbox broker error: {detail}"}
            except Exception as exc:
                return {"exit_code": -1, "stdout": "", "stderr": f"Sandbox broker error: {exc}"}
        mount = f"type=bind,source={os.path.abspath(repo_dir)},target=/workspace,readonly"
        temp_options = "rw,nosuid,nodev,size=64m"
        temp_options += ",exec" if allow_temp_execution else ",noexec"
        container_name = f"devpilot-check-{uuid4().hex}"
        cmd = [
            "docker", "run", "--rm", "--name", container_name,
            "--network", "none",
            "--security-opt=no-new-privileges",
            "--cap-drop=ALL",
            "--pids-limit", "128",
            "--read-only", "--tmpfs", f"/tmp:{temp_options}",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "-m", self.memory_limit,
            f"--cpus={self.cpus}",
            "--mount", mount,
            "-w", "/workspace",
            self.docker_image,
            *args,
        ]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds
            )
            return {"exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
        except subprocess.TimeoutExpired:
            message = f"Docker container timed out after {self.timeout_seconds}s"
            try:
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                message += ". Container cleanup could not be confirmed."
            return {"exit_code": -1, "stdout": "", "stderr": message}
        except Exception as e:
            return {"exit_code": -1, "stdout": "", "stderr": str(e)}

    def _execute_sandboxed_subprocess(self, repo_dir: str, test_target: str, target_lang: str = "Python") -> dict:
        """Disabled for security. Untrusted code execution directly on the host is strictly prohibited."""
        raise PermissionError(
            "Host subprocess fallback is permanently disabled for security. "
            "Untrusted repository code must only execute inside an isolated Docker sandbox."
        )

    def _parse_pytest_output(self, output: str) -> tuple[List[TestCaseResult], int, int, int]:
        cases = []
        passed = 0
        failed = 0
        for line in output.splitlines():
            # Pytest format
            match = re.search(r"^(.+?::\S+)\s+(PASSED|FAILED|ERROR|SKIPPED)", line)
            if match:
                test_name, status = match.groups()
                status_lower = status.lower()
                if status_lower == "passed":
                    passed += 1
                elif status_lower in ["failed", "error"]:
                    failed += 1
                cases.append(TestCaseResult(
                    test_name=test_name,
                    status=status_lower,
                    duration_seconds=0.01,
                    error_message=None if status_lower == "passed" else line
                ))
            # Node.js native test runner format (e.g. "✔ test name (1.23ms)")
            elif "✔" in line or "pass " in line or line.startswith("ok "):
                t_name = line.replace("✔", "").replace("ok ", "").strip()
                passed += 1
                cases.append(TestCaseResult(
                    test_name=t_name or "Node.js Test Case",
                    status="passed",
                    duration_seconds=0.01
                ))
            elif "✖" in line or "fail " in line or line.startswith("not ok"):
                t_name = line.replace("✖", "").replace("not ok", "").strip()
                failed += 1
                cases.append(TestCaseResult(
                    test_name=t_name or "Node.js Failed Case",
                    status="failed",
                    duration_seconds=0.01,
                    error_message=line
                ))

        summary_match = re.search(r"(\d+)\s+passed", output)
        if summary_match and passed == 0:
            passed = int(summary_match.group(1))

        fail_match = re.search(r"(\d+)\s+failed", output)
        if fail_match and failed == 0:
            failed = int(fail_match.group(1))

        total = passed + failed
        return cases, total, passed, failed
