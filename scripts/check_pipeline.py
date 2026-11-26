"""Run one real upload inspection and report each integration's observed status."""
import json
import socket
import sys
import time
import uuid
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from src.mcp_tools.docker_sandbox import DockerSandboxTool

BASE = "http://127.0.0.1:8000"
SAMPLE = Path("devpilot_repos/inspection_demo.py")


def request_json(path: str, payload: bytes | None = None, content_type: str = "application/json") -> dict:
    headers = {"Content-Type": content_type} if payload is not None else {}
    request = Request(BASE + path, data=payload, headers=headers)
    with urlopen(request, timeout=420) as response:
        return json.load(response)


def wait_for_services(timeout_seconds: int = 150) -> dict:
    """Wait for Compose containers to be ready after an immediate restart."""
    deadline = time.monotonic() + timeout_seconds
    last_error = "web server has not started"
    while time.monotonic() < deadline:
        try:
            health = request_json("/api/health")
            if health.get("docker_sandbox") != "connected" or health.get("blackboard_backend") != "connected":
                last_error = "web is ready; waiting for Docker broker and Redis"
            else:
                with socket.create_connection(("adk-workers", 8484), timeout=2):
                    return health
        except (OSError, URLError, ValueError) as exc:
            last_error = type(exc).__name__
        time.sleep(3)
    raise RuntimeError(f"Services were not ready within {timeout_seconds}s ({last_error}).")


def main() -> int:
    print("Waiting for web, Redis, sandbox broker, and A2A worker...", flush=True)
    health = wait_for_services()
    print("Services ready. Uploading sample...", flush=True)
    boundary = "devpilot-" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{SAMPLE.name}\"\r\n"
        "Content-Type: text/x-python\r\n\r\n"
    ).encode() + SAMPLE.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    upload = request_json("/api/upload", body, f"multipart/form-data; boundary={boundary}")
    print("Upload complete. Running inspection and LLM review...", flush=True)
    report = request_json("/api/inspect", json.dumps({"repo_path": upload["file_path"]}).encode())
    print("Inspection complete. Running isolated sandbox probe...", flush=True)
    # Exercise the real broker and child container independently of whether
    # this uploaded sample contains a patch with a matching regression test.
    sandbox_probe = DockerSandboxTool().verify_python_correction(
        "probe.py",
        "def calculate_average(values=None):\n"
        "    values = values or []\n"
        "    return sum(values) / len(values) if values else 0.0\n",
    )
    checks = report.get("tests_summary", {})
    llm = checks.get("llm_review", {})
    result = {
        "docker_sandbox": health.get("docker_sandbox"),
        "blackboard_backend": health.get("blackboard_backend"),
        "gemini_api": health.get("gemini_api"),
        "a2a_mcp": checks.get("mcp_analysis"),
        "llm_review": llm.get("status"),
        "llm_files_reviewed": llm.get("files_reviewed", 0),
        "llm_failure_reason": llm.get("reason"),
        "uploaded_files_inspected": report.get("total_files"),
        "isolated_checks_ran": checks.get("total_checks", 0),
        "sandbox_probe_checks": sandbox_probe.get("total_checks", 0),
        "sandbox_probe_passed": sandbox_probe.get("overall_passed", False),
        "sandbox_probe_error": sandbox_probe.get("reason") if sandbox_probe.get("status") == "error" else None,
        "verified_patches": report.get("verified_patches", 0),
    }
    print(json.dumps(result, indent=2))
    required = (
        result["docker_sandbox"] == "connected"
        and result["blackboard_backend"] == "connected"
        and result["a2a_mcp"] == "completed"
        and result["llm_review"] in ("completed", "partial")
        and result["llm_files_reviewed"] >= 1
        and result["uploaded_files_inspected"] == 1
        and result["sandbox_probe_checks"] >= 4
        and result["sandbox_probe_passed"] is True
    )
    if not required:
        print("Pipeline integration check failed; inspect the service logs.", file=sys.stderr)
        return 1
    print("Pipeline integration check passed. Runtime patch verification is reported separately above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
