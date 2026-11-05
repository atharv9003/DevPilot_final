"""
DevPilot Web Application Backend
FastAPI server exposing REST endpoints, complete multi-agent code inspection,
telemetry visualizations, and serving the interactive DevPilot Multi-Agent Dashboard.
"""
import os
import sys
import tempfile
import json
import uuid
import shutil
import zipfile
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Body, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.agents.crewai.coordinator import CoordinatorAgent
from src.analysis.corrector import AutonomousCodeCorrector
from src.blackboard.schema import FullInspectionReport, CodeIssue
from src.telemetry.heatmap import MASHeatmapGenerator
from config.settings import settings, is_online
from src.git_manager import git_manager

app = FastAPI(
    title="DevPilot: Multi-Agent Autonomous Code Review & Debugging System",
    description="Backend API and Web Interface for DevPilot MAS",
    version="2.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Request

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensures all unhandled exceptions return structured JSON rather than HTML 500 error."""
    import traceback
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": f"Server execution error: {str(exc)}"}
    )

# Cache for inspection reports across downloads/copies
INSPECTION_REPORTS_CACHE: Dict[str, FullInspectionReport] = {}

UPLOAD_DIR = os.path.abspath("devpilot_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)


# Request Models
class InspectRequest(BaseModel):
    repo_path: str = "."
    optional_context: str = ""
    test_file: Optional[str] = None


class ApplyCopyRequest(BaseModel):
    destination_path: Optional[str] = None


class DebugRequest(BaseModel):
    repo_path: str = "."
    prompt: str = ""
    error_trace: str = ""
    persona: str = "constructive"
    test_file: Optional[str] = None
    generate_heatmap: bool = True


class GitCloneRequest(BaseModel):
    git_url: str
    branch: Optional[str] = None
    auth_token: Optional[str] = None
    override_existing: bool = False


_last_health = None
_last_health_time = 0.0


@app.get("/api/health")
def health_check():
    """System and dependency connectivity check with 30s TTL cache."""
    global _last_health, _last_health_time
    import time
    now = time.time()
    if _last_health and (now - _last_health_time) < 30.0:
        return _last_health

    # Check Docker availability
    docker_status = "unavailable"
    try:
        import subprocess
        res = subprocess.run(["docker", "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        docker_status = "connected" if res.returncode == 0 else "daemon_unreachable"
    except Exception:
        docker_status = "cli_not_found"

    # Check Redis availability
    redis_status = "in_memory_fallback"
    try:
        import redis
        client = redis.Redis(host=settings.redis_host, port=settings.redis_port, socket_connect_timeout=1)
        if client.ping():
            redis_status = "connected"
    except Exception:
        redis_status = "in_memory_fallback"

    # Multi-language toolchains readiness
    toolchains = {}
    try:
        from src.analysis.languages.manager import MultiLanguageManager
        toolchains = MultiLanguageManager().get_toolchain_summary()
    except Exception as e:
        toolchains = {"error": str(e)}

    res_dict = {
        "status": "healthy",
        "service": "DevPilot MAS Web Backend",
        "docker_sandbox": docker_status,
        "blackboard_backend": redis_status,
        "gemini_api": "configured" if settings.gemini_api_key else "not_configured",
        "tavily_api": "configured" if settings.tavily_api_key else "not_configured",
        "online_mode": is_online(),
        "toolchains": toolchains
    }
    _last_health = res_dict
    _last_health_time = now
    return res_dict


@app.post("/api/inspect")
def inspect_codebase(req: InspectRequest):
    """
    Executes full multi-agent code inspection across all 5 specialized agents:
    - Code Understanding Agent
    - Static Analysis Agent
    - Security Analysis Agent
    - Runtime & Dependency Analysis Agent
    - Evaluator / Critic Agent (Anti-hallucination line-by-line verification)
    - Autonomous Code Correction & Unified Patch Generation
    """
    clean_path = req.repo_path.strip(' "\'')

    # Auto-clone if Git URL provided
    if clean_path.startswith("http://") or clean_path.startswith("https://") or clean_path.endswith(".git") or clean_path.startswith("git@"):
        try:
            clone_res = git_manager.clone_repository(clean_path)
            clean_path = clone_res["repo_path"]
        except Exception as e:
            return JSONResponse(status_code=400, content={"status": "error", "message": f"Git clone failed: {str(e)}"})

    target_repo = os.path.abspath(clean_path)
    if not os.path.exists(target_repo):
        return JSONResponse(status_code=404, content={"status": "error", "message": f"Path '{clean_path}' not found."})

    try:
        coordinator = CoordinatorAgent()
        report = coordinator.run_full_inspection(
            repo_path=target_repo,
            optional_context=req.optional_context,
            test_file=req.test_file
        )
        # Cache for download / copy-apply
        INSPECTION_REPORTS_CACHE[report.run_id] = report
        return JSONResponse(status_code=200, content=report.model_dump(mode="json"))
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"status": "error", "message": f"Inspection failed: {str(e)}"})


@app.post("/api/upload")
async def upload_code_file(
    file: Optional[UploadFile] = File(None),
    files: Optional[List[UploadFile]] = File(None)
):
    """
    Receives an uploaded source file, multiple files (batch/group), or a ZIP archive,
    stores them in devpilot_uploads, and returns the target path for complete inspection.
    """
    upload_list: List[UploadFile] = []
    if files:
        upload_list.extend(files)
    if file:
        upload_list.append(file)

    if not upload_list:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    upload_id = f"up_{uuid.uuid4().hex[:6]}"
    session_dir = os.path.join(UPLOAD_DIR, upload_id)
    os.makedirs(session_dir, exist_ok=True)

    try:
        # Case A: Single file uploaded
        if len(upload_list) == 1:
            single = upload_list[0]
            filename = single.filename or "uploaded_code.py"
            target_path = os.path.join(session_dir, filename)

            with open(target_path, "wb") as buffer:
                shutil.copyfileobj(single.file, buffer)

            # Check if ZIP archive
            if filename.endswith(".zip"):
                extract_dir = os.path.join(session_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                return {
                    "status": "success",
                    "filename": filename,
                    "file_path": extract_dir,
                    "is_archive": True
                }

            return {
                "status": "success",
                "filename": filename,
                "file_path": target_path,
                "is_archive": False
            }

        # Case B: Group of multiple files selected together
        for f in upload_list:
            fname = os.path.basename(f.filename or "module.py")
            fpath = os.path.join(session_dir, fname)
            with open(fpath, "wb") as buffer:
                shutil.copyfileobj(f.file, buffer)

        return {
            "status": "success",
            "filename": f"Group of {len(upload_list)} files",
            "file_path": session_dir,
            "is_group": True,
            "total_files": len(upload_list)
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": f"Upload failed: {str(e)}"})


@app.post("/api/upload-folder")
async def upload_code_folder(files: List[UploadFile] = File(...)):
    """
    Receives an uploaded project directory with preserved relative folder structure,
    stores it in devpilot_uploads, and sets it as the active inspection target.
    """
    upload_id = f"up_dir_{uuid.uuid4().hex[:6]}"
    session_dir = os.path.join(UPLOAD_DIR, upload_id)
    os.makedirs(session_dir, exist_ok=True)

    folder_name = "uploaded_project"
    try:
        for f in files:
            rel_path = (f.filename or "file.py").replace("\\", "/").strip("/")
            parts = [p for p in rel_path.split("/") if p and p != ".."]
            if len(parts) > 1:
                folder_name = parts[0]
            dest_file = os.path.join(session_dir, *parts)
            os.makedirs(os.path.dirname(dest_file), exist_ok=True)
            with open(dest_file, "wb") as buffer:
                shutil.copyfileobj(f.file, buffer)

        target_dir = os.path.join(session_dir, folder_name)
        if not os.path.exists(target_dir):
            target_dir = session_dir

        return {
            "status": "success",
            "filename": folder_name,
            "file_path": os.path.abspath(target_dir),
            "is_directory": True
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": f"Folder upload failed: {str(e)}"})


@app.get("/api/download-corrected/{run_id}")
def download_corrected_project(run_id: str):
    """
    Creates and streams a downloadable ZIP archive containing the complete
    corrected project with all verified fixes safely applied.
    """
    report = INSPECTION_REPORTS_CACHE.get(run_id)
    if not report:
        raise HTTPException(status_code=404, detail="Inspection session report expired or not found.")

    corrector = AutonomousCodeCorrector()
    zip_dest = os.path.join(tempfile.gettempdir(), f"devpilot_corrected_{run_id}.zip")

    try:
        corrector.create_corrected_zip(
            repo_path=report.repo_path,
            issues=report.issues,
            zip_output_path=zip_dest
        )
        return FileResponse(
            zip_dest,
            media_type="application/zip",
            filename=f"devpilot_corrected_{run_id}.zip"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create ZIP package: {str(e)}")


@app.post("/api/apply-copy/{run_id}")
def apply_fixes_to_copy(run_id: str, req: ApplyCopyRequest = Body(default=ApplyCopyRequest())):
    """
    Safely copies the inspected repository to a new directory (e.g., <project>_corrected)
    and applies all verified fixes. The original project remains completely unmodified.
    """
    report = INSPECTION_REPORTS_CACHE.get(run_id)
    if not report:
        raise HTTPException(status_code=404, detail="Inspection session report not found.")

    corrector = AutonomousCodeCorrector()
    try:
        dest = corrector.apply_fixes_to_copy(
            repo_path=report.repo_path,
            issues=report.issues,
            destination_path=req.destination_path
        )
        return {
            "status": "success",
            "message": "Fixes applied safely to copy.",
            "original_path": report.repo_path,
            "destination_path": dest
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to apply fixes to copy: {str(e)}")


@app.get("/api/presets")
def get_presets():
    """Returns sample bug presets for interactive 1-click testing."""
    return [
        {
            "id": "full_sample",
            "title": "Comprehensive Flawed Python Code Sample",
            "category": "all",
            "path": "devpilot_repos/code_error_detection_sample.py",
            "prompt": "Run full code inspection to identify and fix all security vulnerabilities and bugs.",
            "error_trace": ""
        },
        {
            "id": "runtime_1",
            "title": "Runtime KeyError in JSON Processor",
            "category": "runtime",
            "persona": "adversarial",
            "prompt": "Investigate unhandled KeyError when parsing nested payload. Ensure fallback defaults are applied.",
            "error_trace": "Traceback (most recent call last):\n  File 'app/processor.py', line 14, in parse\n    return data['user']['profile']['email']\nKeyError: 'profile'",
            "test_file": "tests/test_blackboard_guardrails.py"
        },
        {
            "id": "logic_1",
            "title": "Algorithmic Off-by-One in Binary Range",
            "category": "logic",
            "persona": "stressed",
            "prompt": "Fix logic error in range iteration causing upper bound index exclusion.",
            "error_trace": "AssertionError: Expected range length 10 but received 9 items.",
            "test_file": "tests/test_mcp_tools.py"
        },
        {
            "id": "syntax_1",
            "title": "Syntax & Import Resolution Error",
            "category": "syntax",
            "persona": "constructive",
            "prompt": "Resolve import error for missing utility module and clean up syntax.",
            "error_trace": "ImportError: cannot import name 'safe_eval' from 'utils'",
            "test_file": "tests/test_agents_interop.py"
        }
    ]


@app.post("/api/git/clone")
def clone_git_repo(req: GitCloneRequest):
    """Clones a remote Git repository into the managed workspace."""
    try:
        meta = git_manager.clone_repository(
            git_url=req.git_url,
            branch=req.branch,
            auth_token=req.auth_token,
            override_existing=req.override_existing
        )
        return {"status": "success", "repository": meta}
    except Exception as e:
        return JSONResponse(status_code=400, content={"status": "error", "message": str(e)})


@app.get("/api/git/repos")
def list_git_repos():
    """Lists all cloned and managed repositories."""
    repos = git_manager.list_saved_repositories()
    return {"total": len(repos), "repositories": repos}


@app.get("/api/git/inspect")
def inspect_local_repo(path: str = "."):
    """Inspects a repository or local path, discovering test files and python source files."""
    clean_path = path.strip(' "\'')
    abs_path = os.path.abspath(clean_path)
    if not os.path.exists(abs_path):
        return JSONResponse(status_code=404, content={"status": "error", "message": f"Path '{clean_path}' does not exist on disk."})
    meta = git_manager.get_repo_metadata(abs_path)
    return {"status": "success", "repository": meta}


@app.post("/api/debug")
def run_debug_session(req: DebugRequest):
    """Executes full multi-agent review and debugging workflow."""
    clean_path = req.repo_path.strip(' "\'')

    if clean_path.startswith("http://") or clean_path.startswith("https://") or clean_path.endswith(".git") or clean_path.startswith("git@"):
        try:
            clone_res = git_manager.clone_repository(clean_path)
            clean_path = clone_res["repo_path"]
        except Exception as e:
            return JSONResponse(status_code=400, content={"status": "error", "message": f"Git clone failed: {str(e)}"})

    target_repo = os.path.abspath(clean_path)
    if not os.path.exists(target_repo):
        return JSONResponse(status_code=404, content={"status": "error", "message": f"Repository '{clean_path}' not found."})

    try:
        coordinator = CoordinatorAgent()
        result = coordinator.run_debugging_session(
            repo_path=target_repo,
            user_prompt=req.prompt or "Analyze and resolve error.",
            error_trace=req.error_trace,
            persona=req.persona,
            test_file=req.test_file
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Execution error: {str(e)}"
            }
        )

    if result.get("status") == "blocked":
        return {
            "status": "blocked",
            "reason": result.get("reason"),
            "detected_patterns": result.get("detected_patterns", []),
            "persona": req.persona
        }

    review = result.get("review") or {}
    reports = review.get("reports") or {}
    final_state = result.get("final_state")
    telemetry = result.get("telemetry")
    tracer = result.get("tracer")

    heatmap_generated = False
    heatmap_path = "benchmark/results/mas_execution_heatmap.png"
    if req.generate_heatmap and telemetry:
        df_metrics = telemetry.get_summary_dataframe()
        hm_res = MASHeatmapGenerator.generate_heatmap(df_metrics, heatmap_path)
        if hm_res:
            heatmap_generated = True

    primary_hypo = final_state.hypotheses[0] if (final_state and final_state.hypotheses) else None
    latest_test = final_state.test_runs[-1] if (final_state and final_state.test_runs) else None

    cat_val = "runtime"
    if primary_hypo and getattr(primary_hypo, "category", None):
        cat = primary_hypo.category
        cat_val = cat.value if hasattr(cat, "value") else str(cat)

    target_file = ""
    if primary_hypo and hasattr(primary_hypo, "suspected_files") and primary_hypo.suspected_files:
        target_file = primary_hypo.suspected_files[0]

    return {
        "status": "success",
        "run_id": result.get("run_id"),
        "diagnosis_status": result.get("status"),
        "all_passed": result.get("all_passed"),
        "retries_count": result.get("retries"),
        "telemetry_summary": telemetry.get_aggregate_summary() if telemetry else {},
        "target_file": target_file,
        "bug_category": cat_val,
        "root_cause_explanation": primary_hypo.root_cause if primary_hypo else "Analysis completed.",
        "patch_diff": final_state.candidate_patches[-1].diff if (final_state and final_state.candidate_patches) else "",
        "test_run": {
            "passed": latest_test.all_passed if latest_test else False,
            "stdout": latest_test.stdout if latest_test else "",
            "stderr": latest_test.stderr if latest_test else "",
            "execution_duration": latest_test.execution_duration_sec if latest_test else 0.0
        },
        "audit_trail_hash": final_state.get_state_hash() if final_state else "",
        "reports": reports,
        "heatmap_generated": heatmap_generated,
        "heatmap_url": "/api/heatmap" if heatmap_generated else None
    }


@app.get("/api/heatmap")
def get_heatmap():
    """Serves the generated Multi-Agent System Execution Heatmap."""
    heatmap_path = os.path.abspath("benchmark/results/mas_execution_heatmap.png")
    if os.path.exists(heatmap_path):
        return FileResponse(heatmap_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Heatmap has not been generated yet.")


@app.get("/api/benchmark/summary")
def get_benchmark_summary():
    """Returns 40-run empirical benchmark summary records."""
    csv_path = os.path.abspath("benchmark/results/benchmark_40_runs.csv")
    if not os.path.exists(csv_path):
        raise HTTPException(status_code=404, detail="Benchmark results not found.")
    
    import csv
    rows = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return {"total_runs": len(rows), "records": rows}


@app.get("/api/benchmark/images/{image_name}")
def get_benchmark_image(image_name: str):
    """Serves generated boxplot distribution analytics charts."""
    allowed = ["boxplot_completion_times.png", "boxplot_token_spread.png", "summary_accuracy_regression.png", "mas_execution_heatmap.png"]
    if image_name not in allowed:
        raise HTTPException(status_code=400, detail="Invalid chart name requested.")
    img_path = os.path.abspath(os.path.join("benchmark/results", image_name))
    if os.path.exists(img_path):
        return FileResponse(img_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Chart image not found.")


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def index_page():
    """Serves the main DevPilot Frontend Dashboard UI."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h2>DevPilot UI static files missing.</h2>", status_code=500)


# Mount static directory for JS/CSS assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
