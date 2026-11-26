"""
Observability & Tracing Module
Production integration of OpenTelemetry distributed tracing and Langfuse Cloud observability,
coupled with cryptographic provenance auditing.
"""
import hashlib
import json
import os
import time
from typing import Dict, Any, Optional
from config.settings import settings

# OpenTelemetry SDK Integration
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import Status, StatusCode

    _OTEL_AVAILABLE = True
except Exception:
    _OTEL_AVAILABLE = False

# Langfuse SDK Integration
try:
    from langfuse import Langfuse
    _LANGFUSE_AVAILABLE = True
except Exception:
    _LANGFUSE_AVAILABLE = False


class DevPilotTracer:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.provenance_hashes: Dict[str, str] = {}
        self.active_spans: Dict[str, Any] = {}
        self.recorded_spans: list[Dict[str, Any]] = []

        # 1. Initialize OpenTelemetry Tracer
        self.otel_tracer = None
        if _OTEL_AVAILABLE and settings.enable_opentelemetry:
            try:
                resource = Resource.create({"service.name": "devpilot-mas", "run_id": run_id})
                provider = TracerProvider(resource=resource)
                self.otel_tracer = provider.get_tracer("devpilot.tracer", "2.0.0")
            except Exception:
                self.otel_tracer = None

        # 2. Initialize Langfuse Client
        self.langfuse = None
        self.langfuse_trace = None
        if (
            _LANGFUSE_AVAILABLE
            and settings.langfuse_public_key
            and settings.langfuse_secret_key
            and settings.langfuse_public_key.strip()
        ):
            try:
                self.langfuse = Langfuse(
                    public_key=settings.langfuse_public_key,
                    secret_key=settings.langfuse_secret_key,
                    host=settings.langfuse_host
                )
                self.langfuse_trace = self.langfuse.trace(
                    id=run_id,
                    name=f"devpilot-debugging-{run_id}",
                    metadata={"run_id": run_id, "service": "devpilot-mas"}
                )
            except Exception:
                self.langfuse = None
                self.langfuse_trace = None

    def log_provenance(self, artifact_name: str, content: str) -> str:
        """Computes and records cryptographic SHA-256 hash for code files, diffs, or reports."""
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.provenance_hashes[artifact_name] = sha
        if self.langfuse_trace:
            try:
                self.langfuse_trace.update(metadata={f"hash_{artifact_name}": sha})
            except Exception:
                pass
        return sha

    def start_span(self, span_name: str, agent_name: str, metadata: Optional[Dict[str, Any]] = None):
        """Starts an OpenTelemetry and Langfuse span for an agent or tool execution."""
        meta = metadata or {}
        span_data = {
            "run_id": self.run_id,
            "span_name": span_name,
            "agent_name": agent_name,
            "metadata": meta,
            "start_time": time.time(),
            "status": "running"
        }
        self.active_spans[span_name] = span_data

        # OpenTelemetry span
        otel_span = None
        if self.otel_tracer:
            try:
                otel_span = self.otel_tracer.start_span(name=span_name)
                otel_span.set_attribute("agent.name", agent_name)
                otel_span.set_attribute("devpilot.run_id", self.run_id)
                for k, v in meta.items():
                    if isinstance(v, (str, int, float, bool)):
                        otel_span.set_attribute(f"metadata.{k}", v)
                span_data["_otel_span"] = otel_span
            except Exception:
                pass

        # Langfuse span
        if self.langfuse_trace:
            try:
                lf_span = self.langfuse_trace.span(
                    name=span_name,
                    metadata={"agent_name": agent_name, **meta}
                )
                span_data["_lf_span"] = lf_span
            except Exception:
                pass

    def end_span(self, span_name: str, status: str = "success", error: Optional[Exception] = None):
        """Ends active OpenTelemetry and Langfuse spans with duration and outcome metrics."""
        span_data = self.active_spans.pop(span_name, None)
        if not span_data:
            return

        end_time = time.time()
        duration = round(end_time - span_data["start_time"], 3)
        span_data["end_time"] = end_time
        span_data["duration_sec"] = duration
        span_data["status"] = status
        if error:
            span_data["error"] = str(error)

        # End OpenTelemetry span
        otel_span = span_data.pop("_otel_span", None)
        if otel_span:
            try:
                if status == "success":
                    otel_span.set_status(Status(StatusCode.OK))
                else:
                    otel_span.set_status(Status(StatusCode.ERROR, description=str(error or "Execution Error")))
                otel_span.end()
            except Exception:
                pass

        # End Langfuse span
        lf_span = span_data.pop("_lf_span", None)
        if lf_span:
            try:
                lf_span.end(output={"status": status, "duration_sec": duration})
            except Exception:
                pass

        self.recorded_spans.append(span_data)

    def log_llm_call(self, model: str, prompt: str, completion: str, tokens: Optional[Dict[str, int]] = None):
        """Records an LLM generation call directly into Langfuse."""
        if self.langfuse_trace:
            try:
                usage = tokens or {}
                self.langfuse_trace.generation(
                    name="gemini_code_diagnosis",
                    model=model,
                    input=prompt[:500],
                    output=completion[:500],
                    usage={
                        "input": usage.get("input", 150),
                        "output": usage.get("output", 100),
                        "total": usage.get("total", 250)
                    }
                )
            except Exception:
                pass

    def flush(self):
        """Flushes telemetry batches to Langfuse Cloud."""
        if self.langfuse:
            try:
                self.langfuse.flush()
            except Exception:
                pass

    def export_trace_summary(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        self.flush()
        summary = {
            "run_id": self.run_id,
            "total_spans": len(self.recorded_spans),
            "provenance_hashes": self.provenance_hashes,
            "spans": self.recorded_spans,
            "opentelemetry_active": self.otel_tracer is not None,
            "langfuse_active": self.langfuse is not None
        }
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
        return summary
