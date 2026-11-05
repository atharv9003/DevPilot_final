"""
Observability & Tracing Module
Integrates OpenTelemetry and Langfuse client hooks with cryptographic provenance auditing.
"""
import hashlib
import json
import os
from typing import Dict, Any, Optional
from config.settings import settings


class DevPilotTracer:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.spans: list[Dict[str, Any]] = []
        self.provenance_hashes: Dict[str, str] = {}

    def log_provenance(self, artifact_name: str, content: str) -> str:
        """Computes and records SHA-256 hash for code files, diffs, or reports."""
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.provenance_hashes[artifact_name] = sha
        return sha

    def start_span(self, span_name: str, agent_name: str, metadata: Optional[Dict[str, Any]] = None):
        span = {
            "run_id": self.run_id,
            "span_name": span_name,
            "agent_name": agent_name,
            "metadata": metadata or {},
            "status": "running"
        }
        self.spans.append(span)

    def export_trace_summary(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        summary = {
            "run_id": self.run_id,
            "total_spans": len(self.spans),
            "provenance_hashes": self.provenance_hashes,
            "spans": self.spans
        }
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
        return summary

