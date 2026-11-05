"""
Unit test for TelemetryTracker and MASHeatmapGenerator.
"""
import pytest
import os
import tempfile
import pandas as pd
from src.telemetry.callbacks import TelemetryTracker
from src.telemetry.heatmap import MASHeatmapGenerator


def test_telemetry_and_heatmap_generation():
    with tempfile.TemporaryDirectory() as tmpdir:
        telemetry = TelemetryTracker(run_id="run_test_heatmap")
        
        # Simulate steps
        s1 = telemetry.on_step_start("Coordinator", "Planning")
        telemetry.on_step_end(s1)
        
        s2 = telemetry.on_step_start("CodebaseAnalyst", "AST_Analysis")
        telemetry.on_tool_start("ASTParserTool", "CodebaseAnalyst")
        telemetry.on_tool_end("ASTParserTool", "CodebaseAnalyst")
        telemetry.on_step_end(s2)

        s3 = telemetry.on_step_start("DebuggingAgent", "ReAct_Diagnosis")
        telemetry.on_tool_start("VectorCodebaseTool", "DebuggingAgent")
        telemetry.on_tool_end("VectorCodebaseTool", "DebuggingAgent")
        telemetry.on_step_end(s3)

        s4 = telemetry.on_step_start("TestingAgent", "Sandbox_Execution")
        telemetry.on_tool_start("DockerSandboxTool", "TestingAgent")
        telemetry.on_tool_end("DockerSandboxTool", "TestingAgent")
        telemetry.on_step_end(s4)

        s5 = telemetry.on_step_start("PatchReviewer", "Security_Audit")
        telemetry.on_step_end(s5)

        df = telemetry.get_summary_dataframe()
        assert len(df) == 5

        output_png = os.path.join(tmpdir, "test_heatmap.png")
        saved_path = MASHeatmapGenerator.generate_heatmap(
            df_metrics=df,
            output_png_path=output_png,
            metric_col="duration_sec"
        )
        assert saved_path == output_png
        assert os.path.exists(output_png)
        assert os.path.getsize(output_png) > 1000

