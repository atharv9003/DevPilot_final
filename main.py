"""
DevPilot CLI Entrypoint
Run DevPilot multi-agent debugging sessions from the command line.
"""
import argparse
import sys
import os
import json

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass
from src.agents.crewai.coordinator import CoordinatorAgent
from src.telemetry.heatmap import MASHeatmapGenerator


def main():
    parser = argparse.ArgumentParser(
        description="DevPilot: Multi-Agent Autonomous Code Review & Debugging System"
    )
    parser.add_argument("--repo", type=str, required=True, help="Path to Python repository")
    parser.add_argument("--prompt", type=str, default="", help="Natural language bug description or ticket")
    parser.add_argument("--trace", type=str, default="", help="Stack trace / exception traceback")
    parser.add_argument("--persona", type=str, default="constructive", choices=["constructive", "stressed", "adversarial"], help="Developer prompt persona")
    parser.add_argument("--test-file", type=str, default=None, help="Target test file (e.g. tests/test_app.py)")
    parser.add_argument("--output-report", type=str, default="devpilot_report.md", help="Path to save markdown diagnosis report")
    parser.add_argument("--generate-heatmap", action="store_true", help="Generate MAS execution heat map")

    args = parser.parse_args()

    if not os.path.exists(args.repo):
        print(f"Error: Repository path '{args.repo}' does not exist.")
        sys.exit(1)

    print("===============================================================")
    print(" DevPilot: Multi-Agent Autonomous Code Review & Debugging")
    print("===============================================================")
    print(f"Target Repository : {os.path.abspath(args.repo)}")
    print(f"Persona Profile   : {args.persona}")
    print(f"Test Target       : {args.test_file or 'All discovery tests'}")
    print("---------------------------------------------------------------")

    coordinator = CoordinatorAgent()
    result = coordinator.run_debugging_session(
        repo_path=args.repo,
        user_prompt=args.prompt or "Investigate and resolve reported exception.",
        error_trace=args.trace,
        persona=args.persona,
        test_file=args.test_file
    )

    if result.get("status") == "blocked":
        print(f"\n[BLOCKED BY GUARDRAILS] {result.get('reason')}")
        print(f"Detected Injection Patterns: {result.get('detected_patterns')}")
        sys.exit(2)

    review = result.get("review", {})
    reports = review.get("reports", {})
    final_state = result.get("final_state")

    print("\n" + reports.get("table", "No tabular report generated."))

    if args.output_report and "markdown" in reports:
        with open(args.output_report, "w", encoding="utf-8") as f:
            f.write(reports["markdown"])
        print(f"\nReport written to: {os.path.abspath(args.output_report)}")

    if args.generate_heatmap and "telemetry" in result:
        df_metrics = result["telemetry"].get_summary_dataframe()
        png_path = "benchmark/results/mas_execution_heatmap.png"
        heatmap_res = MASHeatmapGenerator.generate_heatmap(df_metrics, png_path)
        if heatmap_res:
            print(f"MAS Execution Heatmap generated: {os.path.abspath(png_path)}")

    print("\nSession completed successfully.")


if __name__ == "__main__":
    main()

