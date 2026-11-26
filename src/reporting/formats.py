"""
Tri-Format Report Generator (Section 6 & 8)
Generates:
(a) Machine-readable JSON with diagnosis codes & confidence scores
(b) Tabular summary of modified files and test passes
(c) Markdown summary with diffs and explanations for human review
"""
import json
import hashlib
from typing import Dict, Any, List
from tabulate import tabulate
from src.blackboard.schema import BlackboardState, FinalDiagnosisReport


class ReportFormatter:
    @staticmethod
    def generate_all_formats(state: BlackboardState) -> Dict[str, Any]:
        hypothesis = None
        if state.hypotheses:
            hypothesis = next((h for h in state.hypotheses if h.id == state.selected_hypothesis_id), state.hypotheses[0])

        patch = state.candidate_patches[-1] if state.candidate_patches else None
        latest_test = state.test_runs[-1] if state.test_runs else None

        diag_code = f"DP-{hypothesis.category.upper() if hypothesis else 'GEN'}-{(state.run_id[:6]).upper()}"
        confidence = hypothesis.confidence_score if hypothesis else 0.0
        root_cause = hypothesis.root_cause_explanation if hypothesis else "Undetermined"
        files_modified = [patch.file_path] if patch else []
        diff_text = patch.diff if patch else "No patch generated."

        # Compute audit hash
        audit_payload = f"{diag_code}:{diff_text}:{confidence}"
        audit_hash = hashlib.sha256(audit_payload.encode('utf-8')).hexdigest()

        # (a) Machine-Readable JSON
        json_obj = {
            "run_id": state.run_id,
            "diagnosis_code": diag_code,
            "category": hypothesis.category if hypothesis else "unknown",
            "confidence_score": confidence,
            "root_cause": root_cause,
            "files_modified": files_modified,
            "tests_summary": {
                "all_passed": latest_test.all_passed if latest_test else False,
                "total_tests": latest_test.total_tests if latest_test else 0,
                "passed_tests": latest_test.passed_tests if latest_test else 0,
                "failed_tests": latest_test.failed_tests if latest_test else 0,
                "regression_detected": latest_test.regression_detected if latest_test else False
            },
            "patch_hash": patch.patch_hash if patch else "",
            "audit_hash": audit_hash
        }
        format_json = json.dumps(json_obj, indent=2)

        # (b) Tabular Summary
        table_rows = [
            ["Diagnosis Code", diag_code],
            ["Confidence Score", f"{confidence * 100:.1f}%"],
            ["Root Cause Category", hypothesis.category.capitalize() if hypothesis else "N/A"],
            ["Files Modified", ", ".join(files_modified) if files_modified else "None"],
            ["Tests Passed / Total", f"{latest_test.passed_tests if latest_test else 0} / {latest_test.total_tests if latest_test else 0}"],
            ["Regression Avoidance", "CLEAN (No regressions)" if (latest_test and not latest_test.regression_detected) else "REGRESSION DETECTED"],
            ["Audit SHA-256", audit_hash[:16] + "..."]
        ]
        format_table = tabulate(table_rows, headers=["Metric / Attribute", "DevPilot Evaluation"], tablefmt="github")

        # (c) Human-Readable Markdown with Diff
        format_markdown = f"""# DevPilot Autonomous Code Review & Debugging Report
**Run ID:** `{state.run_id}` | **Diagnosis:** `{diag_code}`

## 1. Executive Summary & Root Cause
* **Category:** `{hypothesis.category if hypothesis else 'general'}`
* **Confidence Level:** `{confidence * 100:.1f}%`
* **Root Cause Analysis:** {root_cause}

## 2. Test Verification & Regression Delta
| Total Tests | Passed | Failed | Regression Avoided | Duration |
| :--- | :--- | :--- | :--- | :--- |
| {latest_test.total_tests if latest_test else 0} | {latest_test.passed_tests if latest_test else 0} | {latest_test.failed_tests if latest_test else 0} | {'Yes' if (latest_test and not latest_test.regression_detected) else 'No'} | {latest_test.execution_duration_sec if latest_test else 0.0}s |

## 3. Proposed & Verified Patch Diff
```diff
{diff_text}
```

## 4. Provenance & Cryptographic Audit
* **Patch SHA-256:** `{patch.patch_hash if patch else 'N/A'}`
* **State SHA-256:** `{audit_hash}`
"""

        # Also create structured Pydantic object
        final_report_obj = FinalDiagnosisReport(
            diagnosis_code=diag_code,
            category=hypothesis.category if hypothesis else "unknown",
            confidence_score=confidence,
            root_cause=root_cause,
            files_modified=files_modified,
            tests_summary=json_obj["tests_summary"],
            patch_diff=diff_text,
            human_explanation=root_cause,
            audit_hash=audit_hash
        )

        return {
            "json": format_json,
            "table": format_table,
            "markdown": format_markdown,
            "report_obj": final_report_obj
        }

