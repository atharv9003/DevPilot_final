"""
Agent 5: Evaluator / Critic Agent with Anti-Hallucination & Runtime Verification
- Detects and merges overlapping/duplicate findings across agents.
- Verifies line-by-line file grounding against disk (rejects hallucinations).
- Independently inspects and verifies generated patches (rejects undefined variables / invented functions).
- Executes runtime verification & regression suites against generated corrections.
- Calibrates confidence based on source evidence, static analysis, and reproducible tests.
- Enforces strict verification policy: corrections are marked verified only if relevant tests pass.
- Produces a comprehensive completeness coverage report.
"""
import os
import ast
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set
from src.blackboard.schema import CodeIssue
from src.analysis.corrector import AutonomousCodeCorrector
from src.mcp_tools.docker_sandbox import DockerSandboxTool


class EvaluatorCriticAgent:
    """Specialized Evaluator / Critic Agent with anti-hallucination and empirical verification."""

    SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def __init__(self, agent_id: str = "evaluator_critic_agent"):
        self.agent_id = agent_id
        self.corrector = AutonomousCodeCorrector()
        self._sandbox = None

    def evaluate_and_verify(
        self,
        candidate_issues: List[CodeIssue],
        repo_root: str,
        test_file: str | None = None,
    ) -> Tuple[List[CodeIssue], int, Dict[str, Any], Dict[str, Any]]:
        """
        Validates, deduplicates, merges overlaps, and dynamically tests candidate issues.
        Returns:
            verified_issues: List of confirmed (and uncertain) issues with test results.
            false_positives_rejected: Count of discarded hallucinated/invalid findings.
            verification_summary: Summary of dynamic test runs and regression checks.
            coverage_report: Final inspection completeness coverage report.
        """
        # Step 1: Anti-hallucination line-by-line grounding check
        grounded_issues, false_positives_count = self._ground_against_disk(candidate_issues, repo_root)

        # Step 2: Merge overlapping and genuinely duplicate findings
        merged_issues = self._merge_overlapping_findings(grounded_issues)

        # Step 3: Dynamic Runtime & Regression Testing of Corrected Code
        verification_summary = self._run_dynamic_verification(merged_issues, repo_root, test_file)

        # Step 4: Completeness Coverage Report
        coverage_report = self._generate_coverage_report(repo_root, merged_issues, false_positives_count)

        return merged_issues, false_positives_count, verification_summary, coverage_report

    def _ground_against_disk(self, candidate_issues: List[CodeIssue], repo_root: str) -> Tuple[List[CodeIssue], int]:
        """Checks that cited files, lines, and tokens physically exist on disk."""
        grounded = []
        fp_count = 0

        for issue in candidate_issues:
            full_file_path = issue.file_path
            if not os.path.isabs(full_file_path):
                full_file_path = os.path.join(repo_root, issue.file_path)

            if not os.path.exists(full_file_path) and os.path.isfile(repo_root):
                full_file_path = repo_root

            if not os.path.exists(full_file_path):
                fp_count += 1
                continue

            try:
                with open(full_file_path, "r", encoding="utf-8", errors="replace") as f:
                    file_lines = f.read().splitlines()
            except Exception:
                fp_count += 1
                continue

            if issue.line_number < 1 or issue.line_number > len(file_lines):
                fp_count += 1
                continue

            cited_snippet = issue.original_code.strip()
            if cited_snippet:
                surrounding = " ".join(
                    file_lines[max(0, issue.line_number - 3):min(len(file_lines), issue.line_number + 2)]
                )
                significant_tokens = [tok for tok in cited_snippet.split() if len(tok) > 2]
                if significant_tokens:
                    matches = sum(1 for tok in significant_tokens if tok in surrounding)
                    if (matches / len(significant_tokens)) < 0.20:
                        fp_count += 1
                        continue

            grounded.append(issue)

        return grounded, fp_count

    def _merge_overlapping_findings(self, issues: List[CodeIssue]) -> List[CodeIssue]:
        """
        Detects overlapping findings on contiguous lines (±2 lines) or the same function
        and merges genuine duplicates while consolidating impact statements.
        """
        if not issues:
            return []

        sorted_issues = sorted(issues, key=lambda x: (x.file_path, x.line_number))
        merged: List[CodeIssue] = []

        for current in sorted_issues:
            if not merged:
                merged.append(current)
                continue

            prev = merged[-1]
            same_file = (prev.file_path == current.file_path)
            close_lines = abs(prev.line_number - current.line_number) <= 2
            same_category = (prev.category == current.category)
            same_func = (prev.function_name and current.function_name and prev.function_name == current.function_name)

            is_duplicate = False
            if same_file and close_lines and (same_category or same_func):
                if "SQL" in prev.title and "SQL" in current.title:
                    is_duplicate = True
                elif "eval" in prev.title and "eval" in current.title:
                    is_duplicate = True
                elif "Command" in prev.title and "Command" in current.title:
                    is_duplicate = True
                elif "Insecure Default" in prev.title and "Insecure Default" in current.title:
                    is_duplicate = True
                elif "Redirect" in prev.title and "Redirect" in current.title:
                    is_duplicate = True
                elif "Range Boundary" in prev.title and "Range Boundary" in current.title:
                    is_duplicate = True
                elif prev.title == current.title:
                    is_duplicate = True

            if is_duplicate:
                prev_sev_w = self.SEVERITY_WEIGHTS.get(prev.severity.lower(), 1)
                curr_sev_w = self.SEVERITY_WEIGHTS.get(current.severity.lower(), 1)
                if curr_sev_w > prev_sev_w:
                    prev.severity = current.severity

                if current.what_is_wrong not in prev.what_is_wrong:
                    prev.what_is_wrong += f" Also observed: {current.what_is_wrong}"
                if current.potential_impact not in prev.potential_impact:
                    prev.potential_impact += f" Additional impact: {current.potential_impact}"

                if len(current.title) > len(prev.title):
                    prev.title = current.title
                if len(current.corrected_code) > len(prev.corrected_code):
                    prev.corrected_code = current.corrected_code
            else:
                merged.append(current)

        return merged

    def _run_dynamic_verification(
        self, issues: List[CodeIssue], repo_root: str, test_file: str | None = None
    ) -> Dict[str, Any]:
        """Verify each proposed change against its own file and report checks that ran."""
        repo = Path(repo_root).resolve()
        root = repo.parent if repo.is_file() else repo
        by_file: Dict[Path, List[CodeIssue]] = {}
        for issue in issues:
            self._set_verification(issue, "unverified", reason="No isolated verification was completed.")
            path = repo if repo.is_file() else (root / issue.file_path).resolve()
            if path.is_relative_to(root):
                by_file.setdefault(path, []).append(issue)

        if test_file:
            requested = (root / test_file).resolve()
            if not requested.is_relative_to(root) or not requested.is_file():
                return {"status": "error", "reason": "The requested test file must exist inside the project."}
            if repo.is_file() and requested != repo:
                return {"status": "error", "reason": "Select the project directory to run a separate test file."}
            test_file = requested.relative_to(root).as_posix()

        results = {}
        for path, file_issues in by_file.items():
            relative_path = path.relative_to(root).as_posix()
            try:
                results[relative_path] = self._verify_file(path, file_issues, repo, relative_path, test_file)
            except (OSError, ValueError) as exc:
                results[relative_path] = {"status": "error", "reason": str(exc)}
                for issue in file_issues:
                    self._set_verification(issue, "unverified", reason=str(exc))
        if test_file and not any(result.get("requested_test_file") for result in results.values()):
            results["requested_test_file"] = self._run_requested_tests(repo, test_file)

        counts = {
            key: sum(result.get(key, 0) for result in results.values())
            for key in ("total_checks", "passed_checks", "failed_checks")
        }
        tested = any(result.get("sandbox_tested", False) for result in results.values())
        has_error = any(result.get("status") == "error" for result in results.values())
        has_rejected = any(result.get("patch_syntax_valid") is False for result in results.values())
        return {
            "status": "error" if has_error else ("completed" if tested else ("failed_validation" if has_rejected else "skipped")),
            "sandbox_tested": tested,
            "overall_passed": tested and not has_error and not has_rejected and all(
                result.get("overall_passed", False) for result in results.values()
            ),
            **counts,
            "tests": results,
            "reason": None if results else "No proposed patches or explicit test file to verify.",
        }

    @staticmethod
    def _set_verification(issue: CodeIssue, status: str, **result: Any) -> None:
        issue.verified = status == "confirmed"
        issue.status = status
        issue.test_results = result
        issue.remaining_risks = result.get("reason") or (
            "Relevant isolated checks passed." if issue.verified else "Review failed checks before applying this patch."
        )

    def _verify_file(
        self, path: Path, issues: List[CodeIssue], repo: Path, relative_path: str, test_file: str | None
    ) -> Dict[str, Any]:
        with path.open(encoding="utf-8", newline="") as file:
            original = file.read()
        corrected = self.corrector.generate_corrected_file(original, issues)
        if corrected == original:
            for issue in issues:
                self._set_verification(issue, "unverified", reason="No source change was generated.")
            return {"status": "skipped", "reason": "No source change was generated."}

        valid, errors = self.corrector.verify_patch_syntax_and_symbols(corrected, file_path=str(path))
        if not valid:
            for issue in issues:
                self._set_verification(issue, "rejected_syntax_error", passed=False, reason="Patch syntax validation failed.")
            return {"overall_passed": False, "patch_syntax_valid": False, "patch_errors": errors}

        from src.analysis.languages.manager import MultiLanguageManager
        manager = MultiLanguageManager()
        language = manager.detect_file_language(str(path), corrected)
        if language == "Python":
            if test_file:
                diff = self.corrector.generate_unified_patch(original, corrected, relative_path)
                summary = self._run_requested_tests(repo, test_file, diff)
                summary["requested_test_file"] = test_file
            else:
                if self._sandbox is None:
                    self._sandbox = DockerSandboxTool()
                summary = self._sandbox.verify_python_correction(path.name, corrected)
        elif language == "C/C++":
            with tempfile.TemporaryDirectory(prefix="devpilot_cpp_patch_") as workspace:
                corrected_file = Path(workspace) / path.name
                corrected_file.write_text(corrected, encoding="utf-8")
                run = manager.run_tests_for_language(language, workspace, test_target=str(corrected_file))
            summary = {
                "status": "completed" if run.get("testable") else "skipped",
                "sandbox_tested": bool(run.get("total_tests")),
                "overall_passed": run.get("all_passed", False),
                "total_checks": run.get("total_tests", 0),
                "passed_checks": run.get("passed_tests", 0),
                "failed_checks": run.get("failed_tests", 0),
                "tests": run.get("test_cases", []),
                "reason": run.get("reason") or run.get("stderr"),
            }
        else:
            summary = {"status": "skipped", "reason": f"No isolated runtime verifier is configured for {language or 'this file type'}."}

        for issue in issues:
            tests = summary.get("tests", {})
            if isinstance(tests, dict):
                name = issue.function_name or ""
                if not name and ("api_key" in issue.original_code.lower() or "api_key" in issue.title.lower()):
                    name = "api_key_config"
                if not name and "payment_secret" in (issue.original_code + issue.title).lower():
                    name = "payment_secret_config"
                associated = tests.get(name)
            else:
                cases = [case for case in tests if issue.function_name and case["name"].startswith(issue.function_name + "_")]
                associated = {
                    "passed": all(case.get("status") == "passed" for case in cases),
                    "checks": cases,
                    "checks_run": len(cases),
                    "checks_passed": sum(case.get("status") == "passed" for case in cases),
                } if cases else None

            if associated and summary.get("sandbox_tested"):
                passed = associated.get("passed", False) and summary.get("overall_passed", False)
                associated = {**associated, "passed": passed}
                self._set_verification(issue, "confirmed" if passed else "uncertain", **associated)
            else:
                reason = summary.get("reason") or "No isolated check specifically exercised this patch."
                self._set_verification(issue, "unverified", reason=reason, syntax_valid=True)
        return {**summary, "patch_syntax_valid": True}

    def _run_requested_tests(self, repo: Path, test_file: str, diff: str | None = None) -> Dict[str, Any]:
        if Path(test_file).suffix.lower() != ".py":
            return {"status": "skipped", "reason": "The isolated project test runner supports Python test files."}
        if self._sandbox is None:
            self._sandbox = DockerSandboxTool()
        if not self._sandbox.docker_available:
            return {"status": "skipped", "reason": "Docker is required for project tests."}
        run = self._sandbox.run_tests(str(repo), test_file, diff)
        return {
            "status": "completed" if run.total_tests else "error",
            "sandbox_tested": run.total_tests > 0,
            "overall_passed": run.all_passed,
            "total_checks": run.total_tests,
            "passed_checks": run.passed_tests,
            "failed_checks": run.failed_tests,
            "reason": run.stderr or None,
            "tests": {"requested_test_file": [case.model_dump() for case in run.test_cases]},
        }

    def _generate_coverage_report(self, repo_root: str, issues: List[CodeIssue], rejected_count: int) -> Dict[str, Any]:
        """
        Computes completeness coverage metrics across all inspected files and functions
        for all supported languages.
        """
        all_funcs: Set[str] = set()
        total_loc = 0
        inspected_files: List[str] = []

        from src.analysis.languages.manager import MultiLanguageManager
        mgr = MultiLanguageManager()
        proj = mgr.inspect_project_structure(repo_root)

        for fpath in proj["all_scannable_files"]:
            rel = os.path.basename(fpath)
            inspected_files.append(rel)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                total_loc += len(content.splitlines())
                if fpath.endswith(".py"):
                    tree = ast.parse(content)
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            all_funcs.add(node.name)
                else:
                    # Generic function / method extractor regex for JS/TS/Java/C/C++
                    matches = re.findall(r"(?:function\s+([a-zA-Z0-9_]+)|(?:public|private|protected|static|\s)+[a-zA-Z0-9_<>]+\s+([a-zA-Z0-9_]+)\s*\()", content)
                    for m in matches:
                        fn = m[0] or m[1]
                        if fn and fn not in ("if", "for", "while", "switch", "catch"):
                            all_funcs.add(fn)
            except Exception:
                pass

        funcs_with_issues = {iss.function_name for iss in issues if iss.function_name}
        clean_functions = sorted(list(all_funcs - funcs_with_issues))

        cat_counts: Dict[str, int] = {}
        for iss in issues:
            cat_counts[iss.category] = cat_counts.get(iss.category, 0) + 1

        verified_count = sum(1 for iss in issues if iss.verified)
        unverified_count = sum(1 for iss in issues if not iss.verified and iss.status != "rejected_syntax_error")
        rejected_total = rejected_count + sum(1 for iss in issues if iss.status == "rejected_syntax_error")
        unresolved_count = len(issues) - verified_count

        return {
            "files_inspected": inspected_files,
            "total_files": len(inspected_files),
            "functions_inspected": sorted(list(all_funcs)),
            "total_functions": len(all_funcs),
            "lines_inspected": total_loc,
            "findings_by_category": cat_counts,
            "verified_findings": verified_count,
            "unverified_findings": unverified_count,
            "rejected_findings": rejected_total,
            "unresolved_findings": unresolved_count,
            "clean_functions": clean_functions,
            "languages_detected": proj["languages_detected"],
            "toolchains_active": proj["toolchain_status"]
        }
