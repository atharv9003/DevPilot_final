"""
Google ADK Testing Agent
Pulls candidate patches from the Blackboard, applies them in the isolated Docker sandbox,
executes the test suite, detects regression deltas, and posts results back to the Blackboard.
"""
from typing import Dict, Any, Optional
from src.blackboard.store import BlackboardStore
from src.blackboard.schema import SandboxTestExecution
from src.mcp_tools.docker_sandbox import DockerSandboxTool


class TestingAgent:
    def __init__(self, agent_id: str = "adk_testing_agent"):
        self.agent_id = agent_id
        self.sandbox = DockerSandboxTool()

    def execute_testing(self, blackboard: BlackboardStore, test_file_path: Optional[str] = None) -> Dict[str, Any]:
        """Pulls candidate patch, runs isolated tests, and logs regression metrics."""
        state = blackboard.get_state()
        repo_path = state.repo_path

        # Find selected patch
        candidate_diff = None
        patch_id = None
        if state.candidate_patches:
            # Pick latest or selected patch
            patch = state.candidate_patches[-1]
            candidate_diff = patch.diff
            patch_id = patch.id

        # Run tests in Docker Sandbox
        test_run: SandboxTestExecution = self.sandbox.run_tests(
            repo_dir=repo_path,
            test_file_path=test_file_path,
            candidate_patch_diff=candidate_diff
        )
        test_run.candidate_patch_id = patch_id

        # Post test execution findings to Blackboard
        blackboard.post_test_result(agent_name=self.agent_id, test_run=test_run)

        return {
            "status": "success",
            "execution_id": test_run.execution_id,
            "all_passed": test_run.all_passed,
            "total_tests": test_run.total_tests,
            "passed_tests": test_run.passed_tests,
            "failed_tests": test_run.failed_tests,
            "regression_detected": test_run.regression_detected,
            "duration_sec": test_run.execution_duration_sec
        }

