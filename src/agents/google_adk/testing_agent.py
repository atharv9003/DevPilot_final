"""
Google ADK Testing Agent
Pulls candidate patches from the Blackboard, applies them in the isolated Docker sandbox,
executes the test suite, detects regression deltas, and posts results back to the Blackboard.
"""
from typing import Dict, Any, Optional, Union
from src.blackboard.store import BlackboardStore
from src.blackboard.schema import SandboxTestExecution, TestCaseResult
from src.mcp_tools.mcp_client import default_mcp_client


class TestingAgent:
    """Agent 4 – Google ADK Isolated Container Testing Agent."""

    def __init__(self, agent_id: str = "adk_testing_agent"):
        self.agent_id = agent_id
        self.mcp = default_mcp_client

    def execute_testing(self, target: Union[BlackboardStore, str, Dict[str, Any]], test_file_path: Optional[str] = None) -> Dict[str, Any]:
        """Pulls candidate patch, runs isolated tests in Docker sandbox via MCP, and logs regression metrics."""
        if isinstance(target, BlackboardStore):
            blackboard = target
            run_id = blackboard.run_id
        elif isinstance(target, dict):
            run_id = target.get("run_id", "default_run")
            test_file_path = test_file_path or target.get("test_file")
            blackboard = BlackboardStore(run_id=run_id)
        else:
            run_id = str(target)
            blackboard = BlackboardStore(run_id=run_id)

        state = blackboard.get_state()
        repo_path = state.repo_path or (target.get("repo_path", "") if isinstance(target, dict) else "")

        # Find selected patch
        candidate_diff = None
        patch_id = None
        if state.candidate_patches:
            patch = state.candidate_patches[-1]
            candidate_diff = patch.diff
            patch_id = patch.id

        # Run tests in Docker Sandbox via MCP Tool 4
        mcp_test_res = self.mcp.call_tool("docker_pytest_runner", {
            "repo_dir": repo_path,
            "test_file_path": test_file_path,
            "candidate_patch_diff": candidate_diff
        })

        test_run = SandboxTestExecution(**mcp_test_res)
        test_run.candidate_patch_id = patch_id

        # Post test execution findings to Blackboard
        blackboard.post_test_result(agent_name=self.agent_id, test_run=test_run)

        return {
            "status": "success",
            "run_id": run_id,
            "execution_id": test_run.execution_id,
            "all_passed": test_run.all_passed,
            "total_tests": test_run.total_tests,
            "passed_tests": test_run.passed_tests,
            "failed_tests": test_run.failed_tests,
            "regression_detected": test_run.regression_detected,
            "duration_sec": test_run.execution_duration_sec
        }

