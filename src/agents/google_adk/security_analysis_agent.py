"""
Agent 3: Security Analysis Agent
Specialized agent for detecting security vulnerabilities, insecure coding practices,
hardcoded secrets/credentials, injection flaws, and sensitive data leakage across multiple languages.
"""
from typing import List, Dict, Any, Optional
import os
from src.analysis.languages.manager import MultiLanguageManager
from src.blackboard.schema import CodeIssue


class SecurityAnalysisAgent:
    """Specialized Multi-Language Security Analysis Agent."""

    def __init__(self, agent_id: str = "adk_security_analysis_agent"):
        self.agent_id = agent_id
        self.lang_manager = MultiLanguageManager()

    def analyze_files(self, file_paths: List[str], repo_root: str) -> List[CodeIssue]:
        """Analyzes given files for security vulnerabilities and secret exposures across all languages."""
        issues = self.lang_manager.scan_security_files(file_paths, repo_root=repo_root)
        for issue in issues:
            issue.agent_source = "security_analysis_agent"
        return issues

