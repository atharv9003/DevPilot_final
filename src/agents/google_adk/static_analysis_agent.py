"""
Agent 2: Static Analysis Agent
Specialized agent for detecting syntax errors, compilation defects,
logical errors, code quality issues, and coding standard violations across multiple languages.
"""
from typing import List, Dict, Any, Optional
import os
from src.analysis.languages.manager import MultiLanguageManager
from src.blackboard.schema import CodeIssue


class StaticAnalysisAgent:
    """Specialized Multi-Language Static Analysis Agent."""

    def __init__(self, agent_id: str = "adk_static_analysis_agent"):
        self.agent_id = agent_id
        self.lang_manager = MultiLanguageManager()

    def analyze_files(self, file_paths: List[str], repo_root: str) -> List[CodeIssue]:
        """Analyzes given files for syntax, logic, and code quality issues across all languages."""
        issues = self.lang_manager.scan_static_files(file_paths, repo_root=repo_root)
        for issue in issues:
            issue.agent_source = "static_analysis_agent"
        return issues

