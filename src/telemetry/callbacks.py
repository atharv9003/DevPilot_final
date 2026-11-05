"""
Telemetry Callbacks & Metrics Tracker
Hooks into agent and task execution lifecycles:
on_step_start, on_step_end, on_tool_start, on_tool_end, on_error.
Integrates with CrewAI agent step_callback, task callback, and Google ADK tools.
"""

import time
from typing import Dict, List, Optional, Any
from pydantic import BaseModel


class StepMetric(BaseModel):
    step_id: str
    agent_name: str
    task_name: str
    start_time: float
    end_time: float = 0.0
    duration_sec: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    error_count: int = 0
    retries: int = 0


class ToolMetric(BaseModel):
    tool_name: str
    agent_name: str
    start_time: float
    end_time: float = 0.0
    duration_sec: float = 0.0
    status: str = "success"
    error_message: Optional[str] = None


class TelemetryTracker:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.step_metrics: Dict[str, StepMetric] = {}
        self.tool_metrics: List[ToolMetric] = []
        self._active_tools: Dict[str, float] = {}
        self._active_steps: List[str] = []

    def on_step_start(
        self,
        agent_name: str,
        task_name: str,
        est_input_tokens: int = 250
    ) -> str:
        step_id = f"{agent_name}_{len(self.step_metrics)}"
        self.step_metrics[step_id] = StepMetric(
            step_id=step_id,
            agent_name=agent_name,
            task_name=task_name,
            start_time=time.time(),
            input_tokens=est_input_tokens
        )
        self._active_steps.append(step_id)
        return step_id

    def on_step_end(self, step_id: str, est_output_tokens: int = 150):
        if step_id in self.step_metrics:
            metric = self.step_metrics[step_id]
            metric.end_time = time.time()
            metric.duration_sec = round(metric.end_time - metric.start_time, 3)
            metric.output_tokens = est_output_tokens
            if step_id in self._active_steps:
                self._active_steps.remove(step_id)

    def on_tool_start(self, tool_name: str, agent_name: str):
        key = f"{agent_name}:{tool_name}"
        self._active_tools[key] = time.time()

    def on_tool_end(
        self,
        tool_name: str,
        agent_name: str,
        status: str = "success",
        error_msg: Optional[str] = None
    ):
        key = f"{agent_name}:{tool_name}"
        start = self._active_tools.pop(key, time.time())
        end = time.time()
        self.tool_metrics.append(
            ToolMetric(
                tool_name=tool_name,
                agent_name=agent_name,
                start_time=start,
                end_time=end,
                duration_sec=round(end - start, 3),
                status=status,
                error_message=error_msg
            )
        )

    def on_error(self, step_id: str, error: Exception):
        if step_id in self.step_metrics:
            self.step_metrics[step_id].error_count += 1
            self.step_metrics[step_id].retries += 1

    # CrewAI Agent Step Callback hook
    def crewai_step_callback(self, step_output: Any):
        agent_name = getattr(step_output, "agent", "CrewAI_Agent")
        task_name = getattr(step_output, "task", "Agent_Execution")
        step_id = self.on_step_start(str(agent_name), str(task_name))
        self.on_step_end(step_id)
        return step_output

    # CrewAI Task Callback hook
    def crewai_task_callback(self, task_output: Any):
        agent_name = "CrewAI_Agent"
        task_name = getattr(task_output, "description", "CrewAI_Task")
        step_id = self.on_step_start(agent_name, str(task_name)[:50])
        self.on_step_end(step_id)
        return task_output

    # CrewAI Error Callback hook
    def crewai_error_callback(self, error: Exception):
        if self._active_steps:
            step_id = self._active_steps[-1]
            self.on_error(step_id, error)

    # Attach Telemetry to CrewAI Agent
    def attach_to_agent(self, agent: Any) -> Any:
        agent.step_callback = self.crewai_step_callback
        return agent

    # Attach Telemetry to CrewAI Task
    def attach_to_task(self, task: Any) -> Any:
        task.callback = self.crewai_task_callback
        return task

    # Generate Step Metrics DataFrame for Heat Map
    def get_summary_dataframe(self):
        import pandas as pd
        records = []
        for metric in self.step_metrics.values():
            records.append({
                "agent_name": metric.agent_name,
                "task_name": metric.task_name,
                "duration_sec": metric.duration_sec,
                "total_tokens": metric.input_tokens + metric.output_tokens,
                "errors": metric.error_count,
                "retries": metric.retries
            })
        return pd.DataFrame(
            records,
            columns=[
                "agent_name",
                "task_name",
                "duration_sec",
                "total_tokens",
                "errors",
                "retries"
            ]
        )

    # Generate Tool Metrics DataFrame
    def get_tool_dataframe(self):
        import pandas as pd
        return pd.DataFrame([
            metric.model_dump()
            for metric in self.tool_metrics
        ])


if __name__ == "__main__":
    tracker = TelemetryTracker(run_id="devpilot_run_001")
    s1 = tracker.on_step_start("Coordinator", "Planning")
    tracker.on_tool_start("ASTParserTool", "Coordinator")
    tracker.on_tool_end("ASTParserTool", "Coordinator")
    tracker.on_step_end(s1)

    print("\nExecution Metrics:")
    print(tracker.get_summary_dataframe())

    print("\nTool Metrics:")
    print(tracker.get_tool_dataframe())
