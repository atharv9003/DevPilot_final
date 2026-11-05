"""
Multi-Agent System (MAS) Execution Heat Map Visualizer
Renders an Agent-by-Task matrix highlighting execution latencies, token consumption, and retry bottlenecks.
"""
import os
import tempfile
if "MPLCONFIGDIR" not in os.environ:
    os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib_devpilot")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from typing import Optional


class MASHeatmapGenerator:
    @staticmethod
    def generate_heatmap(
        df_metrics: pd.DataFrame,
        output_png_path: str = "benchmark/results/mas_execution_heatmap.png",
        metric_col: str = "duration_sec"
    ) -> Optional[str]:
        """
        Generates and saves a publication-grade heatmap:
        Y-axis: Agent Name
        X-axis: Task / Subtask Name
        Color scale: Latency (seconds) or Token count
        """
        if df_metrics.empty:
            return None

        os.makedirs(os.path.dirname(output_png_path), exist_ok=True)

        # Pivot DataFrame to create Agent vs. Task matrix
        pivot = df_metrics.pivot_table(
            index="agent_name",
            columns="task_name",
            values=metric_col,
            aggfunc="mean",
            fill_value=0.0
        )

        plt.figure(figsize=(10, 6))
        sns.set_theme(style="white")

        colormap = "YlOrRd" if metric_col == "duration_sec" else "Blues"
        ax = sns.heatmap(
            pivot,
            annot=True,
            fmt=".2f",
            cmap=colormap,
            cbar_kws={"label": f"Mean {metric_col.replace('_', ' ').title()}"},
            linewidths=0.5,
            linecolor="gray"
        )

        plt.title(f"DevPilot MAS Execution Heat Map: Agent by Task ({metric_col.replace('_', ' ').title()})", fontsize=14, weight="bold")
        plt.xlabel("Task / Execution Phase", fontsize=12)
        plt.ylabel("Agent Name", fontsize=12)
        plt.xticks(rotation=30, ha="right")
        plt.yticks(rotation=0)
        plt.tight_layout()

        plt.savefig(output_png_path, dpi=300)
        plt.close()

        return output_png_path

