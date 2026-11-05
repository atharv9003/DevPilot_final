"""
Statistical Boxplot Analytics Generator (Section 12)
Reads the 40-run empirical benchmark results and generates:
1. Boxplot of Execution Durations across Failure Categories (Variance, Median, IQR)
2. Boxplot of Token Usage Spread across Tested Persona Profiles
3. Statistical Distribution Summary Figures
"""
import os
import sys
import tempfile
if "MPLCONFIGDIR" not in os.environ:
    os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib_devpilot")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns


class BoxplotAnalytics:
    def __init__(self, csv_path: str = "benchmark/results/benchmark_40_runs.csv", output_dir: str = "benchmark/results"):
        self.csv_path = csv_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def load_data(self) -> pd.DataFrame:
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"Benchmark CSV not found at {self.csv_path}. Run benchmark first.")
        return pd.read_csv(self.csv_path)

    def generate_all_boxplots(self):
        df = self.load_data()
        sns.set_theme(style="whitegrid", palette="deep")

        # -------------------------------------------------------------
        # Figure 1: Execution Duration Distribution by Category & Arch
        # -------------------------------------------------------------
        plt.figure(figsize=(10, 6))
        ax = sns.boxplot(
            data=df,
            x="category",
            y="duration_seconds",
            hue="architecture",
            notch=True,
            showmeans=True,
            meanprops={"marker": "o", "markerfacecolor": "white", "markeredgecolor": "black"}
        )
        plt.title("DevPilot Empirical Benchmark: Execution Duration Distribution (40 Runs)", fontsize=13, weight="bold")
        plt.xlabel("Failure Category", fontsize=11, weight="bold")
        plt.ylabel("Execution Duration (Seconds)", fontsize=11, weight="bold")
        plt.legend(title="Architecture", loc="upper right")
        plt.tight_layout()
        fig1_path = os.path.join(self.output_dir, "boxplot_completion_times.png")
        plt.savefig(fig1_path, dpi=300)
        plt.close()
        print(f"Generated Figure 1: {fig1_path}")

        # -------------------------------------------------------------
        # Figure 2: Token Usage Spread across Tested Persona Profiles
        # -------------------------------------------------------------
        plt.figure(figsize=(9, 6))
        ax = sns.boxplot(
            data=df,
            x="persona",
            y="token_usage",
            hue="persona",
            legend=False,
            palette="Set2",
            showmeans=True,
            meanprops={"marker": "D", "markerfacecolor": "yellow", "markeredgecolor": "black"}
        )
        plt.title("DevPilot Token Usage Spread by Developer Persona Profile", fontsize=13, weight="bold")
        plt.xlabel("Tested Persona Profile", fontsize=11, weight="bold")
        plt.ylabel("Total Token Consumption (Input + Output)", fontsize=11, weight="bold")
        plt.tight_layout()
        fig2_path = os.path.join(self.output_dir, "boxplot_token_spread.png")
        plt.savefig(fig2_path, dpi=300)
        plt.close()
        print(f"Generated Figure 2: {fig2_path}")

        # -------------------------------------------------------------
        # Figure 3: Root-Cause Accuracy & Regression Avoidance by Category
        # -------------------------------------------------------------
        summary_df = df.groupby("category")[["root_cause_accuracy", "regression_avoided"]].mean().reset_index()
        summary_df_melted = summary_df.melt(id_vars="category", var_name="Metric", value_name="Score")

        plt.figure(figsize=(9, 5))
        ax = sns.barplot(
            data=summary_df_melted,
            x="category",
            y="Score",
            hue="Metric",
            palette="viridis"
        )
        plt.title("Root-Cause Accuracy & Regression Avoidance Rates by Failure Category", fontsize=13, weight="bold")
        plt.xlabel("Failure Category", fontsize=11, weight="bold")
        plt.ylabel("Success Rate (0.0 to 1.0)", fontsize=11, weight="bold")
        plt.ylim(0.0, 1.1)
        plt.legend(title="Metric", loc="lower right")
        plt.tight_layout()
        fig3_path = os.path.join(self.output_dir, "summary_accuracy_regression.png")
        plt.savefig(fig3_path, dpi=300)
        plt.close()
        print(f"Generated Figure 3: {fig3_path}")

        return {
            "fig1_completion_times": fig1_path,
            "fig2_token_spread": fig2_path,
            "fig3_accuracy_regression": fig3_path
        }


if __name__ == "__main__":
    analytics = BoxplotAnalytics()
    analytics.generate_all_boxplots()
