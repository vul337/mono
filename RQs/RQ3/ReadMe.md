# RQ3: Influence of Context on LLM Vulnerability Detection

This section evaluates how **contextual information** gathered by MONO impacts LLM performance in vulnerability detection. Our goal is to quantify if providing high-quality, relevant context enhances LLMs' ability to detect vulnerabilities and pinpoint root causes.

## Experiment Overview

We used 1,128 randomly selected CVE pairs (vulnerable and fixed code) from 8 CWE categories. We compared LLMs' performance with and without our system's context.

* **Tasks**:
  * **Vulnerability Detection (VD)**: LLMs identify vulnerabilities in code, outputting `VUL` or `NO_VUL`.
  * **Root Cause Judgment (Judge)**: Experts assess if the LLM's identified root cause matches ground truth.
* **Metrics**: We used standard binary classification metrics, treating pre-patch code as positive and post-patch as negative.
* **Models**: Evaluated 13 diverse LLMs (Deepseek, Qwen, Meta, OpenAI) to assess context influence across various architectures and scales.

## Key Findings

Our evaluation showed that MONO's context consistently and significantly improves LLM performance:

* **F1-score gains**: 3% to 15% improvement across various CWE types, especially for complex issues like CWE-284 (Access Control) and CWE-707 (Neutralization).
* **Paired Detection Accuracy**: All models showed improvements ranging from 1.5% to 7.2% in distinguishing vulnerable from non-vulnerable code.

These results confirm that MONO's collected context is valuable for enhancing LLMs' vulnerability detection capabilities.

---

## Project Structure

This folder contains the code and data for RQ3:

* **`code/`**: Core scripts for analysis, LLM interaction, and evaluation.
  * `batch_csvs.py`: Utility for batch processing CSV files.
  * `code_analyzer.py`: LLM analyzes code.
  * `dataclass.py`: Defines data structures used in the project.
  * `llm_analyzer.py`: Interfaces with LLMs for vulnerability analysis.
  * `llm_judge.py`: Script for LLM-based root cause judgment.
  * `normal_worker.py`: Handles standard processing tasks.
  * `prompt.py`: Stores the prompts used for LLM interactions.
* **`dataset_1128/`**: Contains the dataset used for the experiment.
  * `CWE-TREE/`: CWE tree structure.
  * `cwe_tree_extract.py`: Script for extracting CWE tree information.
  * `dataset1128/`: The 1128 CVE pairs.
* **`evaluate/`**: Scripts and results for evaluating LLM performance.
  * `cwe_pair_accuracy.pdf`, `cwe_result_accuracy.pdf`, `cwe_result_f1.pdf`, `cwe_result_recall.pdf`: Plots visualizing evaluation metrics.
  * `judge_evaluate.py`: Merge all the statistical results together.
  * `normal_evaluate.py`: Statistical and computational analysis of each result.
  * `parsed_data_with_con.json`, `parsed_data_without_con.json`: Parsed data with and without context.
  * `Plot_evaluator.ipynb`: Jupyter notebook for plotting evaluation results.
* **`ReadMe.md`**: This document.
* **`result/`**: Stores raw results from the experiments.
  * `judge/`: Results specifically from the root cause judgment task.
