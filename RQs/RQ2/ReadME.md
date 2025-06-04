# RQ2: Inter-Procedure and Undecidable Patches Analysis

This section details our analysis of inter-procedure vulnerability fixes and the identification of undecidable patches, demonstrating **MONO's** capabilities in complex vulnerability tracing.

## Key Findings

Using Qwen3-32B as `AnalysisAgent` and DeepSeek-V3 as `ContextAgent`, we successfully enriched **4,467 of 5,573 processed CVEs (80.15%)** with context and root causes.

* **Inter-Procedure Vulnerabilities**: We found that **89%** of CVEs require **inter-procedure reasoning** (root cause lies outside the patched function), emphasizing the distributed nature of real-world vulnerabilities and **MONO's** ability to handle non-local dependencies.
* **Root Cause Accuracy**: Manual evaluation of 50 high-confidence CVEs showed **84% root cause alignment** with expert annotations, even for complex inter-procedure cases (84.1% valid rate).
* **Undecidable Patches**: Of the 19.85% (1106) unresolved CVEs, **84% were classified as undecidable patches**, lacking clear, statically verifiable signals. This highlights **MONO's** effectiveness in filtering infeasible cases and points to a significant portion of vulnerabilities challenging automated static analysis.

---

## Project Structure

This folder contains the data and scripts for RQ2:

### `Dataset_Statistic/`

Contains data related to CVEs and their categorization.

* **`CWE-TREE/`**: Text files outlining the tree structure for various CWE categories (e.g., `cwe_284_tree.txt`, `cwe_664_tree.txt`).
* **`finals/`**: Organized CVE data by project source (e.g., `freedesktop`, `github`, `kernel`).
* `output/` Output CSV files from CVE analysis.
* **`statistics.ipynb`**: A Jupyter notebook for generating dataset statistics.

### `ReadME.md`

This document.
