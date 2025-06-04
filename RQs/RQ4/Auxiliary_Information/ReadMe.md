# RQ4 auxiliary information

For this section, we investigated the **impact of auxiliary information** (PR details, comments) on patch classification.

When an LLM classified 500 random patches using only commit messages and raw code (like CleanVul and PrimeVul), it disagreed with previous classifications 86 times. Our enriched auxiliary information, however, significantly **improved the LLM's accuracy**, leading to 78 of those 86 disagreements being correctly re-evaluated.

---

### Project Structure

This `Auxiliary_Information` directory contains resources for studying the impact of auxiliary information on patch classification:

* **`code/`**: Experimental scripts (e.g., `compare.py`, `zero-shot.py`) and logs.
* **`dataset/`**: The complete dataset for patch classification.
* **`diff_patch/`**: Contains LLM responses illustrating classification changes with and without auxiliary data.
* **`ReadMe.md`**: This file.
* **`sample500/`**: The 500 random patches used in this study.
