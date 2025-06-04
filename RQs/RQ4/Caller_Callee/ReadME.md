# RQ4 Caller-Callee 

For **RQ4**, we conducted an experiment to validate our refined vulnerability reproduction tool. We deliberately restricted MONO's capabilities, allowing it to only query **complete function definitions**—no data definitions, data queries, or arbitrary code snippets. When comparing this limited MONO against our tool on **100 previously successful CVE reproductions**, only **54** could be reproduced under these constraints. This outcome clearly demonstrates **our tool's effectiveness**, as MONO's success rate dropped significantly without broader data access and flexible code retrieval.

---

The project directory is structured as follows:

### `code/`

Contains the experimental scripts, including `get_cves_info.py`, `random_100.py`, and `rq4_agent_pipeline.py`, alongside experiment logs.

### `ReadME.md`

This overview of the project and experiment.

### `Results/`

Houses experiment outputs, such as `cache.db` (LLM request cache), `error_analysis/` (details on failures), and `success.csv` (successful reproductions).

### `samples/`

Stores the datasets used, including `cve-500.txt` and `random-100.txt`.
