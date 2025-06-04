# mono: Is Your "Clean" Vulnerability Dataset Really Solvable? Exposing and Trapping Undecidable Patches and Beyond

This document describes the artifacts accompanying our paper: "mono: Is Your "Clean" Vulnerability Dataset Really Solvable? Exposing and Trapping Undecidable Patches and Beyond".
'mono' represents **M**ulti-agent **O**perated **N**oise **O**utfilter.
The artifacts are organized in the following directories:

## `mono`

This directory contains the source code of our project.

## `MonoLens`

This subfolder contains the final dataset, MonoLens, generated and analyzed by our framework.

The subfolders within `MonoLens` are organized as follows:

### `examples`

This directory provides a sample of 8 data entries in the `csv` file and the overall stats of these samples. Each entry includes the original CVE metadata, the root cause analysis performed by our agent, and other relevant information. It also contains a reference to a corresponding folder within `other_context` folder, which holds the complete analysis results and the step-by-step process undertaken by the agent.

### `conf_0.9`

This directory contains the subset of CVEs for which our agent's final confidence score in its analysis was greater than 0.9. The `other_context` subfolder is ommitted due to the large size of the data.

### `all`

This directory includes the results for all CVEs that our agent was able to process and analyze. The `other_context` subfolder is ommitted due to the large size of the data.

## `whole-workflow-examples`

This directory showcases the complete analysis process of our mono framework for four specific cases, each with an `ReadMe.md`. It details the entire pipeline:

- `Stage1`. Patch Pre-filtering and Classification: Filtering of security-related patches.

- `Stage2`. Data Acquisition and Preprocessing: Preprocessing using Joern to generate Code Property Graphs (CPGs). The binary files (cpg.bin), whole repo are excluded due to its large size.

- `Stage3`. Iterative Contextual Analysis: Including:
    - The agent's analysis of the CVEs.
    - The contextual information gathered to understand the root cause of the CVE. 
    - The context as understood and summarized by the agent.

## `RQs`

This directory is dedicated to the research questions (RQs) addressed in our paper. Each RQ has its own subfolder, which contains:

- The specific code used for that RQ.
- The data relevant to that RQ.
- The final results obtained for that RQ.

Each RQ subfolder also includes its own `ReadMe.md` file providing more detailed information specific to that research question.
