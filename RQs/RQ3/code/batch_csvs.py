import os
import sys
import json
from pathlib import Path
import time 
import queue
sys.path.append("/agent_utils") 

from normal_worker import run_analysis_from_csv 
from logging_helper import global_logger 
logger = global_logger

# --- Configuration ---
BASE_CSV_DIR = Path("RQ3/dataset_1132/cwe-top10/newstop10") 
RESULT_ROOT = Path("../result/analysis/no_judge")
ROOT_CVE_FOLDER = "RQ3/dataset_1132/CWE-1132-RAW" 
LLM_MODEL_NAME = "qn3-32b-0"

CONTEXT_ON = 1
# 4o

# r1-qn-7b
# r1-qn-14b
# r1-qn-32b

# qn-7b
# qn-14b
# qn-32b

# lm-8b
# lm-70b
# ds-v3
# ds-r1

# qn3-32b
# qn3-235b

os.environ['OPENAI_API_KEY'] = "aaaa" 
os.environ['OPENAI_API_BASE'] = "http://127.0.0.1:8081/v1"


model_aliases = {
    # Qwen Series (Non-reasoning Instruct)
    'qn-7b': 'Qwen/Qwen2.5-7B-Instruct',
    'qn-14b': 'Qwen/Qwen2.5-14B-Instruct',
    'qn-32b': 'Qwen/Qwen2.5-32B-Instruct',
    'qn-72b': 'Qwen/Qwen2.5-72B-Instruct',
    'qn3-32b': 'Qwen/Qwen3-32B',
    "qn3-235b": "Qwen/Qwen3-235B-A22B",

    # DeepSeek R1 Distill (Reasoning)
    # Note: Based on comments, these are Distill versions of DeepSeek R1.
    'r1-qn-7b': 'Pro/deepseek-ai/DeepSeek-R1-Distill-Qwen-7B',
    'r1-qn-14b': 'deepseek-ai/DeepSeek-R1-Distill-Qwen-14B',
    'r1-qn-32b': 'deepseek-ai/DeepSeek-R1-Distill-Qwen-32B', 
    'r1-lm-8b': 'deepseek-ai/DeepSeek-R1-Distill-Llama-8B',
    'r1-lm-70b': 'deepseek-ai/DeepSeek-R1-Distill-Llama-70B',

    # Llama Series (Non-reasoning Instruct)
    'lm-8b': 'meta-llama/Meta-Llama-3.1-8B-Instruct',
    'lm-70b': 'meta-llama/Meta-Llama-3.1-70B-Instruct',
    'lm-405b': 'meta-llama/Meta-Llama-3.1-405B-Instruct', 

    # DeepSeek Native Series
    'ds-v3': 'Pro/deepseek-ai/DeepSeek-V3', # DeepSeek-V3
    'ds-r1': 'Pro/deepseek-ai/DeepSeek-R1', # DeepSeek-R1

    # OpenAI Series
    'o3-mini': 'o3-mini',
    '4o': 'gpt-4o',
    '4': 'gpt-4',
}

def main():
    logger.info("--- Starting Batch Analysis ---")


    csv_files = sorted(BASE_CSV_DIR.glob("cwe-*.csv"))
    logger.info(f"Found {len(csv_files)} CSV files to process in {BASE_CSV_DIR}.")

    if not csv_files:
        logger.warning("No CSV files found matching the pattern. Exiting.")
        return
        
    overall_results_summary: Dict[str, Dict] = {}
    total_files = len(csv_files)

    for i, csv_file_path in enumerate(csv_files):
        csv_name = csv_file_path.name
        logger.info(f"\n--- Processing File {i + 1}/{total_files}: {csv_name} ---")

        # Check if this file was already processed and has results
        cwe_id_from_filename = csv_file_path.stem.split("-")[1]
        # Optionally check if a _summary.json exists or if the analysis_results.json is non-empty
        # For simplicity, we'll re-run each time unless you add state tracking.
        try:
            # Call the modified analysis function for this specific CSV
            # Pass root_cve_folder explicitly
            file_analysis_summary = run_analysis_from_csv(
                str(csv_file_path),
                LLM_MODEL_NAME,
                root_cve_folder=ROOT_CVE_FOLDER, 
                with_con = CONTEXT_ON,
            )

            # Store the results for this file
            overall_results_summary[csv_name] = file_analysis_summary

            # Log summary for the file that just finished
            logger.info(f"\n--- Finished Processing {csv_name} ---")
            logger.info(f"Summary for {csv_name}:")
            if "error" in file_analysis_summary:
                 logger.error(f"  Status: {file_analysis_summary.get('status', 'Failed')}")
                 logger.error(f"  Error: {file_analysis_summary['error']}")
            else:
                 logger.info(f"  Status: {file_analysis_summary.get('status', 'Unknown')}")
                 logger.info(f"  Valid Pairs Processed: {file_analysis_summary.get('valid_pairs_processed', 0)}")
                 logger.info(f"  Pairs Submitted to Analyzer: {file_analysis_summary.get('pairs_submitted_to_analyzer', 0)}")
                 logger.info(f"  TP/TP: {file_analysis_summary.get('TP_TP', 0)}")
                 logger.info(f"  TP/FP: {file_analysis_summary.get('TP_FP', 0)}")
                 logger.info(f"  FP/TP: {file_analysis_summary.get('FP_TP', 0)}")
                 logger.info(f"  FP/FP: {file_analysis_summary.get('FP_FP', 0)}")
                 logger.info(f"  RUNERROR: {file_analysis_summary.get('RUNERROR', 0)}")

        except Exception as e:
            logger.critical(f"A critical error occurred while processing {csv_name}: {e}", exc_info=True)
            overall_results_summary[csv_name] = {
                "csv_file": csv_name,
                "status": "Critical Failure",
                "error": str(e),
                "TP_TP": 0, "TP_FP": 0, "FP_TP": 0, "FP_FP": 0, "RUNERROR": 0 # Initialize counts to 0 on failure
            }

        # Optional: Add a delay between processing files
        # time.sleep(5) # Wait for 5 seconds before starting the next file


    logger.info("\n--- Batch Analysis Complete ---")

    # Calculate overall totals across all files
    total_tp_tp = sum(res.get("TP_TP", 0) for res in overall_results_summary.values())
    total_tp_fp = sum(res.get("TP_FP", 0) for res in overall_results_summary.values())
    total_fp_tp = sum(res.get("FP_TP", 0) for res in overall_results_summary.values())
    total_fp_fp = sum(res.get("FP_FP", 0) for res in overall_results_summary.values())
    total_runerror = sum(res.get("RUNERROR", 0) for res in overall_results_summary.values())
    total_valid_pairs = sum(res.get("valid_pairs_processed", 0) for res in overall_results_summary.values())


    logger.info("\n--- Overall Summary Across All Files ---")
    logger.info(f"Total CSV files processed: {total_files}")
    logger.info(f"Total Valid Pairs Processed: {total_valid_pairs}")
    logger.info(f"Overall (1,0): {total_tp_tp}")
    logger.info(f"Overall (1,1): {total_tp_fp}")
    logger.info(f"Overall (0,0): {total_fp_tp}")
    logger.info(f"Overall (0,1): {total_fp_fp}")
    logger.info(f"Overall RUNERROR: {total_runerror}")


    if CONTEXT_ON:
        overall_summary_file = RESULT_ROOT / "with-con" / LLM_MODEL_NAME / f"{LLM_MODEL_NAME}_overall_analysis_summary.json"
    else:
        overall_summary_file = RESULT_ROOT / "without-con" / LLM_MODEL_NAME / f"{LLM_MODEL_NAME}_overall_analysis_summary.json"
    if not overall_summary_file.parent.exists():
        overall_summary_file.parent.mkdir(parents=True, exist_ok=True)
        # logger.info(f"Created directory for overall summary: {overall_summary_file.parent}")
    try:
        with open(overall_summary_file, "w") as f:
            json.dump(overall_results_summary, f, indent=4)
        logger.info(f"Saved overall analysis summary to {overall_summary_file}.")
    except Exception as e:
        logger.error(f"Error saving overall summary to {overall_summary_file}: {e}", exc_info=True)


if __name__ == "__main__":
    main()