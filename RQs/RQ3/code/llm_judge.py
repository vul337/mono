import os
import json
import csv
from datetime import datetime
import difflib
import sys
from llm_analyzer import get_analyzer
import concurrent.futures
import threading

os.environ['OPENAI_API_KEY'] = "aaaa"
os.environ['OPENAI_API_BASE'] = "http://127.0.0.1:8082/v1"
Judge_MODEL = "ds-v3"

MAX_WORKERS = 8
CSV_INPUT_DIR = "../dataset_1128/cwe-top10/newstop10"
CONTEXT_ON = True

MODEL = "qn3-32b-0" 

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
JSON_INPUT_DIR = f"../result/analysis/no_judge"
JUDGED_OUTPUT_DIR = "../result/analysis/judge"


if CONTEXT_ON:
    JSON_INPUT_DIR = os.path.join(JSON_INPUT_DIR, f"with-con/{MODEL}")
    JUDGED_OUTPUT_DIR = os.path.join(JUDGED_OUTPUT_DIR, f"with-con/{MODEL}")
else:
    JSON_INPUT_DIR = os.path.join(JSON_INPUT_DIR, f"without-con/{MODEL}")
    JUDGED_OUTPUT_DIR = os.path.join(JUDGED_OUTPUT_DIR, f"without-con/{MODEL}")


thread_local = threading.local()

def diff_merge(before_code_lines, after_code_lines):
    differ = difflib.Differ()
    diff_list = list(differ.compare(before_code_lines, after_code_lines))

    diff_lines = []
    for line in diff_list:
        if line.startswith("  "):
            diff_lines.append(line[2:])
        elif line.startswith("- "):
            diff_lines.append("-" + line[2:])
        elif line.startswith("+ "):
            diff_lines.append("+" + line[2:])
    return diff_lines


def get_patch(func_before_json_str, func_after_json_str):
    diff_methods = []
    try:
        func_before = json.loads(func_before_json_str) if func_before_json_str and isinstance(func_before_json_str, str) else []
        func_after = json.loads(func_after_json_str) if func_after_json_str and isinstance(func_after_json_str, str) else []
    except json.JSONDecodeError as e:
        global_logger.error(f"[{getattr(thread_local, 'current_file', 'UnknownFile')}] JSON decode error in get_patch: {e}")
        return "Error generating patch: Invalid JSON input for function data."
    except Exception as e:
        global_logger.error(f"[{getattr(thread_local, 'current_file', 'UnknownFile')}] Unexpected error in get_patch loading JSON: {e}")
        return "Error generating patch: Unexpected error."

    before_dict = {(m.get('file_path'), m.get('func_name')): m.get('func_code', '').splitlines()
                   for m in func_before if isinstance(m, dict) and m.get('file_path') and m.get('func_name') is not None}
    after_dict = {(m.get('file_path'), m.get('func_name')): m.get('func_code', '').splitlines()
                  for m in func_after if isinstance(m, dict) and m.get('file_path') and m.get('func_name') is not None}

    all_methods = set(before_dict.keys()) | set(after_dict.keys())

    if not all_methods:
         return "No function data to generate patch."

    for file_path, method_name in sorted(list(all_methods)):
        diff_lines_for_method = []
        diff_lines_for_method.append(f"File: {file_path}, Method: {method_name}")

        before_exists = (file_path, method_name) in before_dict
        after_exists = (file_path, method_name) in after_dict

        if not before_exists and after_exists:
            after_code = after_dict[(file_path, method_name)]
            for line in after_code:
                diff_lines_for_method.append(f"+ {line}")
        elif before_exists and not after_exists:
            before_code = before_dict[(file_path, method_name)]
            for line in before_code:
                diff_lines_for_method.append(f"- {line}")
        elif before_exists and after_exists:
            before_code = before_dict[(file_path, method_name)]
            after_code = after_dict[(file_path, method_name)]
            diff_lines_for_method.extend(diff_merge(before_code, after_code))

        diff_methods.append("\n".join(diff_lines_for_method))

    return "\n".join(diff_methods)


def check_eval_result(answer: str, is_vuln: bool) -> int:
    if not isinstance(answer, str):
        return -1

    answer = answer.upper()

    if is_vuln:
        return answer.rfind("MISMATCH") +3 != answer.rfind("MATCH")
    else:
        return answer.rfind("FALSE_ALARM") > answer.rfind("CORRECT")


def construct_eval_prompt(
    commit_msg: str,
    commit: str,
    cve_desc: str,
    cwe_id: str,
    rationale: str,
    is_vuln: bool,
) -> str:
    instruction = ""
    if is_vuln:
        instruction = f"""
The rationale is generated based on the vulnerable version of the code, rather than the patched code. This does not necessarily mean the vulnerability detection tool has produced a correct result. We are specifically interested in whether the rationale correctly identifies the ground truth vulnerability.
If the causes described in the rationale include the ground truth vulnerability, even if it also mentions unrelated issues, it indicates a MATCH.
If the rationale does not include the ground truth vulnerability and only identifies unrelated issues, return MISMATCH.
Let's think step by step, first analyze the ground truth and rationale, in the end return ONLY "MATCH" or "MISMATCH". Do NOT include other text in your final line.
"""

    else:
        instruction = f"""
The rationale is generated based on the patched version of the code, not the original vulnerable code, which means the tool reports some issues on the non-vulnerable code. However, this does not necessarily mean the vulnerability detection tool has produced a false alarm. We are specifically interested in whether the rationale includes a false alarm related to the ground truth vulnerability.
If the causes described in the rationale include the ground truth vulnerability (already fixed in the patched code), meaning either the rationale considers a newly added line in the patch problematic (indicated by + in the diff), or the cause identified by the rationale matches the ground truth vulnerability, it indicates a FALSE ALARM.
Otherwise, if the rationale does not include the ground truth vulnerability or refers to different issues, return CORRECT.
Let's think step by step, first analyze the ground truth and rationale, in the end return ONLY "FALSE_ALARM" or "CORRECT". Do NOT include other text in your final line.
"""

    prompt = f"""
You are a security expert tasked with evaluating a vulnerability detection tool. You are provided with the following:
* Ground Truth: This includes a CVE description, a CWE ID, a commit (patch diff), and a commit message, which collectively describe the cause of the vulnerability.
* Rationale: This is a vulnerability detection rationale generated by a tool, explaining the detected causes of the vulnerability.

```cve_desc
{cve_desc}
```cwe_id
{cwe_id}
```commit_msg
{commit_msg}
```commit
{commit}
```rationale
{rationale}
```
{instruction}
"""
    return prompt


def load_csv_data(csv_filepath: str) -> dict:
    csv_data = {}
    try:
        with open(csv_filepath, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            if 'cve_id' not in reader.fieldnames:
                 global_logger.error(f"[{getattr(thread_local, 'current_file', 'UnknownFile')}] CSV file {csv_filepath} missing 'cve_id' column. Skipping.")
                 return {}
            for row in reader:
                cve_id = row.get('cve_id')
                if cve_id:
                    csv_data[cve_id] = row
                else:
                    global_logger.warning(f"[{getattr(thread_local, 'current_file', 'UnknownFile')}] Skipping row in {csv_filepath} due to missing 'cve_id': {row}")
    except FileNotFoundError:
        global_logger.error(f"[{getattr(thread_local, 'current_file', 'UnknownFile')}] Error: CSV file not found at {csv_filepath}")
        return {}
    except Exception as e:
        global_logger.error(f"[{getattr(thread_local, 'current_file', 'UnknownFile')}] Error loading CSV file {csv_filepath}: {e}", exc_info=True)
        return {}
    return csv_data

def process_single_json_file(json_filepath: str, csv_dir: str, output_dir: str, evaluator):
    thread_local.current_file = os.path.basename(json_filepath)

    global_logger.info(f"[{thread_local.current_file}] Thread processing started.")

    try:
        with open(json_filepath, 'r', encoding='utf-8') as f:
            analysis_data = json.load(f)
    except FileNotFoundError:
        global_logger.error(f"[{thread_local.current_file}] Error: JSON file not found.")
        return
    except json.JSONDecodeError:
        global_logger.error(f"[{thread_local.current_file}] Error: Could not decode JSON.")
        return
    except Exception as e:
        global_logger.error(f"[{thread_local.current_file}] Error loading JSON file: {e}", exc_info=True)
        return

    filename = os.path.basename(json_filepath)
    parts = filename.split('_')
    if not parts or not parts[0].isdigit():
        global_logger.error(f"[{thread_local.current_file}] Skipping file with unexpected name format.")
        return

    cwe_number = parts[0]
    csv_filename = f"cwe-{cwe_number}.csv"
    csv_filepath = os.path.join(csv_dir, csv_filename)

    csv_data_lookup = load_csv_data(csv_filepath)
    if not csv_data_lookup:
        global_logger.warning(f"[{thread_local.current_file}] No data loaded from CSV {csv_filepath}. Skipping judging.")
        output_filename = filename.replace("_analysis_results.json", "_analysis_results_judge.json")
        output_filepath = os.path.join(output_dir, output_filename)
        try:
             with open(output_filepath, 'w', encoding='utf-8') as f:
                 json.dump(analysis_data, f, indent=4, ensure_ascii=False)
             global_logger.info(f"[{thread_local.current_file}] Copied original data to {output_filepath} (No CSV data).")
        except Exception as e:
             global_logger.error(f"[{thread_local.current_file}] Error writing original JSON file {output_filepath} (No CSV data): {e}", exc_info=True)
        return

    updated_analysis_data = {}
    total_entries = len(analysis_data)
    processed_count = 0

    for cve_id, entry in analysis_data.items():
        processed_count += 1
        global_logger.info(f"[{thread_local.current_file}] Judging {cve_id} ({processed_count}/{total_entries})...")

        csv_entry = csv_data_lookup.get(cve_id)

        if not csv_entry:
            global_logger.warning(f"[{thread_local.current_file} - {cve_id}] No CSV data found. Cannot judge. Copying original entry.")
            updated_analysis_data[cve_id] = entry
            continue

        tool_vuln_result = entry.get("vuln_result", 0)
        tool_patched_result = entry.get("patched_result", 0)
        tool_vuln_response = entry.get("vuln_response", "")
        tool_patched_response = entry.get("patched_response", "")

        cve_desc = csv_entry.get("description", "")
        csv_cwe_id = csv_entry.get("cwe_id", "")
        if not csv_cwe_id and entry.get("cwe"):
            csv_cwe_id = ", ".join(map(str, entry["cwe"]))

        commit_msg = csv_entry.get("commit_msg", "")
        func_before_json_str = csv_entry.get("func_before", "[]")
        func_after_json_str = csv_entry.get("func_after", "[]")

        patch_diff = get_patch(func_before_json_str, func_after_json_str)
        if "Error generating patch" in patch_diff:
             global_logger.error(f"[{thread_local.current_file} - {cve_id}] Failed to generate patch diff: {patch_diff}")
             pass

        ret_vuln_eval = -1
        ret_patched_eval = -1
        rationale_vuln_llm = ""
        rationale_patched_llm = ""

        if tool_vuln_result == 1 and tool_vuln_response and tool_vuln_response.strip():
            global_logger.info(f"[{thread_local.current_file} - {cve_id}] Judging vulnerable version...")
            prompt_vuln = construct_eval_prompt(
                commit_msg=commit_msg,
                commit=patch_diff,
                cve_desc=cve_desc,
                cwe_id=csv_cwe_id,
                rationale=tool_vuln_response,
                is_vuln=True,
            )
            try:
                rationale_vuln_llm = evaluator.generate(prompt_vuln)
                ret_vuln_eval = check_eval_result(rationale_vuln_llm, is_vuln=True)
                global_logger.info(f"[{thread_local.current_file} - {cve_id}] Vuln Eval Result: {ret_vuln_eval}")
            except Exception as e:
                global_logger.error(f"[{thread_local.current_file} - {cve_id}] Error during vulnerable version LLM call: {e}", exc_info=True)
                rationale_vuln_llm = f"Error during evaluation: {e}"
                ret_vuln_eval = -2


        else:
            global_logger.info(f"[{thread_local.current_file} - {cve_id}] Skipping vulnerable version judging (no result, empty response, or result not 1).")

        if tool_patched_result == 1 and tool_patched_response and tool_patched_response.strip():
            global_logger.info(f"[{thread_local.current_file} - {cve_id}] Judging patched version...")
            prompt_patched = construct_eval_prompt(
                commit_msg=commit_msg,
                commit=patch_diff,
                cve_desc=cve_desc,
                cwe_id=csv_cwe_id,
                rationale=tool_patched_response,
                is_vuln=False,
            )
            try:
                rationale_patched_llm = evaluator.generate(prompt_patched)
                ret_patched_eval = check_eval_result(rationale_patched_llm, is_vuln=False)
                global_logger.info(f"[{thread_local.current_file} - {cve_id}] Patched Eval Result: {ret_patched_eval}")
            except Exception as e:
                global_logger.error(f"[{thread_local.current_file} - {cve_id}] Error during patched version LLM call: {e}", exc_info=True)
                rationale_patched_llm = f"Error during evaluation: {e}"
                ret_patched_eval = -2
        else:
             global_logger.info(f"[{thread_local.current_file} - {cve_id}] Skipping patched version judging (no result, empty response, or result not 1).")

        entry["ret_vuln_eval"] = ret_vuln_eval
        entry["ret_patched_eval"] = ret_patched_eval
        entry["rationale_vuln_llm"] = rationale_vuln_llm
        entry["rationale_patched_llm"] = rationale_patched_llm

        updated_analysis_data[cve_id] = entry
        global_logger.info(f"[{thread_local.current_file} - {cve_id}] Updated entry: vuln_eval={ret_vuln_eval}, patched_eval={ret_patched_eval}")

    output_filename = filename.replace("_analysis_results.json", "_analysis_results_judge.json")
    output_filepath = os.path.join(output_dir, output_filename)
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            json.dump(updated_analysis_data, f, indent=4, ensure_ascii=False)
        global_logger.info(f"[{thread_local.current_file}] Thread finished processing and wrote judged results to {output_filepath}")
    except Exception as e:
        global_logger.error(f"[{thread_local.current_file}] Thread error writing output JSON file {output_filepath}: {e}", exc_info=True)


def process_files_multithreaded(json_dir: str, csv_dir: str, output_dir: str):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        global_logger.info(f"Created output directory: {output_dir}")

    try:
        evaluator = get_analyzer(Judge_MODEL)
        global_logger.info(f"LLM Evaluator initialized with model: {Judge_MODEL}")
    except Exception as e:
        global_logger.error(f"Failed to initialize LLM Evaluator with model {Judge_MODEL}: {e}", exc_info=True)
        global_logger.error("Exiting due to LLM Evaluator initialization failure.")
        return

    files_to_process = []
    try:
        for filename in os.listdir(json_dir):
            if filename.endswith("_analysis_results.json") and not filename.endswith("_judge.json"):
                json_filepath = os.path.join(json_dir, filename)
                if os.path.isfile(json_filepath):
                    files_to_process.append(json_filepath)
    except FileNotFoundError:
        global_logger.error(f"Input JSON directory not found: {json_dir}")
        return
    except Exception as e:
        global_logger.error(f"Error listing files in {json_dir}: {e}", exc_info=True)
        return

    if not files_to_process:
        global_logger.warning(f"No '_analysis_results.json' files found in {json_dir} (excluding '_judge.json'). Nothing to process.")
        return

    global_logger.info(f"Found {len(files_to_process)} files to process.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(process_single_json_file, filepath, csv_dir, output_dir, evaluator): filepath
                          for filepath in files_to_process}

        for future in concurrent.futures.as_completed(future_to_file):
            filepath = future_to_file[future]
            filename = os.path.basename(filepath)
            try:
                future.result()
                global_logger.info(f"Finished processing file: {filename}")
            except Exception as exc:
                global_logger.error(f"File {filename} generated an exception: {exc}", exc_info=True)

    global_logger.info("All threads finished execution.")


if __name__ == "__main__":
    global_logger.info(f"Starting LLM Judge process (Multithreaded)...")
    global_logger.info(f"Reading JSONs from: {JSON_INPUT_DIR}")
    global_logger.info(f"Reading CSVs from: {CSV_INPUT_DIR}")
    global_logger.info(f"Writing judged results to: {JUDGED_OUTPUT_DIR}")
    global_logger.info(f"Using up to {MAX_WORKERS} worker threads.")

    process_files_multithreaded(JSON_INPUT_DIR, CSV_INPUT_DIR, JUDGED_OUTPUT_DIR)

    global_logger.info("\nLLM Judge process finished.")
