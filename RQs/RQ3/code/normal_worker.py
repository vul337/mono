import pandas as pd
import json
import re # Import regex for parsing source strings
import sys
import os
import csv
import concurrent.futures
# Assuming Dataclass.py and prompt.py are in the same directory or sys.path is set correctly
from dataclass import VulnPairWithContext, VulAgentContext, RelatedMethod, CallerMethod, ValueTrace, Code_Snippet, QueryContext, VulnMethod
from prompt import get_zero_shot_cot_prompt_with_more_context, cwes_to_str
from typing import Dict, List, Any
from pathlib import Path
# Make sure this path is correct for your environment
sys.path.append("Agent4Vul/agent_utils")

from logging_helper import global_logger
logger = global_logger

from llm_analyzer import get_analyzer


# Global counters are removed here and moved inside run_analysis_from_csv
# TP_TP = 0
# TP_FP = 0
# FP_TP = 0
# FP_FP = 0
# RUNERROR = 0
# ALL_PAIR = 0


ROOT_CVE_FOLDER =""
NO_JUDGE_ROOT = ""

def parse_source_string(source: str) -> dict:
    """Parses the source string like 'caller_info(file:..., func:...)'"""
    match = re.match(r'(\w+)_info\(file:(.*?), (func|value):([^)]+)\)', source)
    if match:
        info_type = match.group(1)
        filename = match.group(2)
        detail_type = match.group(3)
        detail_name = match.group(4)
        return {"type": info_type, "filename": filename, detail_type: detail_name}
    # Handle 'code_info' which has a different structure
    match_code = re.match(r'code_info\(file:(.*?), lines:([\d-]+)\)', source)
    if match_code:
        filename = match_code.group(1)
        lines = match_code.group(2)
        return {"type": "code", "filename": filename, "lines": lines}
    # Handle 'query_info' which has a different structure
    match_query = re.match(r'query_info\((.*?)\)', source)
    if match_query:
        query_details = match_query.group(1)
        return {"type": "query", "details": query_details}


    return {"type": "unknown", "source_raw": source} # Return raw source if parsing fails




def parse_source_string(source: str) -> dict:
    """Parses the source string like 'caller_info(file:..., func:...)'"""
    match = re.match(r'(\w+)_info\(file:(.*?), (func|value):([^)]+)\)', source)
    if match:
        info_type = match.group(1)  # e.g., 'caller', 'func', 'value'
        filename = match.group(2)
        detail_type = match.group(3)  # 'func' or 'value'
        detail_name = match.group(4)
        return {"type": info_type, "filename": filename, detail_type: detail_name}
    
    # Handle 'code_info' which has a different structure
    match_code = re.match(r'code_info\(file:(.*?), lines:([\d-]+)\)', source)
    if match_code:
        filename = match_code.group(1)
        lines = match_code.group(2)
        return {"type": "code", "filename": filename, "lines": lines}
    
    # Handle 'query_info' which has a different structure
    match_query = re.match(r'query_info\((.*?)\)', source)
    if match_query:
        query_details = match_query.group(1)
        return {"type": "query", "details": query_details}

    return {"type": "unknown", "source_raw": source}  # Return raw source if parsing fails


def process_csv_row(row: pd.Series, root_cve_folder: str) -> VulnPairWithContext:
    try:
        cwe_list_raw = row.get("cwe_id", "")
        cwe_list = [
            c.strip() for c in cwe_list_raw.replace("'", "").replace('"', "").split(",") if c.strip() and c.strip() != "NVD-CWE-noinfo"
        ]
        if not cwe_list:
            logger.warning(f"Skipping row {row.get('id', row.name)} due to empty or invalid cwe_id: {cwe_list_raw}")
            return None

        id = row.get("id", "")
        cve_id = row.get("cve_id", "")

        func_before_raw = row.get("func_before", "[]")  # List[dict], [{func_name, file_path, func_code}, ...]
        vuln_methods_data: List[Dict[str, Any]] = []  # List of dicts from JSON
        if isinstance(func_before_raw, str):
            try:
                vuln_methods_data = json.loads(func_before_raw)
                if not isinstance(vuln_methods_data, list):
                    vuln_methods_data = []
            except json.JSONDecodeError:
                logger.warning(f"{cve_id} Failed to parse func_before JSON...")
                vuln_methods_data = []
        else:
            logger.warning(f"{cve_id} func_before column content is not a string: {type(func_before_raw)}")
            vuln_methods_data = []

        func_after_raw = row.get("func_after", "[]")  # List[dict], [{func_name, file_path, func_code}, ...]
        patched_method_data: List[Dict[str, Any]] = []  # List of dicts from JSON
        if isinstance(func_after_raw, str):
            try:
                patched_method_data = json.loads(func_after_raw)
                if not isinstance(patched_method_data, list):
                    patched_method_data = []
            except json.JSONDecodeError:
                logger.warning(f"{cve_id} Failed to parse func_after JSON...")
                patched_method_data = []
        else:
            logger.warning(f"{cve_id} func_after column content is not a string: {type(func_after_raw)}")
            patched_method_data = []

        patchs_list = []  # List[dict], [{patch, old_start, old_count, new_start, new_count}, ...]
        other_context = row.get("other_context_path", "")
        other_context_path = os.path.join(root_cve_folder, other_context)
        before_context_file = os.path.join(other_context_path, "Joern_context.json")
        before_context_file = before_context_file.replace("./", "/")
        before_context_file = before_context_file.replace("//", "/")
 
        if not os.path.exists(before_context_file):
            print(f"Warning: {before_context_file} does not exist.")
            return None
        with open(before_context_file, "r") as f:
            before_context_data = json.load(f)

        before_context = before_context_data.get("before_context", [])
        for file_patch_entry in before_context:
            if isinstance(file_patch_entry, dict):
                file_path_in_patch = file_patch_entry.get("file_path")
                patches_list = file_patch_entry.get("patch", [])
                if file_path_in_patch and isinstance(patches_list, list):
                    for patch_entry in patches_list:
                        if isinstance(patch_entry, dict) and patch_entry.get("patch"):
                            patch_string = patch_entry.get("patch")
                            func_name = patch_entry.get("func_name", "unknown_func")
                            # Parse diff hunks from the patch string
                            pattern = re.compile(r'^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@', re.MULTILINE)
                            # Find all hunk headers in the patch string
                            for match in pattern.finditer(patch_string):
                                try:
                                    old_start = int(match.group(1))
                                    old_count_str = match.group(2)
                                    old_count = int(old_count_str) if old_count_str is not None else 1
                                    new_start = int(match.group(3))
                                    new_count_str = match.group(4)
                                    new_count = int(new_count_str) if new_count_str is not None else 1
                                    patchs_list.append(
                                        {"file_path": file_path_in_patch,
                                         "func_name": func_name,
                                         "patch": patch_string,
                                         "old_start": old_start,
                                         "old_count": old_count,
                                         "new_start": new_start,
                                         "new_count": new_count,}
                                    )
                                except ValueError:
                                    continue

        vuln_methods: List[VulnMethod] = []
        for func in vuln_methods_data:
            if isinstance(func, dict):
                func_name = func.get("func_name", "unknown_func")
                file_path = func.get("file_path", "unknown_file")
                func_code = func.get("func_code", "")
                # Check if the function is in the patchs_list
                if func_name and file_path:
                    for patch_entry in patchs_list:
                        if func_name == patch_entry.get("func_name") and file_path == patch_entry.get("file_path"):
                            old_start_line = patch_entry.get("old_start", 1)
                            old_count = patch_entry.get("old_count", 1)
                vuln_methods.append(
                    VulnMethod(
                        filename=file_path,
                        method_name=func_name,
                        raw_code=func_code,
                        patch_start=old_start_line,
                        patch_count=old_count
                    )
                )
        # print(f"Vulnerable methods: {vuln_methods}")
        # input("Press Enter to continue...")  # Pause for user input
        if not vuln_methods:
            logger.warning(f"{cve_id}: No valid vulnerable methods found in func_before.")
            return None

        patched_methods: List[VulnMethod] = []
        for func in patched_method_data:
            if isinstance(func, dict):
                func_name = func.get("func_name", "unknown_func")
                file_path = func.get("file_path", "unknown_file")
                func_code = func.get("func_code", "")
                # Check if the function is in the patchs_list
                if func_name and file_path:
                    for patch_entry in patchs_list:
                        if func_name == patch_entry.get("func_name") and file_path == patch_entry.get("file_path"):
                            new_start_line = patch_entry.get("new_start", 1)
                            new_count = patch_entry.get("new_count", 1)
                patched_methods.append(
                    VulnMethod(
                        filename=file_path,
                        method_name=func_name,
                        raw_code=func_code,
                        patch_start=new_start_line,
                        patch_count=new_count
                    )
                )
        if not vuln_methods:
            logger.warning(f"{cve_id}: No valid vulnerable methods found in func_before.")
            return None

        context_data_json_raw = row.get("context_data", "[]")
        context_data_json = []
        try:
            context_data_json = json.loads(context_data_json_raw)
            if not isinstance(context_data_json, list):
                logger.warning(f"{cve_id}: context_data is not a list, skipping context parsing.")
                context_data_json = []
        except json.JSONDecodeError:
            logger.warning(f"{cve_id}: Failed to parse context_data JSON: {context_data_json_raw[:200]}...")
            context_data_json = []

        related_methods: List[RelatedMethod] = []
        caller_methods: List[CallerMethod] = []
        code_snippets: List[Code_Snippet] = []
        value_traces: List[ValueTrace] = []
        query_contexts: List[QueryContext] = []

        for context_entry in context_data_json:
            if not isinstance(context_entry, dict):
                continue
            source = context_entry.get("source")
            result = context_entry.get("result")

            if source and result is not None:
                parsed_source = parse_source_string(source)
                context_type = parsed_source.get("type")
                filename = parsed_source.get("filename", "unknown_file")
                func_name = parsed_source.get("func")  # Method name from source string

                if context_type == "func" and isinstance(result, list):  # Related functions
                    for item in result:
                        if isinstance(item, dict) and item.get("code"):
                            related_methods.append(
                                RelatedMethod(
                                    filename=item.get("file_path", filename),
                                    method_name=item.get("full_name", func_name or "unknown_func"),
                                    raw_code=item["code"]
                                )
                            )
                elif context_type == "caller" and isinstance(result, list):  # Caller methods
                    for item in result:
                        if isinstance(item, dict) and item.get("caller_code"):
                            caller_methods.append(
                                CallerMethod(
                                    filename=item.get("file_path", filename),
                                    method_name=func_name or "unknown_caller",  # Method name is the called function
                                    raw_code=item["caller_code"],  # This is the caller's code
                                    call_code=item.get("call_code", "")  # The specific line of the call
                                )
                            )
                elif context_type == "code" and isinstance(result, str):  # Code snippets
                    line_range_str = parsed_source.get('lines', '1-1')
                    try:
                        start_line, end_line = map(int, line_range_str.split('-'))
                    except ValueError:
                        start_line, end_line = 1, 1  # Default if parsing fails
                    code_snippets.append(
                        Code_Snippet(
                            filename=filename,
                            raw_code=result,
                            start_line=start_line,
                            end_line=end_line
                        )
                    )
                elif context_type == "value" and isinstance(result, dict):  # Value traces
                    value_traces.append(
                        ValueTrace(
                            value_info=source.replace("value_info", ""),  # Replace 'value_info' with 'value'
                            value_trace_details=result.get('value_trace', []),
                            struct_var=result.get('struct_var', []),
                            struct_type=result.get('struct_type', ""),
                            struct_definition=result.get('struct_definition', "")
                        )
                    )
                elif context_type == "query" and isinstance(result, str):  # Query Context
                    query_contexts.append(
                        QueryContext(
                            query=source,
                            result=result
                        )
                    )

        new_vuln_context = VulAgentContext(
            relatedMethods=related_methods,
            callerMethods=caller_methods,
            codeSnippets=code_snippets,
            valueTraces=value_traces,
            queryContexts=query_contexts,
            # typeDefs=[],
            # globalVars=[],
            # importContext=[],
            # visitedLines_before={},
            # visitedLines_after={},
            # visitedParams={},
        )

        pair = VulnPairWithContext(
            cwe=cwe_list,
            vuln=vuln_methods,
            patched=patched_methods,
            name=cve_id,
            context=new_vuln_context,
        )
        return pair

    except Exception as e:
        logger.error(f"Error processing row {row.get('id', row.name)}: {e}")
        return None


def analyze_pair_task(analyzer, name: str, pair: VulnPairWithContext, with_con: bool = True):
    """Analyzes a single vulnerability pair (vuln and patched) using the given analyzer."""
    try:
        # logger.info(f"Analyzing {name} in thread...")

        # Analyze vulnerable code
        vuln_result, vuln_response = analyzer.zeroShotCoTAnalyze(pair, is_vuln=True, context_on=with_con)
        # logger.info(f"Analysis complete for {name} (vuln). Result: {vuln_result}")


        # Analyze patched code
        patched_result, patched_response = analyzer.zeroShotCoTAnalyze(pair, is_vuln=False, context_on=with_con)
        # logger.info(f"Analysis complete for {name} (patched). Result: {patched_result}")


        # Return all results needed by the main thread
        return {
            "name": name, # Include name to identify which result belongs to which pair
            "cwe": pair.cwe,
            "vuln_result": vuln_result,
            "patched_result": patched_result,
            "vuln_response": vuln_response,
            "patched_response": patched_response,
        }
    except Exception as e:
        # Catch exceptions within the thread and return error information
        logger.error(f"Error analyzing pair {name}: {e}", exc_info=True) # Log exception details
        return {
            "name": name,
            "cwe": pair.cwe if pair else "N/A", # Still try to get CWE if pair object is valid
            "error": str(e),
            "vuln_result": -1, # Use -1 or None to indicate an error happened
            "patched_result": -1,
            "vuln_response": "Error during analysis",
            "patched_response": "Error during analysis",
        }


# Modify this function to return the counts and summary
def run_analysis_from_csv(csv_file_path: str, analyzer_name: str, root_cve_folder: str = ROOT_CVE_FOLDER, with_con: bool = True) -> Dict[str, Any]:
    logger.info(f"--- Starting analysis for CSV: {csv_file_path} ---")
    logger.info(f"Using analyzer: {analyzer_name}")
    logger.info(f"Root CVE folder: {root_cve_folder}")
    logger.info(f"Context on: {with_con}")
    # --- Initialize local counters for this specific CSV file ---
    local_TP_TP = 0
    local_TP_FP = 0
    local_FP_TP = 0
    local_FP_FP = 0
    local_RUNERROR = 0
    local_ALL_PAIR = 0

    # --- Load and Process CSV ---
    try:
        df = pd.read_csv(csv_file_path, quoting=csv.QUOTE_ALL)
    except FileNotFoundError:
        logger.error(f"CSV file not found: {csv_file_path}")
        return {"error": f"CSV file not found: {csv_file_path}"}
    except Exception as e:
        logger.error(f"Error reading CSV file {csv_file_path}: {e}", exc_info=True)
        return {"error": f"Error reading CSV: {e}"}

    logger.info(f"Loaded {len(df)} rows from {Path(csv_file_path).name}.")

    data_pairs: Dict[str, VulnPairWithContext] = {}
    csv_dir = Path(csv_file_path).parent
    cwe_id_from_filename = Path(csv_file_path).stem.split("-")[1] # Extract CWE ID from filename
    data_pairs_file = csv_dir / f"{cwe_id_from_filename}_data_pairs.json"

    # --- Process Rows from CSV ---
    processed_count = 0
    for index, row in df.iterrows():
        # print(root_cve_folder)
        pair = process_csv_row(row, root_cve_folder)
        if pair:
            data_pairs[pair.name] = pair
            processed_count += 1
        else:
            cve_id = row.get("cve_id", f"row_{row.name}")
            logger.warning(f"Could not process CSV row {index} for {cve_id} into a valid pair. Skipping analysis for this row.")
            # Optionally, you could count these skipped rows if needed

    logger.info(f"Successfully processed {processed_count} entries from {Path(csv_file_path).name} into data pairs.")
    local_ALL_PAIR = len(data_pairs)
    logger.info(f"Total unique data pairs collected for {Path(csv_file_path).name}: {local_ALL_PAIR}")


    # if local_ALL_PAIR > 0: # Only save if there are valid pairs processed
    #     try:
    #         # Convert data_pairs to dictionary format for JSON saving
    #         data_pairs_dict = {name: pair.to_dict() for name, pair in data_pairs.items()}
    #         with open(data_pairs_file , "w") as f:
    #              json.dump(data_pairs_dict, f, indent=4)
    #         logger.info(f"Saved processed data pairs for {Path(csv_file_path).name} to {data_pairs_file}.")
    #     except Exception as e:
    #          logger.error(f"Error saving data pairs to {data_pairs_file}: {e}", exc_info=True)
    # else:
    #     logger.warning(f"No valid data pairs found for {Path(csv_file_path).name}. Skipping save to data_pairs.json.")


    if not data_pairs:
        logger.warning(f"No valid data pairs available for analysis in {Path(csv_file_path).name}. Analysis skipped.")
        return {
             "csv_file": Path(csv_file_path).name,
             "total_pairs_attempted": len(df), # Number of rows in the CSV
             "valid_pairs_for_analysis": local_ALL_PAIR,
             "TP_TP": local_TP_TP,
             "TP_FP": local_TP_FP,
             "FP_TP": local_FP_TP,
             "FP_FP": local_FP_FP,
             "RUNERROR": local_RUNERROR,
             "status": "Skipped - No valid pairs"
        }


    try:
        analyzer = get_analyzer(analyzer_name)
        logger.info(f"Using analyzer '{analyzer_name}' for {Path(csv_file_path).name}.")
    except KeyError as e:
        logger.error(f"Analyzer '{analyzer_name}' not found: {e}", exc_info=True)
        return {
             "csv_file": Path(csv_file_path).name,
             "total_pairs_attempted": len(df),
             "valid_pairs_for_analysis": local_ALL_PAIR,
             "TP_TP": local_TP_TP,
             "TP_FP": local_TP_FP,
             "FP_TP": local_FP_TP,
             "FP_FP": local_FP_FP,
             "RUNERROR": local_RUNERROR,
             "error": f"Analyzer not found: {analyzer_name}",
             "status": "Analysis failed - Analyzer"
        }


    logger.info(f"Starting parallel analysis for {local_ALL_PAIR} pairs in {Path(csv_file_path).name} using ThreadPoolExecutor...")

    analysis_results: Dict[str, Dict] = {}

    MAX_THREADS = min(8,(os.cpu_count() or 1) * 5) # Use reasonable thread count
    logger.info(f"Using a maximum of {MAX_THREADS} worker threads for {Path(csv_file_path).name}.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_name = {
            executor.submit(analyze_pair_task, analyzer, name, pair, with_con): name
            for name, pair in data_pairs.items()
        }
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result_data = future.result()
                analysis_results[name] = result_data # Store the results directly
            except Exception as exc:
                logger.error(f'Pair {name} from {Path(csv_file_path).name} generated an unhandled exception in the executor: {exc}', exc_info=True)
                analysis_results[name] = {
                    "name": name,
                    "cwe": data_pairs.get(name).cwe if name in data_pairs and hasattr(data_pairs.get(name), 'cwe') else "N/A",
                    "error": f"Unhandled executor exception: {exc}",
                    "vuln_result": -1, # Indicate error state
                    "patched_result": -1, # Indicate error state
                    "vuln_response": "Exception during analysis submission",
                    "patched_response": "Exception during analysis submission",
                }

    logger.info(f"--- Parallel Analysis Submission Complete for {Path(csv_file_path).name}. Processing results ---")

    # --- Consolidating Results and Updating Local Counters ---
    final_results_summary: Dict[str, Dict] = {}
    processed_analysis_count = 0

    for name, result_data in analysis_results.items():
        processed_analysis_count += 1
        # Log progress every N pairs
        if processed_analysis_count % 50 == 0: # Log every 50 pairs
             logger.info(f"Consolidating result {processed_analysis_count}/{len(analysis_results)} for {Path(csv_file_path).name}")


        vuln_result = result_data.get("vuln_result", -1)
        patched_result = result_data.get("patched_result", -1)
        cwe = result_data.get("cwe", "N/A") # Keep CWE in the summary for reference
        error_msg = result_data.get("error") # Check if an error occurred for this specific pair


        if error_msg or vuln_result == -1 or patched_result == -1:
            local_RUNERROR += 1
            # Keep the detailed error info in the summary if it exists
            final_results_summary[name] = result_data
            if error_msg:
                logger.warning(f"Analysis failed for pair {name} in {Path(csv_file_path).name} (see analysis_results.json for error).")
            else:
                 logger.warning(f"Analysis for pair {name} in {Path(csv_file_path).name} returned error results: vuln={vuln_result}, patched={patched_result}")
            continue # Skip counting towards TP/FP if there was an error for this pair

        # Update local counters based on analysis results
        if vuln_result == 1 and patched_result == 0:
            local_TP_TP += 1
        elif vuln_result == 0 and patched_result == 1:
            local_FP_FP += 1
        elif vuln_result == 1 and patched_result == 1:
            local_TP_FP += 1
        elif vuln_result == 0 and patched_result == 0:
            local_FP_TP += 1
        # Note: Cases where results are not 0 or 1 (and not -1 error) should ideally not happen
        # but adding a check or assuming they fall into RUNERROR might be robust.
        # The current logic handles -1 as RUNERROR already.

        # Store results in the summary dictionary
        final_results_summary[name] = {
            "cwe": cwe,
            "vuln_result": vuln_result,
            "patched_result": patched_result,
            "vuln_response": result_data.get("vuln_response", ""), # Store responses if needed
            "patched_response": result_data.get("patched_response", ""),
        }

    logger.info(f"\n--- Analysis Summary for {Path(csv_file_path).name} (Analyzer: {analyzer_name}) ---")
    logger.info(f"Total rows attempted from CSV: {len(df)}")
    logger.info(f"Total valid pairs processed: {local_ALL_PAIR}")
    logger.info(f"Total pairs submitted for analysis: {len(analysis_results)}") # Should be equal to local_ALL_PAIR unless filtering happens later
    logger.info(f"Successfully analyzed pairs: {local_TP_TP + local_FP_FP + local_TP_FP + local_FP_TP}")
    logger.info(f"Pairs with analysis errors: {local_RUNERROR}")
    logger.info(f"TP/TP (Correctly identified vuln, correctly identified patched): {local_TP_TP}")
    logger.info(f"FP/FP (Incorrectly identified vuln, incorrectly identified patched): {local_FP_FP}")
    logger.info(f"TP/FP (Correctly identified vuln, incorrectly identified patched): {local_TP_FP}")
    logger.info(f"FP/TP (Incorrectly identified vuln, correctly identified patched): {local_FP_TP}")

    no_judge_root = Path(NO_JUDGE_ROOT)
    if with_con:
        if not os.path.exists(no_judge_root / "with-con"):
            os.makedirs(no_judge_root / "with-con")
        results_output_file = no_judge_root / "with-con" / analyzer_name / f"{cwe_id_from_filename}_analysis_results.json" 
    else:
        if not os.path.exists(no_judge_root / "without-con"):
            os.makedirs(no_judge_root / "without-con")
        results_output_file = no_judge_root / "without-con" / analyzer_name / f"{cwe_id_from_filename}_analysis_results.json"
    if not os.path.exists(results_output_file.parent):
        os.makedirs(results_output_file.parent)
    try:
        with open(results_output_file, "w") as f:
             json.dump(final_results_summary, f, indent=4)
        logger.info(f"Saved analysis results for {Path(csv_file_path).name} to {results_output_file}.")
    except Exception as e:
         logger.error(f"Error saving analysis results to {results_output_file}: {e}", exc_info=True)

    # Return the summary counts and status for the orchestrator
    return {
         "csv_file": Path(csv_file_path).name,
         "total_rows_in_csv": len(df),
         "valid_pairs_processed": processed_count,
         "pairs_submitted_to_analyzer": len(analysis_results),
         "TP_TP": local_TP_TP,
         "TP_FP": local_TP_FP,
         "FP_TP": local_FP_TP,
         "FP_FP": local_FP_FP,
         "RUNERROR": local_RUNERROR,
         "status": "Completed" if local_RUNERROR < len(analysis_results) else "Completed with errors" # Simple status
    }

if __name__ == "__main__":
    # Example usage
    # 1