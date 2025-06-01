import json
import hashlib
import re
import ast
from pathlib import Path
import os
from typing import List, Dict, Any, Optional

def result_fingerprint(result):
    """
    Generate a hash fingerprint for a tool result, ensuring all types are serializable.
    """
    try:
        norm = json.dumps(result, sort_keys=True, ensure_ascii=True, default=str)
    except Exception:
        norm = str(result)
    return hashlib.md5(norm.encode('utf-8')).hexdigest()

def deduplicate_tool_results(tool_results):
    """
    Deduplicate tool results based on their fingerprint.
    """
    seen = {}
    deduped = []

    for r in tool_results:
        if "result" not in r:
            continue  # skip malformed entries

        fp = result_fingerprint(r["result"])
        if fp not in seen:
            seen[fp] = True
            deduped.append(r)

    return deduped

def clean_tool_signature(tool_str):
    try:
        if not isinstance(tool_str, str):
            return tool_str

        match = re.match(r"^([\w_]+\.[\w_]+)$(\{.*\})$$", tool_str)
        if not match:
            return tool_str

        tool_name, param_str = match.groups()
        params = ast.literal_eval(param_str)

        for k in ["project_dir"]:
            params.pop(k, None)

        cleaned = f"{tool_name}({json.dumps(params, sort_keys=True)})"
        return cleaned
    except Exception:
        return tool_str


def filter_analysis_history(history: List[Dict]) -> List[Dict]:
    filtered_history_summary = []
    
    # 1. Find and include the initial analysis summary (without the prompt text)
    initial_state = next((item for item in history if item.get("stage") == "initial"), None)
    if initial_state and isinstance(initial_state.get("result"), dict):
        # Keep key fields from initial analysis result
        initial_summary = {
            "stage": "initial",
            "result": {
                "language": initial_state["result"].get("language"),
                "vulnerability_type": initial_state["result"].get("vulnerability_type"),
                "repair_strategy": initial_state["result"].get("repair_strategy"),
                "required_context": initial_state["result"].get("required_context", ""),
                "root_cause": initial_state["result"].get("root_cause", ""),
            }
        }
        filtered_history_summary.append(initial_summary)

    # 2. Summarize subsequent collection and analysis steps
    subsequent_steps = [item for item in history if item.get("stage") in ["collection", "analysis"]]
    
    summaries_list = []
    for item in subsequent_steps:
        if item.get("stage") == "collection":
            deduped_results = deduplicate_tool_results(item.get("results", []))
            summary = process_and_label_context(deduped_results)
            collect_summary = {
                "stage": "collection",
                "result": summary
            }
            summaries_list.append(collect_summary)
        elif item.get("stage") == "analysis":
            result = item.get("result")
            if isinstance(result, dict):
                summary = {
                    "stage": "analysis",
                    "need_context": result.get("need_context", ""), 
                    "root_cause_partial": result.get("root_cause", ""),
                    "required_context_next": result.get("required_context", ""), 
                    "analysis_summary_text": result.get("analysis", "") 
                }
                summaries_list.append(summary)

    filtered_history_summary.extend(summaries_list)
    return filtered_history_summary


def save_result_to_json(result, save_path, file_name):
    save_path = Path(save_path)
    save_path.mkdir(parents=True, exist_ok=True)

    file_path = save_path / file_name

    def convert_posixpath(obj):
        if isinstance(obj, Path):
            return str(obj)
        return obj

    for key in ['file_cache', 'cpg_file', 'base_url', 'joern', 'need_context', 'project_dir', 'prompt_version']:
        result.pop(key, None)

    json_data = json.dumps(
        result,
        default=convert_posixpath,
        indent=4,
        ensure_ascii=False
    )

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(json_data)
    print(f"Result saved to {file_path}")

def parse_tool_string_from_example(tool_str: str) -> tuple[Optional[str], Optional[Dict]]:
    """
    Parses a tool string formatted like "tool_type.sub_tool({'param': 'value'})".
    Returns the full tool name (e.g., 'caller_info.find_caller_for_func_file') and the parsed params dict.
    Handles potential parsing errors.
    """
    tool_str = tool_str.strip()
    first_paren = tool_str.find('(')

    if first_paren == -1:
        # No parameters part found
        return tool_str, {} # Return tool name, empty params dict

    tool_name = tool_str[:first_paren].strip()
    params_str = tool_str[first_paren + 1:].strip().rstrip(')') # Get string inside parens

    if not tool_name: # Handle cases like just "({})" or malformed strings starting with '('
         return None, None

    try:
        # Safely evaluate the parameters string as a Python literal (should be a dict)
        params = ast.literal_eval(params_str)
        if not isinstance(params, dict):
             # The part inside parens wasn't a dictionary string, treat as no valid params
             return tool_name, {}

        return tool_name, params
    except (SyntaxError, ValueError):
        # Handle errors during literal evaluation, treat as no valid params
        return tool_name, {}

# Helper function to clean the result payload
def _clean_redundant_type_field(data: Any) -> Any:
    """
    Recursively removes the 'type' key if its value is a string.
    This is intended to remove redundant 'type' fields added by the tool formatter
    when the source identifier already indicates the type.
    Creates new dicts/lists to avoid modifying original data in place.
    """
    if isinstance(data, dict):
        # Create a new dict to avoid modifying the original dict in the history/state
        cleaned_dict = {}
        for key, value in data.items():
            # Skip the 'type' key if its value is a string (the redundant label added by formatter)
            if key == 'type' and isinstance(value, str):
                continue
            # Recursively clean the value
            cleaned_dict[key] = _clean_redundant_type_field(value)
        return cleaned_dict
    elif isinstance(data, list):
        cleaned_list = []
        for item in data:
            # Recursively clean each item in the list
            cleaned_list.append(_clean_redundant_type_field(item))
        return cleaned_list
    else:
        # Base case: return the data as is if it's not a dict or list
        return data


# The main cleaning/processing function
def process_and_label_context(context_list: List[Dict]) -> List[Dict]:
    """
    Filters collected context results, cleans redundant 'type' fields from results,
    and adds a clean 'source' identifier to each item.
    Discards failed/empty results.

    Args:
        context_list: A list of context items, each expected to be a dict
                      with 'tool' (string) and 'result' (any) keys,
                      and optionally 'status'.

    Returns:
        A new list containing processed and filtered context items.
        Each item is a dict with 'source' (string identifier) and 'result' (any) keys.
        Returns an empty list if the input is invalid or yields no valid results.
    """
    if not isinstance(context_list, list):
        return [] # Return empty if input is not a list

    processed_context = []

    for item in context_list:
        if not isinstance(item, dict):
             continue # Skip if item is not a dictionary

        result = item.get('result')
        tool_str = item.get('tool')

        # --- Discarding Logic ---
        if result is None:
            continue # Discard None results
        if isinstance(result, str) and result in ["no valid result", "no valid result, and fuzzy match failed", "no valid result, Query timed out"]:
            continue # Discard specific magic failure strings
        if item.get('status') in ["context error", "error"]:
             continue # Discard items marked with error status

        # Ensure 'tool' string is present for identifying the source
        if not isinstance(tool_str, str):
             # If tool string is missing or not a string, skip this item
             continue

        # --- Creating Clean Source Identifier ---
        tool_name, params = parse_tool_string_from_example(tool_str) # Use the parser

        if not tool_name or '.' not in tool_name: # Must have tool_type.sub_tool format
             continue

        tool_type = tool_name.split('.')[0] # Extract tool type (e.g., 'caller_info')

        # Build a concise identifier including key parameters (file, line, func, value, query preview)
        key_params_for_identifier = {}
        if params: # Only look for params if parsing was successful
             if 'file_path' in params and isinstance(params['file_path'], str):
                 # Use basename for brevity, handle potential empty string
                 key_params_for_identifier['file'] = os.path.basename(params['file_path']) if params['file_path'] else 'N/A'
             if 'start_line' in params and 'end_line' in params:
                 # Check if they are numbers before formatting
                 if isinstance(params['start_line'], (int, float)) and isinstance(params['end_line'], (int, float)):
                    key_params_for_identifier['lines'] = f"{int(params['start_line'])}-{int(params['end_line'])}"
             elif 'line' in params: # Handle single 'line' parameter if present
                 if isinstance(params['line'], (int, float)):
                     key_params_for_identifier['line'] = int(params['line'])

             if 'func_name' in params and isinstance(params['func_name'], str):
                 # Use last part if qualified name like com.package.Class.funcName or funcName:returnType
                 name_parts = params['func_name'].replace(':', '.').split('.')
                 key_params_for_identifier['func'] = name_parts[-1] if name_parts[-1] else params['func_name'] # Fallback to full name if last part is empty

             if 'value_name' in params and isinstance(params['value_name'], str):
                 key_params_for_identifier['value'] = params['value_name']
             if tool_name.startswith('query.'):
                 query_param_value = params.get('query')
                 if query_param_value is not None:
                     query_str = str(query_param_value)
                     key_params_for_identifier['query'] = query_str[:50] + "..." if len(query_str) > 50 else query_str

        identifier_details = ", ".join([f"{k}:{v}" for k, v in key_params_for_identifier.items()])

        # Construct the source identifier in the desired format: "tool_type(details)"
        if identifier_details:
            source_identifier = f"{tool_type}({identifier_details})"
        else:
            source_identifier = tool_type # Just tool_type if no key details


        cleaned_result_payload = _clean_redundant_type_field(result)

        processed_context.append({
            "source": source_identifier,
            "result": cleaned_result_payload # Use the cleaned result
        })

    return processed_context


