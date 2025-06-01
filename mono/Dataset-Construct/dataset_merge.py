import os
import json
import csv as standard_csv
import shutil
import ast
from collections import defaultdict


PLATFORMS = ["github"]
CVE_ROOT_BASE = "../storage/result/Part2_result"
global_output_base_dir = "../storage/result/Part2_result/merged_dataset"
output_base_dir = "../storage/result/Part2_result/merged_dataset/platforms"
ERROR_TRACKER = defaultdict(list) 

def safe_read_json(filepath):
    """Safely reads a JSON file, returns None if file doesn't exist or is invalid."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        # print(f"Error: Invalid JSON in file: {filepath}") # This can be very noisy
        return None
    except Exception as e:
        # print(f"Error reading file {filepath}: {e}") # This can be very noisy
        return None

def safe_read_text(filepath):
    """Safely reads a text file, returns None if file doesn't exist or is empty."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            return content if content else None
    except Exception as e:
        # print(f"Error reading text file {filepath}: {e}") # This can be very noisy
        return None

def read_success_file(success_filepath, cve_root_for_platform):
    """Reads the success file and returns a list of (cve_id, cve_input_path) tuples."""
    processed_cves = []
    if not os.path.exists(success_filepath):
        print(f"Error: Success file not found: {success_filepath}")
        return processed_cves

    try:
        with open(success_filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue # Skip empty lines and comments

                parts = line.split(',')
                cve_id = parts[0].strip()
                cve_input_path = ""

                if len(parts) >= 2: # Expect at least CVE ID and path
                    cve_input_path = parts[1].strip()
                else: # Handle case where only CVE ID is provided
                    cve_input_path = os.path.join(cve_root_for_platform, cve_id)
                
                if os.path.isdir(cve_input_path):
                    processed_cves.append((cve_id, cve_input_path))
                else:
                    print(f"Warning: Input directory not found for {cve_id}: {cve_input_path}")
    except Exception as e:
        print(f"Error reading success file {success_filepath}: {e}")

    print(f"Found {len(processed_cves)} successfully processed CVEs listed in {success_filepath}.")
    return processed_cves

def parse_tool_string(tool_str):
    """Parses the tool string format 'tool_name({...})'."""
    if not isinstance(tool_str, str):
        return None, None

    param_start = tool_str.find('(')
    if param_start == -1:
        return tool_str.strip(), None

    tool_name = tool_str[:param_start].strip()
    param_string = tool_str[param_start + 1 :].strip()

    if param_string.endswith(')'):
        param_string = param_string[:-1].strip()

    if not param_string:
        return tool_name, {}

    try:
        params = ast.literal_eval(param_string)
        if not isinstance(params, dict):
            # print(f"Warning: Tool parameters not in dictionary format: {param_string}") # Too noisy
            return tool_name, None
        return tool_name, params
    except (SyntaxError, ValueError) as e:
        # print(f"Warning: Failed to parse tool parameters string '{param_string}': {e}") # Too noisy
        return tool_name, None
    except Exception as e:
        # print(f"Warning: Unexpected error parsing tool parameters string '{param_string}': {e}") # Too noisy
        return tool_name, None

def _clean_redundant_type_field(result):
    """Recursively cleans a 'type' field from result dictionaries."""
    if isinstance(result, list):
        return [_clean_redundant_type_field(item) for item in result]
    elif isinstance(result, dict):
        cleaned_result = result.copy()
        if 'type' in cleaned_result:
            del cleaned_result['type']
        for key, value in cleaned_result.items():
            cleaned_result[key] = _clean_redundant_type_field(value)
        return cleaned_result
    else:
        return result

def process_cve_directory(cve_id, cve_input_path, platform_output_path, platform_name):
    """Processes a single CVE directory, extracts data, and organizes output."""
    print(f"Processing CVE: {cve_id} for platform: {platform_name} from path: {cve_input_path}")

    # Define input file paths
    all_part1_json_path = os.path.join(cve_input_path, f"{cve_id}-all-part1.json")
    context_preprocess_json_path = os.path.join(cve_input_path, "context_preprocess.json")
    
    root_cause_json_path = os.path.join(cve_input_path, "Root_cause_analysis.json")
    root_cause_json_path_06 = os.path.join(cve_input_path, "Root_cause_analysis_06.json")
    root_cause_json_path_top10 = os.path.join(cve_input_path, "Root_cause_analysis_top10.json")

    patch_before_dir_input = os.path.join(cve_input_path, "patch_before")
    patch_after_dir_input = os.path.join(cve_input_path, "patch_after")
    joern_before_context_dir_input = os.path.join(cve_input_path, "Joern_file", "before_context")
    if not os.path.exists(joern_before_context_dir_input):
        joern_before_context_dir_input = os.path.join(cve_input_path, "Joern_files", "before_context")

    # Load necessary data
    all_part1_data = safe_read_json(all_part1_json_path)
    context_preprocess_data = safe_read_json(context_preprocess_json_path)

    # Prioritize root cause files
    root_cause_data = None
    actual_root_cause_json_path_used = None
    if os.path.exists(root_cause_json_path_06):
        root_cause_data = safe_read_json(root_cause_json_path_06)
        actual_root_cause_json_path_used = root_cause_json_path_06
    elif os.path.exists(root_cause_json_path_top10):
        root_cause_data = safe_read_json(root_cause_json_path_top10)
        actual_root_cause_json_path_used = root_cause_json_path_top10
    elif os.path.exists(root_cause_json_path):
        root_cause_data = safe_read_json(root_cause_json_path)
        actual_root_cause_json_path_used = root_cause_json_path

    # Check for essential data
    if not all_part1_data or not root_cause_data:
        print(f"Skipping {cve_id}: Missing essential JSON files. all_part1_data: {bool(all_part1_data)}, root_cause_data: {bool(root_cause_data)}")
        ERROR_TRACKER[platform_name].append(cve_id)
        return None, None

    stats = all_part1_data.get("stats", {})
    raw_data = all_part1_data.get("raw_data", {})
    original_enriched_data = root_cause_data.get("enriched_data", [])
    language = stats.get("language", "N/A") 
    
    raw_cwe_list = context_preprocess_data[0].get("cwe_ids", "N/A") if context_preprocess_data else "N/A"
    description = context_preprocess_data[0].get("description", "N/A") if context_preprocess_data else "N/A"
    other_information = context_preprocess_data[0].get("other_information", "N/A") if context_preprocess_data else "N/A"
    
    if description:
        description = description.replace('\n', '\\n').replace('\r', '\\r')
    if other_information:
        other_information = str(other_information).replace('\n', '\\n').replace('\r', '\\r')
    
    if not isinstance(raw_cwe_list, list):
        # print(f"Warning: Expected list for cwe_ids in {cve_id} stats, but got {type(raw_cwe_list)}. Defaulting to empty list.") # Too noisy
        raw_cwe_list = []
    cwe_ids_str = ", ".join(cwe.strip() for cwe in raw_cwe_list if isinstance(cwe, str) and cwe.strip())

    commit_url = context_preprocess_data[0].get("git_url", "N/A") if context_preprocess_data else "N/A"
    commit_msg = context_preprocess_data[0].get("commit_msg", "N/A") if context_preprocess_data else "N/A"
    if commit_msg:
        commit_msg = commit_msg.replace('\n', '\\n').replace('\r', '\\r')
    patch_nums = stats.get("sec_vul", {}).get("num", 0) + stats.get("non_sec_vul", {}).get("num", 0)

    # Collect func_before and func_after with targets
    func_before_list = []
    func_after_list = []

    target_mapping = {}
    non_sec_vul_types = stats.get("non_sec_vul", {}).get("types", {})
    type_counter = 1
    for type_name in non_sec_vul_types.keys():
        target_mapping[type_name] = type_counter
        type_counter += 1

    sec_vul_identifiers = set()
    for item in stats.get("sec_vul", {}).get("no_more_info", []):
        sec_vul_identifiers.add(item.replace('.json', ''))
    for item in stats.get("sec_vul", {}).get("main_dir", []):
        sec_vul_identifiers.add(item.replace('.json', ''))

    non_sec_vul_identifiers = defaultdict(set)
    for type_name, target_num in target_mapping.items():
        for item in non_sec_vul_types.get(type_name, {}).get("no_more_info", []):
            non_sec_vul_identifiers[type_name].add(item.replace('.json', ''))
        for item in non_sec_vul_types.get(type_name, {}).get("main_dir", []):
            non_sec_vul_identifiers[type_name].add(item.replace('.json', ''))


    for key, entry_data in raw_data.items():
        func_name = entry_data.get("func_name", "N/A")
        file_path = entry_data.get("file_path", "N/A")
        func_before_code = entry_data.get("func_before", "N/A")
        func_after_code = entry_data.get("func", "N/A")

        current_target = -1
        part_identifier = key

        if part_identifier in sec_vul_identifiers:
            current_target = 0
        else:
            for type_name, target_num in target_mapping.items():
                if part_identifier in non_sec_vul_identifiers[type_name]:
                    current_target = target_num
                    break

        func_before_list.append({"func_name": func_name, "file_path": file_path, "func_code": func_before_code, "target": current_target})
        func_after_list.append({"func_name": func_name, "file_path": file_path, "func_code": func_after_code})

    # Process, filter, and count context from original_enriched_data
    processed_context = []
    context_counts = defaultdict(int)
    count_category_map = {
        "caller_info": "caller",
        "func_info": "function",
        "code_info": "code",
        "value_info": "value",
        "query_info": "query" 
    }

    for item in original_enriched_data:
        if not isinstance(item, dict):
            continue

        result = item.get('result')
        tool_str = item.get('tool')

        if result is None:
            continue

        result_str_check = str(result).lower()
        if "no valid" in result_str_check or "erorr query" in result_str_check or "error" in result_str_check: 
            continue

        if not isinstance(tool_str, str):
            continue 

        tool_name, params = parse_tool_string(tool_str) 

        if not tool_name or '.' not in tool_name: 
            continue

        tool_type = tool_name.split('.')[0] 
        key_params_for_identifier = {}
        if params: 
            if 'file_path' in params and isinstance(params['file_path'], str):
                key_params_for_identifier['file'] = os.path.basename(params['file_path']) if params['file_path'] else 'N/A'
            if 'start_line' in params and 'end_line' in params:
                if isinstance(params['start_line'], (int, float)) and isinstance(params['end_line'], (int, float)):
                    key_params_for_identifier['lines'] = f"{int(params['start_line'])}-{int(params['end_line'])}"
            elif 'line' in params:
                if isinstance(params['line'], (int, float)):
                    key_params_for_identifier['line'] = int(params['line'])

            if 'func_name' in params and isinstance(params['func_name'], str):
                name_parts = params['func_name'].replace(':', '.').split('.')
                func_short_name = next((part for part in reversed(name_parts) if part), params['func_name'])
                key_params_for_identifier['func'] = func_short_name

            if 'value_name' in params and isinstance(params['value_name'], str):
                key_params_for_identifier['value'] = params['value_name']

            if tool_type == 'query_info' and 'query_string' in params and isinstance(params['query_string'], str):
                query_str = params['query_string']
                key_params_for_identifier['query'] = query_str[:50] + "..." if len(query_str) > 50 else query_str

        identifier_details = ", ".join([f"{k}:{v}" for k, v in key_params_for_identifier.items()])

        if identifier_details:
            source_identifier = f"{tool_type}({identifier_details})"
        else:
            source_identifier = tool_type

        cleaned_result_payload = _clean_redundant_type_field(result)

        processed_context.append({
            "source": source_identifier,
            "result": cleaned_result_payload
        })

        count_category = count_category_map.get(tool_type)
        if count_category:
            context_counts[count_category] += 1

    context_nums_str = json.dumps(dict(context_counts))
    context_data_str = json.dumps(processed_context, ensure_ascii=False)

    root_cause_text = root_cause_data.get("root_cause", "N/A")
    if isinstance(root_cause_text, str):
        root_cause_text = root_cause_text.replace('\n', '\\n').replace('\r', '\\r')
    elif isinstance(root_cause_text, list):
        if all(isinstance(item, str) for item in root_cause_text):
            root_cause_text = " ".join(root_cause_text).replace('\n', '\\n').replace('\r', '\\r')
        elif all(isinstance(item, dict) for item in root_cause_text):
            root_cause_text = json.dumps(root_cause_text, ensure_ascii=False).replace('\n', '\\n').replace('\r', '\\r')
        elif all(isinstance(item, (str, dict)) for item in root_cause_text):
            root_cause_text = " ".join([str(item) for item in root_cause_text]).replace('\n', '\\n').replace('\r', '\\r')
    elif isinstance(root_cause_text, dict):
        root_cause_text = json.dumps(root_cause_text, ensure_ascii=False).replace('\n', '\\n').replace('\r', '\\r')
    else:
        root_cause_text = "N/A"
    
    analysis = root_cause_data.get("analysis", {})
    need_context = analysis.get("need_context", "N/A")
    if need_context == True or str(need_context).lower() == "true":
        print(f"Warning: 'need_context' is True for {cve_id}, skipping this CVE.")
        ERROR_TRACKER[platform_name].append(cve_id)
        return None, None 
        
    confidence_score = root_cause_data.get("confidence_score", "N/A")

    # Prepare output directories for other_context
    # This path is now relative to the global_output_base_dir/other_context
    relative_other_context_path = os.path.join(platform_name, cve_id)
    cve_output_base = os.path.join(global_output_base_dir, "other_context", relative_other_context_path)
    
    patch_before_dir_output = os.path.join(cve_output_base, "patch_before")
    patch_after_dir_output = os.path.join(cve_output_base, "patch_after")

    os.makedirs(cve_output_base, exist_ok=True)
    if os.path.exists(patch_before_dir_input):
        os.makedirs(patch_before_dir_output, exist_ok=True)
        try:
            shutil.copytree(patch_before_dir_input, patch_before_dir_output, dirs_exist_ok=True)
        except Exception as e:
            print(f"Error copying patch_before for {cve_id}: {e}")

    if os.path.exists(patch_after_dir_input):
        os.makedirs(patch_after_dir_output, exist_ok=True)
        try:
            shutil.copytree(patch_after_dir_input, patch_after_dir_output, dirs_exist_ok=True)
        except Exception as e:
            print(f"Error copying patch_after for {cve_id}: {e}")

    if actual_root_cause_json_path_used and os.path.exists(actual_root_cause_json_path_used):
        try:
            shutil.copy(actual_root_cause_json_path_used, cve_output_base)
        except Exception as e:
            print(f"Error copying Root_cause_analysis.json for {cve_id}: {e}")


    # Build and write Joern_context.json
    joern_context_data = {}
    joern_context_data["cve_id"] = cve_id
    joern_context_data["cwe_id"] = cwe_ids_str
    joern_context_data["commit_url"] = commit_url
    joern_context_data["patch_names"] = [{"func_name": entry["func_name"], "file_path": entry["file_path"]} for entry in func_before_list]

    patched_files_info = defaultdict(list)
    for key, data in raw_data.items():
        file_path = data.get("file_path", "N/A")
        if file_path != "N/A":
            patched_files_info[file_path].append({
                "func_name": data.get("func_name", "N/A"),
                "patch": data.get("diff_func", "N/A")
            })

    before_context_list = []
    for file_path, patches_in_file in patched_files_info.items():
        file_base_name = os.path.basename(file_path)
        context_entry = {"file_path": file_path, "patch": patches_in_file}

        if joern_before_context_dir_input and os.path.exists(joern_before_context_dir_input):
            methods_file_path = os.path.join(joern_before_context_dir_input, f"methods_{file_base_name}.txt")
            methods_file = safe_read_text(methods_file_path)
            if methods_file is not None:
                context_entry[f"related_methods_{file_base_name.replace('.', '_')}"] = methods_file.splitlines()

            bfs_json_path = os.path.join(joern_before_context_dir_input, f"bfs_{file_base_name}.json")
            bfs_json = safe_read_json(bfs_json_path)
            if bfs_json is not None:
                context_entry[f"bfs_{file_base_name.replace('.', '_')}"] = bfs_json

            pdg_json_path = os.path.join(joern_before_context_dir_input, f"pdg_{file_base_name}.json")
            pdg_json = safe_read_json(pdg_json_path)
            if pdg_json is not None:
                context_entry[f"pdg_{file_base_name.replace('.', '_')}"] = pdg_json

        before_context_list.append(context_entry)

    joern_context_data["before_context"] = before_context_list

    file_cache = []
    if context_preprocess_data and isinstance(context_preprocess_data, list) and context_preprocess_data:
        file_cache = context_preprocess_data[0].get("before_cpg_file_cache", [])
    joern_context_data["file_cache_in_old_repos"] = file_cache

    joern_context_json_path = os.path.join(cve_output_base, "Joern_context.json")
    try:
        with open(joern_context_json_path, 'w', encoding='utf-8') as f:
            json.dump(joern_context_data, f, indent=4)
    except Exception as e:
        print(f"Error writing Joern_context.json for {cve_id}: {e}")

    # Prepare CSV row data
    func_before_json_str = json.dumps(func_before_list, ensure_ascii=False)
    func_after_json_str = json.dumps(func_after_list, ensure_ascii=False)

    csv_row = [
        platform_name, 
        cve_id,
        cwe_ids_str,
        language,
        description,
        commit_url,
        commit_msg,
        other_information,
        patch_nums,
        func_before_json_str,
        func_after_json_str,
        context_nums_str,
        context_data_str,
        root_cause_text,
        confidence_score,
        os.path.join("./other_context", relative_other_context_path) # Updated path for merged CSV
    ]

    stats_update = {
        "cwe_counts": {cwe.strip(): 1 for cwe in raw_cwe_list if isinstance(cwe, str) and cwe.strip()},
        "patch_count": patch_nums,
        "context_counts": dict(context_counts) 
    }

    return csv_row, stats_update

def main():
    print(f"Starting processing for all platforms...")

    # Ensure global output directory exists
    os.makedirs(global_output_base_dir, exist_ok=True)
    os.makedirs(os.path.join(global_output_base_dir, "other_context"), exist_ok=True)

    all_cve_rows_for_merged_csv = []
    overall_stats_aggregator = {
        "total_cves_processed": 0,
        "total_patches_processed": 0,
        "total_context_caller": 0,
        "total_context_function": 0,
        "total_context_code": 0,
        "total_context_value": 0,
        "total_context_query": 0,
        "cwe_counts_overall": defaultdict(int),
        "platform_specific_stats": {}
    }
    
    global_csv_header = [
        "id",
        "platform",
        "cve_id",
        "cwe_id",
        "language",
        "description",
        "commit_url",
        "commit_msg",
        "other_information",
        "patch_nums",
        "func_before",
        "func_after",
        "context_nums",
        "context_data",
        "root_cause",
        "confidence_score",
        "other_context_path"
    ]

    for platform_name in PLATFORMS:
        print(f"\n--- Processing platform: {platform_name} ---")
        
        cve_root_for_platform = os.path.join(CVE_ROOT_BASE, platform_name)
        success_file_path = f"/RQs/RQ2/Dataset_Statistic/finals/{platform_name}/Success.txt"
        
        platform_output_path = os.path.join(output_base_dir, platform_name) # Individual platform output dir
        os.makedirs(platform_output_path, exist_ok=True)

        # Load existing stats for this platform (for individual stats file)
        stats_json_filepath_platform = os.path.join(platform_output_path, f"{platform_name}.json")
        current_platform_stats = {
            "platform": platform_name,
            "total_cves": 0,
            "cwe_counts": defaultdict(int),
            "total_patches": 0,
            "total_context_caller": 0,
            "total_context_function": 0,
            "total_context_code": 0,
            "total_context_value": 0,
            "total_context_query": 0,
        }
        if os.path.exists(stats_json_filepath_platform):
            with open(stats_json_filepath_platform, 'r', encoding='utf-8') as f:
                loaded_stats = json.load(f)
                current_platform_stats.update(loaded_stats)
                if 'cwe_counts' in loaded_stats:
                    current_platform_stats['cwe_counts'] = defaultdict(int, loaded_stats['cwe_counts'])

        processed_cves_list = read_success_file(success_file_path, cve_root_for_platform)
        
        # Determine already processed CVEs for this platform based on output directory
        already_processed_cves_for_platform = set()
        platform_other_context_dir = os.path.join(global_output_base_dir, "other_context", platform_name)
        if os.path.exists(platform_other_context_dir):
            already_processed_cves_for_platform = set(os.listdir(platform_other_context_dir))

        new_cves_processed_for_platform = 0

        for cve_id, cve_input_path in processed_cves_list:
            if cve_id in already_processed_cves_for_platform:
                # print(f"Skipping already processed CVE for {platform_name}: {cve_id}") # Too noisy
                continue

            csv_row, stats_update = process_cve_directory(cve_id, cve_input_path, platform_output_path, platform_name)
            if csv_row:
                all_cve_rows_for_merged_csv.append(csv_row)
                new_cves_processed_for_platform += 1
                
                # Update platform-specific statistics
                current_platform_stats["total_cves"] += 1
                current_platform_stats["total_patches"] += stats_update["patch_count"]
                for cwe, count in stats_update["cwe_counts"].items():
                    current_platform_stats["cwe_counts"][cwe] += count
                for context_type, count in stats_update["context_counts"].items():
                    current_platform_stats[f"total_context_{context_type}"] += count
        
        # Finalize and save platform-specific stats
        num_cves_platform = current_platform_stats["total_cves"]
        current_platform_stats["average_patches_per_cve"] = current_platform_stats["total_patches"] / num_cves_platform if num_cves_platform > 0 else 0
        total_context_items_platform = current_platform_stats["total_context_caller"] + current_platform_stats["total_context_function"] + \
                                      current_platform_stats["total_context_code"] + current_platform_stats["total_context_value"] + \
                                      current_platform_stats["total_context_query"]
        current_platform_stats["average_context_items_per_cve"] = total_context_items_platform / num_cves_platform if num_cves_platform > 0 else 0
        current_platform_stats["cwe_counts"] = dict(current_platform_stats["cwe_counts"]) # Convert back to dict for JSON

        with open(stats_json_filepath_platform, 'w', encoding='utf-8') as f:
            json.dump(current_platform_stats, f, indent=4)
        print(f"Updated statistics for {platform_name} written to: {stats_json_filepath_platform}")

        overall_stats_aggregator["platform_specific_stats"][platform_name] = current_platform_stats
        overall_stats_aggregator["total_cves_processed"] += new_cves_processed_for_platform # Only sum newly processed for overall
        print(f"Total new CVEs processed for {platform_name} this run: {new_cves_processed_for_platform}")
        print(f"Error CVEs for {platform_name}: {ERROR_TRACKER[platform_name]}")


    # --- Merge and Write Global CSV ---
    print("\n--- Merging all CVE data into a single CSV ---")
    # Prioritize GitHub entries
    all_cve_rows_for_merged_csv.sort(key=lambda x: 0 if x[0] == "github" else 1) # x[0] is the platform name

    global_csv_filepath = os.path.join(global_output_base_dir, "all_platforms_cves.csv")
    with open(global_csv_filepath, 'w', newline='', encoding='utf-8') as f:
        writer = standard_csv.writer(f)
        writer.writerow(global_csv_header)
        for i, row in enumerate(all_cve_rows_for_merged_csv):
            writer.writerow([i + 1] + row) # Add global ID

    print(f"Merged CSV containing {len(all_cve_rows_for_merged_csv)} CVEs written to: {global_csv_filepath}")

    # --- Generate Overall Statistics ---
    print("\n--- Generating overall statistics across all platforms ---")
    for platform_stats in overall_stats_aggregator["platform_specific_stats"].values():
        overall_stats_aggregator["total_patches_processed"] += platform_stats["total_patches"]
        overall_stats_aggregator["total_context_caller"] += platform_stats["total_context_caller"]
        overall_stats_aggregator["total_context_function"] += platform_stats["total_context_function"]
        overall_stats_aggregator["total_context_code"] += platform_stats["total_context_code"]
        overall_stats_aggregator["total_context_value"] += platform_stats["total_context_value"]
        overall_stats_aggregator["total_context_query"] += platform_stats["total_context_query"]
        
        for cwe, count in platform_stats["cwe_counts"].items():
            overall_stats_aggregator["cwe_counts_overall"][cwe] += count

    num_cves_total = sum(s["total_cves"] for s in overall_stats_aggregator["platform_specific_stats"].values())
    overall_stats_aggregator["total_cves_overall"] = num_cves_total # Total CVEs regardless of whether they were processed this run
    overall_stats_aggregator["average_patches_per_cve_overall"] = overall_stats_aggregator["total_patches_processed"] / num_cves_total if num_cves_total > 0 else 0
    total_context_items_overall = overall_stats_aggregator["total_context_caller"] + overall_stats_aggregator["total_context_function"] + \
                                  overall_stats_aggregator["total_context_code"] + overall_stats_aggregator["total_context_value"] + \
                                  overall_stats_aggregator["total_context_query"]
    overall_stats_aggregator["average_context_items_per_cve_overall"] = total_context_items_overall / num_cves_total if num_cves_total > 0 else 0
    overall_stats_aggregator["cwe_counts_overall"] = dict(overall_stats_aggregator["cwe_counts_overall"])

    overall_stats_json_filepath = os.path.join(global_output_base_dir, "overall_stats.json")
    with open(overall_stats_json_filepath, 'w', encoding='utf-8') as f:
        json.dump(overall_stats_aggregator, f, indent=4)
    print(f"Overall statistics written to: {overall_stats_json_filepath}")

    print("\nAll processing complete.")
    print(f"All individual CVE data organized under: {os.path.join(global_output_base_dir, 'other_context')}")
    print("\nSummary of errors per platform:")
    for platform, errors in ERROR_TRACKER.items():
        if errors:
            print(f"  {platform}: {len(errors)} errors ({', '.join(errors)})")
        else:
            print(f"  {platform}: No errors reported.")

if __name__ == "__main__":
    main()