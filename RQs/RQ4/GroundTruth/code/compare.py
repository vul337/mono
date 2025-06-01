import os
import json
import shutil

def get_classification(bug_filter_str):
    """
    Determines the classification based on the 'Bug Filter' string.
    """
    if not isinstance(bug_filter_str, str):
        return "Unknown" # Handle non-string input

    bug_filter_str_lower = bug_filter_str.lower()
    if "security vulnerability fix" in bug_filter_str_lower:
        return "Security Vulnerability Fix"
    elif "testing & validation updates" in bug_filter_str_lower:
        return "Testing & Validation Updates"
    elif "defect remediation & feature upgrades" in bug_filter_str_lower:
        return "Defect Remediation & Feature Upgrades"
    elif "supporting & non-core improvements" in bug_filter_str_lower:
        return "Supporting & Non-Core Improvements"
    else:
        return "Other" # Default if no match

def collect_json_files(base_dir):
    """
    Collects all JSON file paths in a directory, mapping filenames to their full paths.
    """
    file_map = {}
    for root, _, files in os.walk(base_dir):
        for file_name in files:
            if file_name.endswith(".json"):
                file_map[file_name] = os.path.join(root, file_name)
    return file_map

def compare_json_files_by_name(base_dir1, base_dir2, diff_output_dir):
    """
    Compares JSON files by name across two directories and copies differing ones.
    """
    os.makedirs(diff_output_dir, exist_ok=True) # Ensure output directory exists

    print(f"Collecting files from {base_dir1}...")
    files_in_dir1 = collect_json_files(base_dir1) # Map filenames to paths for dir1
    print(f"Collected {len(files_in_dir1)} JSON files from Result.")

    print(f"Collecting files from {base_dir2}...")
    files_in_dir2 = collect_json_files(base_dir2) # Map filenames to paths for dir2
    print(f"Collected {len(files_in_dir2)} JSON files from Result1.")

    # Get all unique filenames present in either directory
    all_unique_filenames = set(files_in_dir1.keys()).union(set(files_in_dir2.keys()))
    print(f"Total unique filenames to compare: {len(all_unique_filenames)}")

    comparison_count = 0
    diff_count = 0

    for file_name in sorted(list(all_unique_filenames)):
        file_path1 = files_in_dir1.get(file_name) # Path in dir1, None if not found
        file_path2 = files_in_dir2.get(file_name) # Path in dir2, None if not found

        # Only compare if the file exists in BOTH directories
        if file_path1 and file_path2:
            comparison_count += 1
            try:
                # Load JSON data
                with open(file_path1, 'r', encoding='utf-8') as f1:
                    data1 = json.load(f1)
                with open(file_path2, 'r', encoding='utf-8') as f2:
                    data2 = json.load(f2)

                # Get 'Bug Filter' strings
                bug_filter1 = data1.get("Bug Filter", "")
                bug_filter2 = data2.get("Bug Filter", "")

                # Get classifications
                classification1 = get_classification(bug_filter1)
                classification2 = get_classification(bug_filter2)

                # If classifications differ, copy files
                if classification1 != classification2:
                    diff_count += 1
                    print(f"Difference found for: {file_name}")
                    print(f"  Result classification: {classification1} (from {file_path1})")
                    print(f"  Result1 classification: {classification2} (from {file_path2})")

                    # Create subfolder for differing files
                    output_sub_dir = os.path.join(diff_output_dir, os.path.splitext(file_name)[0])
                    os.makedirs(output_sub_dir, exist_ok=True)

                    # Copy files with suffixes
                    shutil.copy2(file_path1, os.path.join(output_sub_dir, f"{os.path.splitext(file_name)[0]}_0.json"))
                    shutil.copy2(file_path2, os.path.join(output_sub_dir, f"{os.path.splitext(file_name)[0]}_1.json"))
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON for {file_name} (paths: {file_path1}, {file_path2}): {e}")
            except Exception as e:
                print(f"An unexpected error occurred for {file_name}: {e}")
        elif file_path1 and not file_path2:
            print(f"Warning: '{file_name}' found in Result ({file_path1}) but not in Result1. Skipping.")
        elif not file_path1 and file_path2:
            print(f"Warning: '{file_name}' found in Result1 ({file_path2}) but not in Result. Skipping.")

    print(f"\nSummary:")
    print(f"  Total files compared (present in both directories): {comparison_count}")
    print(f"  Files with classification differences: {diff_count}")
    print(f"  Comparison finished.")

# Define base directories and output directory
base_dir_result = "/RQ4/GroundTruth/Result"
base_dir_result1 = "/RQ4/GroundTruth/Result_1"
diff_output_dir = "/RQ4/GroundTruth/diff_patch"

# Run the comparison
print("Starting comparison...")
compare_json_files_by_name(base_dir_result, base_dir_result1, diff_output_dir)
print("Script execution complete.")