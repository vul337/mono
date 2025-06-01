import csv
import json
import os
import re
import difflib
import sys
from typing import Optional, Dict, List
from logging_helper import global_logger
from git_utlis.github_helper import (
    handle_github_commit,
    get_pr_info,
    get_repo_info,
    smart_limit
)

def extract_func_name(code: str) -> Optional[str]:
    """
    "public String toString() {" -> "toString"
    "def my_func(" -> "my_func"
    "function test{" -> "test"
    """

    pattern = r'.*\b(\w+)\s*[({]'
    
    for line in code.split('\n'):
        line = line.strip()
        match = re.search(pattern, line)
        if match:
            func_name = match.group(1)
            global_logger.debug(f"Raw match: {line} → Extracted: {func_name}")
            return func_name
    
    global_logger.warning(f"Function name not found in code snippet:\n{code}")
    return None

def generate_custom_diff(func_before: str, func_after: str) -> str:
    """Generate unified diff with context awareness"""
    differ = difflib.Differ()
    diff = differ.compare(
        func_before.splitlines(),
        func_after.splitlines()
    )
    
    # Filter and format diff lines
    processed = []
    for line in diff:
        if line.startswith('  '):  # Context line
            processed.append(f' {line[2:]}')
        elif line.startswith('- '):
            processed.append(f'-{line[2:]}')
        elif line.startswith('+ '):
            processed.append(f'+{line[2:]}')
    
    return "--- func_before\n+++ func_after\n" + '\n'.join(processed)

def extract_api_diff(full_patch: str, func_name: str, max_context: int = 3) -> Optional[str]:
    if not full_patch or not func_name:
        return None

    try:
        pattern = re.compile(
            r'^@@ -(\d+),\d+ \+(\d+),\d+ @@.*\n'  
            r'((?:^[ +-].*\n)*?)'                
            r'(?=^@@|\Z)',                         
            re.MULTILINE
        )

        filtered_hunks = []
        for match in pattern.finditer(full_patch):
            hunk_header = match.group(0)
            hunk_content = match.group(3)

            
            if re.search(rf'^[-+].*\b{re.escape(func_name)}\b', hunk_content, re.MULTILINE):
               
                func_lines = []
                brace_count = 0
                in_function = False

                for line in hunk_content.split('\n'):
                   
                    if re.match(rf'^[ +-].*\b{func_name}\b\s*\(', line):
                        in_function = True
                        brace_count = 0

                    if in_function:
                       
                        brace_count += line.count('{')
                        brace_count -= line.count('}')

                     
                        if line.startswith(('+', '-')):
                            func_lines.append(line)
                        else:
                            func_lines.append(' ' + line.strip())

                
                        if brace_count <= 0 and line.strip().endswith('}'):
                            break

              
                if func_lines:
                
                    header = f"@@ -{match.group(1)} +{match.group(2)} @@"
                    filtered_hunks.append(header + '\n' + '\n'.join(func_lines))

     
        if filtered_hunks:
       
            final_diff = []
            current_context = 0
            for line in '\n'.join(filtered_hunks).split('\n'):
                if line.startswith(('+', '-')):
                    current_context = 0
                    final_diff.append(line)
                else:
                    if current_context < max_context:
                        final_diff.append(line)
                        current_context += 1
    
            return "--- func_before\n+++ func_after\n" + '\n'.join(final_diff)
    except Exception as e:
        global_logger.error(f"Error parsing API diff: {str(e)}")
        return None

def process_csv(
    input_path: str,
    output_dir: str = "csv_to_each_json",
    not_git_path: str = "not_git.csv",
    max_diff_length: int = 2000
) -> None:
    """
    Process CSV file and generate JSON artifacts
    Handles GitHub API rate limits and error logging
    """
    os.makedirs(output_dir, exist_ok=True)
    processed_count = 0
    error_count = 0

    with open(input_path, 'r', encoding='utf-8') as csvfile, \
         open(not_git_path, 'w', newline='', encoding='utf-8') as not_git_file:
        
        reader = csv.DictReader(csvfile)
        not_git_writer = csv.DictWriter(not_git_file, fieldnames=reader.fieldnames)
        not_git_writer.writeheader()
        
        for idx, row in enumerate(reader):
            smart_limit()  # Handle GitHub rate limits
            result = None
            commit_url = row['commit_url']
            
            try:
                if 'github.com' not in commit_url:
                    raise ValueError("Non-GitHub commit")
                
                global_logger.info(f"Processing row {idx}: {commit_url}")
                

                commit_data = handle_github_commit(commit_url)
                if not commit_data or 'files' not in commit_data[0]:
                    raise ValueError("Invalid commit data")
                
                pr_url, pr_info = get_pr_info(commit_url)
                repo_owner, repo_name, commit_sha = get_repo_info(commit_url)
                
                # Prepare filename matching
                target_file = row['file_name'].replace('\\', '/')
                base_name = os.path.basename(target_file)
                
                # Find matching file in commit
                api_diff = None
                for file_info in commit_data[0]['files']:
                    if file_info['filename'].endswith(base_name):
                        if 'patch' in file_info:
                            func_name = extract_func_name(row['func_before']) or \
                                      extract_func_name(row['func_after'])
                            api_diff = extract_api_diff(file_info['patch'], func_name)
                        break
                
                # Generate diff content
                if api_diff:
                    diff_content = api_diff[:max_diff_length]
                    diff_source = 'api'
                else:
                    diff_content = generate_custom_diff(
                        row['func_before'], 
                        row['func_after']
                    )[:max_diff_length]
                    diff_source = 'custom'
                
                global_logger.debug(f"Row {idx} using {diff_source} diff")
                
                # Build result object
                result = {
                    'id': idx,
                    'language': row['language'],
                    'commit_url': commit_url,
                    'commit_sha': commit_sha,
                    'commit_msg': commit_data[0]['message'],
                    'pr_url': pr_url,
                    'pr_info': pr_info or "no more info",
                    'file_name': target_file,
                    'func_name': extract_func_name(row['func_before']) or 
                                extract_func_name(row['func_after']),
                    "func_before": row['func_before'],
                    "func_after": row['func_after'],
                    'diff_func': diff_content,
                    'diff_source': diff_source
                }
                

                output_file = os.path.join(output_dir, f"{idx}.json")
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                
                processed_count += 1
                
            except Exception as e:
                error_count += 1
                global_logger.error(f"Error processing row {idx}: {str(e)}")
                not_git_writer.writerow(row)
            
                error_file = os.path.join(output_dir, f"error_{idx}.json")
                with open(error_file, 'w', encoding='utf-8') as f:
                    error_data = {
                        'error': str(e),
                        'original_data': row
                    }
                    json.dump(error_data, f, indent=2)

    global_logger.info(
        f"Processing complete. Success: {processed_count}, Errors: {error_count}"
    )

if __name__ == "__main__":
    input_path = "./datasets/CleanVul_level_4_very_high_probability.csv"
    process_csv(input_path)