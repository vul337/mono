import os
import json
import requests
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime 

file_write_lock = threading.Lock()

GITHUB_TOKENS = [
    
]

token_lock = threading.Lock()
current_token_index = 0

def get_next_github_token():
    global current_token_index
    with token_lock:
        token = GITHUB_TOKENS[current_token_index]
        current_token_index = (current_token_index + 1) % len(GITHUB_TOKENS)
        return token

# get rate limit, retry = 2
def github_rate_limit(github_token, retry = 2):
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    for attempt in range(retry):
        try:
            url = "https://api.github.com/rate_limit"
            response = requests.get(url, headers=headers)
            response.close()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"rate_limit request error for token {github_token[:5]}...: {e}")
            if attempt < retry - 1:
                print("Retrying...")
                time.sleep(2 ** attempt) 
            else:
                return None

def smart_limit(github_token, verbose=False):
    rate = github_rate_limit(github_token)
    if rate is None:
        return 
    remaining = rate['rate']['remaining']
    reset_epoch = rate['rate']['reset']
    reset = datetime.fromtimestamp(reset_epoch)

    if verbose:
        now = datetime.now()
        print(f"Token: {github_token[:5]}... | Rate Limit Remaining: {remaining} | Reset: {reset} | Current Time: {now}")

    if remaining <= 50: 
        print(f"⚠️  Rate limit nearing for token {github_token[:5]}.... Remaining requests: {remaining}")
        time_until_reset = reset - datetime.now()
        total_seconds = time_until_reset.total_seconds()
        print(f"⏳  Time until reset: {total_seconds} seconds")

        buffer = 30
        sleep_seconds = total_seconds + buffer

        print(f"💤  Sleeping for approximately {sleep_seconds} seconds...")
        while sleep_seconds > 0:
            print(f"⏰  Remaining sleep time: {sleep_seconds} seconds for token {github_token[:5]}...")
            time.sleep(min(10, sleep_seconds)) # Sleep in smaller chunks
            sleep_seconds -= 10
            if sleep_seconds < 0:
                break 

        print(f"✲️  Rate limit reset for token {github_token[:5]}.... Resuming process...")
    else:
        print(f"✅  Sufficient rate limit remaining for token {github_token[:5]}.... Continuing execution...")


def get_pr_info_from_commit_url_simple(commit_url, github_token):
    match = re.match(r"https://github.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)", commit_url)
    if not match:
        return {"error": "Invalid commit URL format."}

    owner, repo_name, commit_sha = match.groups()

    base_url = f"https://api.github.com/repos/{owner}/{repo_name}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    final_output = {
        "pr_url": None,
        "description": {
            "pr_info": {},
            "comment": []
        }
    }

    try:
        smart_limit(github_token, verbose=True) 

        pr_url_endpoint = f"{base_url}/commits/{commit_sha}/pulls"
        pr_response = requests.get(pr_url_endpoint, headers=headers)
        pr_response.raise_for_status()
        pulls = pr_response.json()

        if pulls:
            pr_data = pulls[0]
            pr_number = pr_data['number']
            final_output["pr_url"] = pr_data['html_url']
            final_output["description"]["pr_info"] = {
                "title": pr_data['title'],
                "number": pr_number
            }

            smart_limit(github_token, verbose=True) 
            comments_url_endpoint = f"{base_url}/issues/{pr_number}/comments"
            comments_response = requests.get(comments_url_endpoint, headers=headers)
            comments_response.raise_for_status()
            comments = comments_response.json()

            for comment in comments:
                final_output["description"]["comment"].append(
                    comment['body']
                )
            

            smart_limit(github_token, verbose=True) 
            commit_comments_endpoint = f"{base_url}/commits/{commit_sha}/comments"
            commit_comments_response = requests.get(commit_comments_endpoint, headers=headers)
            commit_comments_response.raise_for_status()
            commit_comments = commit_comments_response.json()

            for comment in commit_comments:
                final_output["description"]["comment"].append(
                    comment['body']
                )

        else:
            final_output["pr_url"] = None
            final_output["description"] = None

        return final_output

    except requests.exceptions.RequestException as e:
        final_output["error"] = f"HTTP Request Error: {e}"
        return final_output
    except Exception as e:
        final_output["error"] = f"An unexpected error occurred: {e}"
        return final_output

def process_cve_file(json_file_path, pr_info_log_file):
    github_token = get_next_github_token()
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if not isinstance(data, list) or not data:
            print(f"Skipping '{json_file_path}': content is empty or not a list.")
            return

        entry = data[0]
        cve_id = entry.get("cve_id")
        git_url = entry.get("git_url")

        existing_pr_url = entry.get("pr_url")
        if existing_pr_url and existing_pr_url != None:
            print(f"   '{cve_id}': 'pr_url' already exists: {existing_pr_url}. Skipping API call.")
            with file_write_lock: 
                with open(pr_info_log_file, 'a', encoding='utf-8') as log_f:
                    log_f.write(f"{cve_id}\n")
            return
        if "more_groundtruth" in entry:
            del entry["more_groundtruth"]  

        pr_data = get_pr_info_from_commit_url_simple(git_url.strip(), github_token)

        if pr_data and "error" not in pr_data and pr_data.get("pr_url") not in [None, "No related PR found"]:
            entry["pr_url"] = pr_data.get("pr_url")
            entry["other_information"] = pr_data.get("description", {})
            print(f"   '{cve_id}': Successfully found PR info. Updated {json_file_path}")
            with file_write_lock:
                with open(pr_info_log_file, 'a', encoding='utf-8') as log_f:
                    log_f.write(f"{cve_id}\n")
        else:
            error_msg = pr_data.get('error', 'No PR found or unknown error')
            
            print(f"   '{cve_id}': Failed to get PR info for {git_url} using token {github_token[:5]}...: {error_msg}")
            entry["pr_url"] = None
            entry["other_information"] = "no more info"
        

        with open(json_file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {json_file_path}")
    except Exception as e:
        print(f"An unexpected error occurred while processing {json_file_path}: {e}")



if __name__ == "__main__":
    if not GITHUB_TOKENS: 
        print("Warning: GITHUB_TOKENS list is empty. API rate limits might be lower.")
        print("Please add tokens for better performance and to access private repos.")

    base_dir = "/github"
    pr_info_log_file = "pr_info.txt"

    if not os.path.isdir(base_dir):
        print(f"Error: Base directory '{base_dir}' not found.")
        exit(1)
    
    processed = set()
    with open(pr_info_log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                processed.add(line)

    cve_dirs = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d)) and d.startswith("CVE-")]
    print(f"Found {len(cve_dirs)} CVE directories in '{base_dir}'.")
    cve_dirs = [d for d in cve_dirs if d not in processed]  # Filter out already processed CVEs
    print(f"After filtering, {len(cve_dirs)} CVE directories remain to be processed.")
    
    if not cve_dirs:
        print(f"No CVE directories found in '{base_dir}'.")
        exit(0)

    files_to_process = []
    for cve_dir_name in cve_dirs:
        cve_path = os.path.join(base_dir, cve_dir_name)
        json_file_path = os.path.join(cve_path, "context_preprocess.json")
        if os.path.isfile(json_file_path):
            files_to_process.append(json_file_path)
        else:
            print(f"Skipping '{cve_dir_name}': context_preprocess.json not found.")

    MAX_WORKERS = 50

    print(f"Starting processing of {len(files_to_process)} CVE files using {MAX_WORKERS} threads.")
    print(f"Successful CVE IDs will be logged to '{pr_info_log_file}'.")
    print("--------------------------------------------------")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {
            executor.submit(process_cve_file, file_path, pr_info_log_file): file_path
            for file_path in files_to_process
        }

        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                future.result() 
            except Exception as exc:
                print(f'Exception processing {file_path}: {exc}')

    print("\n--------------------------------------------------")
    print("All file processing tasks completed.")
    print(f"Check '{pr_info_log_file}' for successfully processed CVE IDs.")
    print("\nProcessing complete.")