import os
import json
import re
import sys
import time
import requests
from tenacity import retry, wait_exponential, stop_after_attempt
from typing import Optional, Dict, Any
import random 

from logging_helper import global_logger
from git_utlis.github_helper import handle_github_commit, smart_limit

GITHUB_TOKEN = "ghp_"
SUCCESS = 0
NON_TARGET = 0
FAIL = 0

def random_choose(num, file_path, logger=global_logger):
    valid_line = 0
    if file_path:
        with open(file_path, 'r') as f:
            while True:
                line = f.readline()
                valid_line += 1
                if not line:
                    break
            global_logger.info(f"Total count: {valid_line}")
            
            
    seed = time.time()
    random.seed(seed)
    logger.info(f"Seed: {seed}")
    idx_list = []
    num = min(num, valid_line//2)
    for _ in range(num):
        idx = random.randint(0, valid_line-1)
        idx_list.append(idx)
    logger.info(f"Choose {num} lines")
    logger.info(f"Choose index: {idx_list}")
    input("Press Enter to continue...")
    return idx_list    



@retry(wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3))
def get_repo_info(commit_id: str) -> Optional[str]:
    headers = {'Accept': 'application/vnd.github.v3+json', 'Authorization': f'token {GITHUB_TOKEN}'}
    try:
        response = requests.get(f'https://api.github.com/search/commits?q=hash:{commit_id}', headers=headers)
        if response.status_code == 200 and response.json().get('total_count', 0) > 0:
            repo = response.json()['items'][0]['repository']['full_name']
            return f'https://github.com/{repo}/commit/{commit_id}'
    except Exception as e:
        global_logger.error(f"API Error: {str(e)}")
    return None


def extract_function_name(func_code: str) -> str:
    patterns = [
        r'^\s*(?:[\w<>:]+\s+)+(\w+)\s*$[^)]*$\s*{',
        r'^\s*(\w+)\s*$[^)]*$\s*{',
        r'^\s*~(\w+)\s*$[^)]*$\s*{',
        r'^\s*template\s*<.*?>\s*(?:[\w<>:]+\s+)+(\w+)\s*$[^)]*$\s*{'
    ]
    for pattern in patterns:
        match = re.search(pattern, func_code, re.MULTILINE)
        if match:
            return match.group(1)
    return ''


def process_single(obj: Dict[str, Any], output_dir: str, id_counter: int) -> bool:
    global SUCCESS, FAIL
    file_path = os.path.join(output_dir, f'{id_counter}.json')
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        global_logger.info(f"Skip existing file {file_path}")
        return True
    try:
        commit_url = get_repo_info(obj['commit_id'])
        if not commit_url:
            return False
        
        raw_info = handle_github_commit(commit_url,global_logger)
        if not raw_info or not raw_info.files:
            return False
        
        func_name = extract_function_name(obj['func'])
        matched_file = next((f for f in raw_info.files if func_name in f.get('patch', '')), None)
        if not matched_file:
            return False

        new_obj = {
            "id": id_counter,
            "language": os.path.splitext(matched_file['filename'])[-1].lstrip('.') or 'unknown',
            "cwe": obj.get('cwe', ''),
            "commit_url": commit_url,
            "commit_sha": raw_info.commit_sha,
            "commit_msg": raw_info.commit_msg,
            "pr_url": raw_info.pr_info[0] if raw_info.pr_info else '',
            "pr_info": raw_info.pr_info[1] if raw_info.pr_info else 'no more info',
            "file_name": matched_file['filename'],
            "func_name": func_name,
            "raw_func_from_json": obj['func'],
            "diff_func": matched_file.get('patch', '')
        }
        new_obj.update({k: v for k, v in obj.items() if k not in new_obj})

        with open(file_path, 'w') as f:
            json.dump(new_obj, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        global_logger.error(f"Process error: {str(e)}")
        return False

def process_big_json(input_path: str, output_dir: str):
    global SUCCESS, FAIL, NON_TARGET
    os.makedirs(output_dir, exist_ok=True)
    id_counter = 0
    api_counter = 0
    # id_list = random_choose(300, file_path=input_path)

    with open(input_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            id_counter += 1
            if not line.strip():
                print(1)
                continue
            # if id_counter in id_list:
            #     print(f"Processing line {line_num}")
            # else:
            #     continue
            try:
                obj = json.loads(line)
                if obj.get('target', 1) == 0:
                    global_logger.info(f"Skip line {line_num} due to target=0")
                    NON_TARGET += 1
                    continue
        
                success = process_single(obj, output_dir, id_counter)
                if success:
                    SUCCESS += 1
                else:
                    FAIL += 1

                api_counter += 1
            
                if api_counter % 10 == 0:
                    smart_limit(verbose=True)

                if line_num % 100 == 0:
                    global_logger.info(f"Processed {line_num} lines | Success: {SUCCESS} | Fail: {FAIL}")
                
                if SUCCESS == 1000:
                    break

            except json.JSONDecodeError:
                FAIL += 1
                global_logger.error(f"Invalid JSON at line {line_num}")
            except Exception as e:
                FAIL += 1
                global_logger.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    a = '../primevul/dataset/raw/primevul_test.jsonl'
    b = '../primevul/dataset/big_to_each_json/test'
    process_big_json(a,b)
    global_logger.info(f"Final stats - Success: {SUCCESS}, Fail: {FAIL}, Non-target: {NON_TARGET}")

    # SUCCESS = 0
    # FAIL = 0
    # NON_TARGET = 0
    # c = '../primevul/dataset/raw/primevul_train.jsonl'
    # d = '../primevul/dataset/big_to_each_json/train'
    # process_big_json(c,d)
    # global_logger.info(f"Final stats - Success: {SUCCESS}, Fail: {FAIL}, Non-target: {NON_TARGET}")

    # SUCCESS = 0
    # FAIL = 0
    # NON_TARGET = 0
    # e = '../primevul/dataset/raw/primevul_valid.jsonl'
    # f = '../primevul/dataset/big_to_each_json/valid'
    # process_big_json(e,f)
    # global_logger.info(f"Final stats - Success: {SUCCESS}, Fail: {FAIL}, Non-target: {NON_TARGET}")
    
        

