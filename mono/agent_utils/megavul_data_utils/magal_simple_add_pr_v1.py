# not use CVE-2021-1234_i.json, but use CVE-2021-1234.json
import sys
import json
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from git_utlis.github_helper import get_pr_info,smart_limit
from logging_helper import global_logger


work_dir = "MegaVul_dataset/mysort_1/c_cpp/megavul_simple/vul"
new_dir = "MegaVul_dataset/mysort_1_pr/c_cpp/megavul_simple_vul"
DESCRIPTION = "no more info"

def load_json_file(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def load_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def save_new_json(new_dir, filename, content, pr_url, description):
    content["pr_url"] = pr_url
    content["description"] = description
    new_file_path = os.path.join(new_dir, filename)
    with open(new_file_path, 'w') as f:
        json.dump(content, f, indent=4)
        print(f"Saved to {new_file_path}")

from git_utlis.github_helper import get_pr_info,smart_limit
def get_pr_info_to_each_json(work_dir, new_dir):
    if not os.path.exists(new_dir):
        os.makedirs(new_dir)
    add_info_all_dir = os.path.join(new_dir, "add_info_all")
    not_git_url_dir = os.path.join(new_dir, "not_git_url")
    no_pr_info_dir = os.path.join(new_dir, "no_pr_info")
    git_pr_info_dir = os.path.join(new_dir, "git_pr_info")
    if not os.path.exists(add_info_all_dir):
        os.makedirs(add_info_all_dir)
    if not os.path.exists(not_git_url_dir):
        os.makedirs(not_git_url_dir)
    if not os.path.exists(no_pr_info_dir):
        os.makedirs(no_pr_info_dir)
    if not os.path.exists(git_pr_info_dir):
        os.makedirs(git_pr_info_dir)
    
    i = 0
    success = 0
    fail = 0
    for filename in os.listdir(work_dir):
        if filename.startswith("CVE-") and os.path.isfile(os.path.join(work_dir, filename)):
            print(f"Processing {filename}")
            file_path = os.path.join(work_dir, filename)
            content = load_json_file(file_path)
            commit_url = content.get("git_url")
            # print(commit_url)
            if "github.com" not in commit_url:
                fail += 1
                save_new_json(not_git_url_dir, filename, content, None, DESCRIPTION)
                save_new_json(add_info_all_dir, filename, content, None, DESCRIPTION)
                print(f"Invalid git_url for {filename}")

            if i%5 == 0:
                smart_limit(verbose=True)
            pr_url, description = get_pr_info(commit_url)
            if pr_url is None:
                print(f"Failed to get PR info for {filename}")
                fail += 1
                save_new_json(no_pr_info_dir, filename, content, None, DESCRIPTION)
                save_new_json(add_info_all_dir, filename, content, None, DESCRIPTION)
                continue

            success += 1
            global_logger.info(f"[+] Processed {filename}")
            save_new_json(git_pr_info_dir, filename, content, pr_url, description)
            save_new_json(add_info_all_dir, filename, content, pr_url, description)
            i += 1
            if i % 100 == 0:
                print(f"Processed {i} entries")
    return success, fail

if __name__ == "__main__":
    success, fail =  get_pr_info_to_each_json(work_dir, new_dir)
    print(f"Done! Success: {success}, Fail: {fail}")
    global_logger.info(f"Done! Success: {success}, Fail: {fail}")

