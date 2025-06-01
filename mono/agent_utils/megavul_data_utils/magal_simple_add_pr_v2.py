# for all the json files in work_dir, get the pr_url and description from github (and old repos to reduce time) and save to new_dir
import sys
import json
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from git_utlis.github_helper import get_pr_info,smart_limit
from logging_helper import global_logger

old_dir = "MegaVul_dataset/mysort_pr/java/megavul_simple/add_info_all"

work_dir = "MegaVul_dataset/mysort_1/java/megavul_simple/vul"
new_dir = "MegaVul_dataset/mysort_1_pr/java/megavul_simple_vul"
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
        print(f"Processing {filename}")
        global_logger.info(f"[+] Processed {filename}")
        file_path = os.path.join(work_dir, filename)
        content = load_json_file(file_path)
        commit_url = content.get("git_url")
        if "github.com" not in commit_url:
            fail += 1
            save_new_json(not_git_url_dir, filename, content, None, DESCRIPTION)
            save_new_json(add_info_all_dir, filename, content, None, DESCRIPTION)
            print(f"Invalid git_url for {filename}")
            continue
        
        # get base name, eg: CVE-2021-1234, CVE-2021-1234_0.json, compare with old_dir/CVE-2021-1234.json
        # # if commit_url is the same, use old pr_url and description, so that we don't need to call github api
        if "_" not in filename:
            old_file = os.path.join(old_dir, filename)
            if os.path.isfile(old_file):
                old_content = load_json_file(old_file)
                pr_url = old_content.get("pr_url")
                description = old_content.get("description")
        else:
            basename = filename.split("_")[0]
            old_file = os.path.join(old_dir, basename+".json")
            if os.path.isfile(old_file):
                old_content = load_json_file(old_file)
                old_commit_url = old_content.get("git_url")
            else:
                old_commit_url = None
            if commit_url == old_commit_url:
                pr_url = old_content.get("pr_url")
                description = old_content.get("description")
            else:
                if i%5 == 0:
                    smart_limit(verbose=True)
                i += 1
                pr_url, description = get_pr_info(commit_url)
            
        if pr_url is None or description is DESCRIPTION:
            print(f"Failed to get PR info for {filename}")
            fail += 1
            save_new_json(no_pr_info_dir, filename, content, None, DESCRIPTION)
            save_new_json(add_info_all_dir, filename, content, None, DESCRIPTION)
            continue

        success += 1
        save_new_json(git_pr_info_dir, filename, content, pr_url, description)
        save_new_json(add_info_all_dir, filename, content, pr_url, description)
        if (success+fail) % 100 == 0:
            print(f"Processed {(success+fail)} entries")
    print(f"Processed {(success+fail)} entries")
    return success, fail

if __name__ == "__main__":
    success, fail =  get_pr_info_to_each_json(work_dir, new_dir)
    print(f"Done! Success: {success}, Fail: {fail}")
    global_logger.info(f"Done! Success: {success}, Fail: {fail}")
    # c_cpp
    # Processed 17885 entries
    # Done! Success: 2753, Fail: 15132

    # java
    # Processed 2425 entries
    # Done! Success: 964, Fail: 1461

