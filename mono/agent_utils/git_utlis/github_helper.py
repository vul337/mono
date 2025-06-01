from dataclasses import dataclass
import json
import logging
from pathlib import Path
import sys
from typing import Dict, Optional
from urllib.request import Request, urlopen
import requests
import git
import re
import os
from dateutil import parser
import pandas as pd
import subprocess
from bs4 import BeautifulSoup
from dateutil import parser
import time
from datetime import datetime 
from git import List, Repo, GitCommandError
from urllib.parse import urlparse

from tqdm import tqdm
from git_clone import Cloner
from logging_helper import global_logger
from config_helper import config_file

GITHUB_TOKEN = config_file['github_tokens'][0]
GITHUB_USERNAME = config_file['github_usernames'][0]
REPO_DIR = Path(config_file["repo_cache_path"]).resolve()

@dataclass
class RawCommitInfo:
    repo_name: str
    commit_msg: str
    commit_sha: str
    parent_commit_sha: Optional[str]
    commit_date: int
    file_paths: List[str]
    tree_url: str
    commit_url: str
    repo_download_url: str
    git_url:str
    files:List[Dict]  ####
    pr_info:str = None  ####



headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }

def test_token():
    print(GITHUB_USERNAME)
    print(GITHUB_TOKEN)

# get soup from url
def get_soup(url):
    response = requests.get(url=url)  
    soup = BeautifulSoup(response.content, 'html.parser')
    return soup

# check yaml status
def check_yaml_status(repo):
    headers = {'Authorization': 'token %s' % GITHUB_TOKEN}
    url = "https://api.github.com/search/code?q=yaml.load+in%3afile+language%3apy+repo%3a" + repo
    response = requests.get(url, headers=headers)
    response.close()
    return response.json()

# get rate limit,retry = 2
def github_rate_limit(retry = 2):
    for attempt in range(retry):
        try:
            url = "https://api.github.com/rate_limit"
            response = requests.get(url, headers=headers)
            response.close()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"rate_limit request error: {e}")
            if attempt < retry - 1:
                print("Retrying...")
                time.sleep(2 ** attempt) 
            else:
                return None

# Handles GitHub rate limit by waiting until reset if necessary
def smart_limit(verbose=False):
    rate = github_rate_limit()
    if rate is None:
        return 
    remaining = rate['rate']['remaining']
    reset_epoch = rate['rate']['reset']
    reset = datetime.fromtimestamp(reset_epoch)

    if verbose:
        now = datetime.now()
        print(f"Rate Limit Remaining: {remaining} | Reset: {reset} | Current Time: {now}")

    if remaining <= 50:
        print(f"⚠️  Rate limit nearing. Remaining requests: {remaining}")
        time_until_reset = reset - datetime.now()
        total_seconds = time_until_reset.total_seconds()
        print(f"⏳  Time until reset: {total_seconds} seconds")

        buffer = 30
        sleep_seconds = total_seconds + buffer

        print(f"💤  Sleeping for approximately {sleep_seconds} seconds...")
        while sleep_seconds > 0:
            print(f"⏰  Remaining sleep time: {sleep_seconds} seconds")
            time.sleep(10) 
            sleep_seconds -= 10
            if sleep_seconds < 0:
                break 

        print("✲️  Rate limit reset. Resuming process...")
    else:
        print("✅  Sufficient rate limit remaining. Continuing execution...")
    

def get_repo_info(commit_url):
    """
    Extracts the repository owner and name from a GitHub commit URL.
    :param commit_url: URL pointing to a specific commit on GitHub
    :return: Tuple containing (repo_owner, repo_name, commit_sha)
    """
    parsed_url = urlparse(commit_url)
    path_parts = parsed_url.path.strip('/').split('/')
    
    # Ensure the path parts are valid
    if len(path_parts) < 4:
        return None, None, None

    repo_owner = path_parts[0]
    repo_name = path_parts[1].replace('.git', '')  # Remove .git if present
    commit_sha = path_parts[-1]
    
    return repo_owner, repo_name, commit_sha

# get pr info from commit url retry = 2
def get_pr_info(commit_url, retry = 2):
    repo_owner, repo_name, commit_sha = get_repo_info(commit_url)
    if not repo_owner or not repo_name:
        print("Invalid commit URL format.")
        return None, None

    api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{commit_sha}/pulls"

    max_retries = retry 
    for attempt in range(max_retries):
        try:
            response = requests.get(api_url, headers=headers, timeout=(3, 10))
            response.raise_for_status()

            pr_data = response.json()
            if pr_data:
                pr_number = pr_data[0]['number']
                pr_url = pr_data[0]['html_url']

                pr_details_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}"
                pr_details_response = requests.get(pr_details_url, headers=headers, timeout=(3, 10))
                pr_details_response.raise_for_status()
                pr_details = pr_details_response.json()

                pr_body = pr_details.get('body', 'No description found.')
                return pr_url, pr_body
            else:
                print("No Pull Request found for this commit.")
                return None, None
        except requests.exceptions.Timeout as e:
            print(f"Timeout error: {e}")
            if attempt < max_retries - 1:
                print("Retrying...")
                time.sleep(2 ** attempt) 
            else:
                print("Max retries reached. Skipping...")
                return None, None
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return None, None

    return None, None

def handle_github_commit(
    commit_url: str,
    logger: logging.Logger,
    timeout: int = 10
) -> Optional[RawCommitInfo]:
    # Validate and convert URL
    parsed_url = urlparse(commit_url)
    if "github.com" not in parsed_url.netloc:
        logger.error(f"Non-GitHub URL: {commit_url}")
        return None

    path_parts = parsed_url.path.strip("/").split("/")
    if len(path_parts) < 4 or path_parts[2] != "commit":
        logger.error(f"Invalid commit URL format: {commit_url}")
        return None

    owner, repo, _, sha = path_parts[:4]
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"

    try:
        response = requests.get(api_url, headers=headers, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {str(e)}")
        return None
    # print(response.json())
    try:
        data = response.json()
    except json.JSONDecodeError:
        logger.error("Invalid JSON response")
        return None


    required_fields = {'sha', 'commit', 'html_url', 'parents', 'files'}
    if not required_fields.issubset(data.keys()):
        logger.error(f"Missing required fields in response: {data.keys()}")
        return None

    try:
        commit_sha = data['sha']
        commit_msg = data['commit']['message']
        commit_date = datetime.strptime(
            data['commit']['committer']['date'], 
            "%Y-%m-%dT%H:%M:%SZ"
        ).timestamp()
        
        parents = [p['sha'] for p in data['parents']]
        parent_sha = parents[0] if parents else None
        file_paths = [f['filename'] for f in data['files']]
        files = data['files']
        
        repo_download_url = f"https://github.com/{owner}/{repo}/archive/{commit_sha}.zip"
        git_url = f"https://github.com/{owner}/{repo}.git"
        tree_url = data['html_url'].replace('/commit/', '/tree/')

        return RawCommitInfo(
            repo_name=f"{owner}-{repo}",
            commit_msg=commit_msg,
            commit_sha=commit_sha,
            parent_commit_sha=parent_sha,
            commit_date=int(commit_date),
            file_paths=file_paths,
            tree_url=tree_url,
            commit_url=commit_url,
            repo_download_url=repo_download_url,
            git_url=git_url,
            files=files,
            pr_info=get_pr_info(commit_url)
        )

    except KeyError as e:
        logger.error(f"Missing JSON field: {str(e)}")
    except ValueError as e:
        logger.error(f"Date format error: {str(e)}")
    
    return None

# clone latest github repo to local
def github_clone(commit_url, dir_path = REPO_DIR):
    """
    Clones a given repository from Github to a set path on local machine
    :param commit_url: URL pointing to a specific commit on GitHub
    """
    repo_owner, repo_name, _ = get_repo_info(commit_url)
    if dir_path is None:
        dir_path = os.getcwd()

    clone_path = f"{dir_path}/github/{repo_name}"
    # print(clone_path)
    if os.path.exists(clone_path):
        print(f"Path already exists: {clone_path}")
    else:
        git.Git(clone_path).clone(f"https://{GITHUB_USERNAME}:{GITHUB_TOKEN}@github.com/{repo_owner}/"
                                  f"{repo_name.replace('.git','')}.git")

# get old repo(ver = sha) based wget 
def get_sha_repo_from_url(commit_url, dir_path = "github_test/"):
    _, _, commit_sha = get_repo_info(commit_url)
    
    dir_path = os.path.join(dir_path, "old_repos/")  
    os.makedirs(dir_path, exist_ok=True)     
    repos_name = str(commit_sha) + ".zip"
    repos_file = os.path.join(dir_path, repos_name)

    raw_url = commit_url
    repos_url = raw_url.replace("commit/" + str(commit_sha), "archive/" + str(commit_sha)) + ".zip"

    try:
        subprocess.run(["wget", "-O", repos_file, repos_url], check=True)
        subprocess.run(["unzip", repos_file, "-d", dir_path], check=True)
        os.remove(repos_file)
        # print("Download old repos successful!")
    except subprocess.CalledProcessError as e:
        print(f"Error downloading repo: {e}")
# commit_url = "https://github.com/cydrobolt/polr/commit/b1981709908caf6069b4a29dad3b6739c322c675"
# get_sha_repo_from_url(commit_url)


def _download_file(raw_url: str, output_path: Path, logger) -> bool:
    try:
        response = requests.get(raw_url, timeout=10)
        response.raise_for_status()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with output_path.open('wb') as f:
            f.write(response.content)
        return True
    except Exception as e:
        logger.error(f"Download failed for {raw_url}: {str(e)}")
        return False

def _process_single_file(file_info: dict, commit_info: object, dir_path: Path, 
                        patches_id: int, files_id: int, logger) -> tuple:
    if not all(key in file_info for key in ('raw_url', 'filename', 'patch')):
        logger.warning(f"Skipping invalid file info at index {patches_id}")
        return (files_id, 1)  # (current_files_id, error_count)

    raw_url = file_info['raw_url']
    file_name = Path(raw_url).name.replace('%2F', '-')
    base_dir = dir_path / "patch_after"
    before_dir = dir_path / "patch_before"
    
    current_file = base_dir / file_name
    if not current_file.exists() or current_file.stat().st_size == 0:
        if not _download_file(raw_url, current_file, logger):
            return (files_id, 1)

    previous_file = before_dir / file_name
    if commit_info.parent_commit_sha and \
       (not previous_file.exists() or previous_file.stat().st_size == 0):
        before_url = raw_url.replace(commit_info.commit_sha, commit_info.parent_commit_sha)
        if not _download_file(before_url, previous_file, logger):
            return (files_id, 1)

    result_data = {
        "patches_id": patches_id,
        "files_id": files_id,
        "file_name": file_name,
        "language": Path(file_name).suffix[1:],
        "raw_url": raw_url,
        "file_path": str(current_file),
        # UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe4 in position 4482: invalid continuation byte
        "raw_code": current_file.read_text(encoding='utf-8', errors='ignore'),
        "raw_code_before": previous_file.read_text(encoding='utf-8', errors='ignore') if previous_file.exists() else "",
        "patch": file_info['patch']
    }

    with (dir_path / "rawcode.jsonl").open('a', encoding='utf-8') as f:
        json.dump(result_data, f)
        f.write('\n')
    
    return (files_id + 1, 0)

def get_github_all_files(commit_info: RawCommitInfo, dir_path: str = "github_test", logger=global_logger) -> None:
    # commit_info = handle_github_commit(commit_url, logger)
    if not commit_info or not hasattr(commit_info, 'files'):
        logger.error("Invalid commit info or missing files")
        return
    # print(commit_info.files)
    base_dir = Path(dir_path)
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "patch_after").mkdir(exist_ok=True)
    (base_dir / "patch_before").mkdir(exist_ok=True)

    files_id, error_count = 0, 0
    for patches_id, file_info in enumerate(tqdm(commit_info.files, desc="Processing files"), 1):
        new_files_id, new_errors = _process_single_file(
            file_info, commit_info, base_dir, patches_id, files_id, logger
        )
        files_id = new_files_id
        error_count += new_errors

    logger.info(f"Process completed: {files_id} files processed, {error_count} errors")


def get_github_sha_repo_from_clone(commit_url: str, save_dir: Path, logger: logging.Logger) -> Optional[Path]:
    if "github" not in commit_url:
        logger.error(f"Invalid github URL: {commit_url}")
        return None
    old_repos_dir = save_dir / "old_repos"
    old_repos_dir.mkdir(parents=True, exist_ok=True)

    try:
        commit_info = handle_github_commit(commit_url, logger)
        if not commit_info:
            logger.error("Failed to parse commit info")
            return None
    except Exception as e:
        logger.exception("Error parsing github commit")
        return None

    try:
        cloner = Cloner(platform="github")
        work_dir = cloner.clone(
            commit_info=commit_info,
            save_dir=old_repos_dir / f"{commit_info.repo_name}_{commit_info.commit_sha[:7]}"
        )
        return work_dir

    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e.stderr.decode().strip()}")
        return None
    except RuntimeError as e:
        logger.error(f"Checkout verification failed: {str(e)}")
        return None
    except Exception as e:
        logger.exception("Unexpected error during cloning")
        return None 






def test():
    commit_url = "https://github.com/Ettercap/ettercap/commit/cb7b2028dc03c628aa0a1a5130ca41421ddebcb2"
    # commit_url = "https://github.com/spring-projects/spring-data-jpa/commit/b8e7fecccc7dc8edcabb4704656a7abe6352c08f"
    # get_github_all_files(commit_url)
    print(handle_github_commit(commit_url, global_logger))
    # print(get_github_sha_repo_from_clone(commit_url, Path("./github_test"), global_logger))
    get_github_all_files(commit_url, Path("./github_test"), global_logger)


if __name__ == '__main__':
    test()
    # smart_limit(verbose=False)



# get commit info from commit url 
# def get_commit_info(commit_url, retry = 2):
#     raw_url = commit_url
#     if "commit" in commit_url and "github" in commit_url:
#         commit_url = commit_url.replace('/commit/', '/commits/').replace('https://github.com/', 'https://api.github.com/repos/')
#         # print(commit_url)
#     else:
#         print("Invalid commit URL format.")
#         return None
    
#     data = {}
#     fetchs = []
#     for attempt in range(retry):
#         try: 
#             output = bytes.decode(subprocess.check_output(["curl", "--request", "GET" ,"-H", f"Authorization: Bearer {GITHUB_TOKEN}", "-H", "X-GitHub-Api-Version: 2022-11-28", "-u", "KEY:", commit_url]))
#             data = json.loads(output)
#         except Exception as e:
#             print(e)
#         if 'url' in data and 'html_url' in data and 'commit' in data and 'files' in data:    
#                 fetchs.append({
#                     'url': data['url'],
#                     'html_url': data['html_url'],
#                     'message': data['commit']['message'], 
#                     'files': data['files'], 
#                     # list: "sha": "filename": "status": "additions": "deletions": "changes": "blob_url":"raw_url":"contents_url":"patch":
#                     'commit_id': data['sha'],
#                     'commit_date': data['commit']['committer']['date']
#                 })
#                 # print(fetchs)
#         else:
#             print("Error! Data is NULL, see raw commit url ", raw_url)
#             print(data)
#             time.sleep(1)
#     return fetchs
#     # with open(patch_name, "w", encoding = "utf-8") as rf:
#     #     rf.write(json.dumps(fetchs, indent=4, separators=(',', ': ')))

# # print(get_commit_info(commit_url))




# def raw_code_before(raw_url, file_path):
#     try:
#         if os.path.exists(file_path):
#             return 
#         commit_id = raw_url.partition('/raw/')[2].split('/')[0]
#         # case : https://github.com/cydrobolt/polr/commits/b1981709908caf6069b4a29dad3b6739c322c675/app%2FHttp%2FControllers%2FSetupController.php
        
#         history_url = raw_url.replace('/raw/'+commit_id, '/commits/'+commit_id)
#         # print(history_url)

#         soup = get_soup(history_url)
#         commit_id_before = None
        
#         # find 1st commit id before
#         commit_links = soup.find_all('a', href=lambda href: href and '/commit/' in href)

#         commit_ids = []
#         for link in commit_links:
#             href = link.get('href')
#             if href:
#                 commit_part = href.split('/commit/')[1]
#                 commit_ids.append(commit_part.split('/')[0])

#         for cid in commit_ids:
#             if cid != commit_id:
#                 commit_id_before = cid
#                 break

#         raw_url_before = raw_url.replace('/raw/'+str(commit_id), '/raw/'+str(commit_id_before))
#         print(raw_url_before)

#         wget_command = "wget -O " + file_path + " " + raw_url_before
#         subprocess.run(wget_command, shell=True)
#     except Exception as e:
#         print(e)
