import logging
import os
import re
import subprocess
import time
import chardet
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, Dict
from urllib.parse import urlparse, quote
from dataclasses import dataclass
from bs4 import BeautifulSoup
import urllib3
import gitlab # pip install python-gitlab
from gitlab.v4.objects import Project
from tqdm import tqdm
import json

from logging_helper import global_logger
from git_clone import Cloner

session = requests.Session()
gl = gitlab.Gitlab(session=session,timeout=30)
GITLAB_COMMIT_THRESHOLD = 10


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
    pr_info: str 
    git_url: str 
    ##gitlab
    pipeline_status: Optional[str] = None 
    merge_request_id: Optional[int] = None  
    
    
# gitlab api
def fetch_gitlab_api(endpoint: str, logger: logging.Logger, token: Optional[str] = None) -> Optional[Dict]:
    headers = {'PRIVATE-TOKEN': token} if token else {}
    try:
        response = requests.get(endpoint, headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"API error: {str(e)}")
        return None

# decode binary data
def _try_decode_binary_data_and_write_to_file(data: bytes, save_path: Path):
    # save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with save_path.open(mode='w') as f:
        file_content = _try_decode_binary_data(data)
        f.write(file_content)


def _try_decode_binary_data(data: bytes) -> str:
    encodings_to_try = ['utf-8', 'ascii']

    for encoding in encodings_to_try:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass

    detect_result = chardet.detect(data)
    detected_encoding = detect_result['encoding']

    try:
        return data.decode(detected_encoding)
    except UnicodeDecodeError:
        raise AssertionError(f'decode error {detected_encoding} {data}')

#  find commits from merge request
def find_commits_from_mr(mr_url: str, logger: logging.Logger, token: Optional[str] = None) -> List[str]:
    parsed = urlparse(mr_url)
    path_segments = parsed.path.split('/-/merge_requests/')
    
    if len(path_segments) != 2:
        logger.error("GitLab MR URL format error")
        return []
    
    project_path, mr_id = path_segments
    api_endpoint = f"{parsed.scheme}://{parsed.netloc}/api/v4/projects/{quote(project_path.strip('/'), safe='')}/merge_requests/{mr_id}/commits"
    
    commits_data = fetch_gitlab_api(api_endpoint, token)
    return [commit['web_url'] for commit in commits_data] if commits_data else []


def _get_pipeline_status(commit_info: RawCommitInfo, logger: logging.Logger, token: Optional[str] = None) -> Optional[Dict]:
    parsed = urlparse(commit_info.commit_url)
    path_segments = parsed.path.split('/-/commit/')
    
    if len(path_segments) != 2:
        return None
    
    project_path, _ = path_segments
    api_endpoint = f"{parsed.scheme}://{parsed.netloc}/api/v4/projects/{quote(project_path.strip('/'), safe='')}/pipelines?sha={commit_info.commit_sha}"
    return fetch_gitlab_api(api_endpoint, token)


# get repos name
def _get_repo_name(url: str) -> Tuple[str, str]:
    re_result = re.match(r"https://gitlab.com/(?P<owner>.*)/(?P<repo>.*)/-/commit/(?P<commit_hash>.*)", url)
    if re_result is None: return None
    owner =re_result.group('owner')
    repo = re_result.group('repo')
    repo_name = f'{owner}/{repo}'
    commit_sha = re_result.group('commit_hash')
    return repo_name, commit_sha

# get patch files path
def _get_patch_files_path(url, logger: logging.Logger) -> List[str]:
    file_paths = []
    # get repos name
    repo_name, commit_sha = _get_repo_name(url)
    try:
        project: Project = gl.projects.get(repo_name)
        commit = project.commits.get(commit_sha)
        # print(commit)  ## sample get commit info  
        for diff in commit.diff(get_all=True):
            # print(diff)
            file_paths.append(diff['new_path'])
        return file_paths
    except Exception as e:
        logger.error(f"Failed to get patch file: {str(e)}")



# get commit info
def handle_gitlab_commit(url: str, logger: logging.Logger, token: Optional[str] = None) -> Optional[RawCommitInfo]:
    parsed = urlparse(url)

    path_segments = parsed.path.split('/-/commit/')
    
    if len(path_segments) != 2:
        logger.error("error url format")
        return None
    
    project_path, commit_sha = path_segments
    api_base = f"{parsed.scheme}://{parsed.netloc}/api/v4"
    
    commit_endpoint = f"{api_base}/projects/{quote(project_path.strip('/'), safe='')}/repository/commits/{commit_sha}"
    commit_data = fetch_gitlab_api(commit_endpoint, token)
    if not commit_data:
        return None
    

    mr_endpoint = f"{commit_endpoint}/merge_requests"
    mr_data = fetch_gitlab_api(mr_endpoint, token)
    
    pipeline_endpoint = f"{api_base}/projects/{quote(project_path.strip('/'), safe='')}/pipelines?sha={commit_sha}"
    pipeline_data = fetch_gitlab_api(pipeline_endpoint, token)
    
    repo_download_url = f"{parsed.scheme}://{parsed.netloc}{project_path}/-/archive/{commit_sha}/{commit_sha}.tar.gz"


    return RawCommitInfo(
        repo_name=_get_repo_name(url)[0].replace('/', '-'),
        commit_msg=commit_data.get('title', ''),
        commit_sha=commit_sha,
        parent_commit_sha=commit_data.get('parent_ids', [None])[0],
        pr_info=commit_data.get('message', None),
        # '2020-05-08T15:55:13.000-04:00'
        # git_time_format = "%Y-%m-%dT%H:%M:%S.%f%z"
        commit_date=int(datetime.fromisoformat(commit_data['committed_date']).timestamp()),
        # file_paths=[change['new_path'] for change in commit_data.get('changes', [])],
        file_paths=_get_patch_files_path(url, logger),
        tree_url=f"{parsed.scheme}://{parsed.netloc}{project_path}/-/tree/{commit_sha}",
        commit_url=commit_data['web_url'],
        git_url=f"{parsed.scheme}://{parsed.netloc}{project_path}.git",
        repo_download_url=repo_download_url,
        pipeline_status=pipeline_data[0]['status'] if pipeline_data else None,
        merge_request_id=mr_data[0]['iid'] if mr_data else None
    )


# if download_parent_commit is True, download the parent commit files
def download_gitlab_files(
    commit_info: RawCommitInfo,
    download_parent_commit: bool,
    save_dir: Path,
    logger: logging.Logger,
    retry: int = 3
) -> Tuple[List[str], List[str]]:
    
    repo_name = commit_info.repo_name
    downloaded = []
    failed = []
    tree_sha = commit_info.parent_commit_sha if download_parent_commit else commit_info.commit_sha
    repo = None
    print(save_dir)
    dir_path = os.path.join(save_dir, 'patch_after/') if not download_parent_commit else os.path.join(save_dir, 'patch_before/')
    for file_path in commit_info.file_paths:
        save_name = file_path.split('/')[-1]
        # if file exists and not empty, skip
        save_path = Path(os.path.join(dir_path, save_name))
        if save_path.exists() and save_path.stat().st_size > 0:
            downloaded.append(file_path)
            continue
        while retry > 0:
            try:
                if repo is None:
                    repo = gl.projects.get(repo_name)
                file_content_b = repo.files.raw(file_path, ref=tree_sha)
                _try_decode_binary_data_and_write_to_file(file_content_b, save_path)
                downloaded.append(file_path)
                # logger.info(f"Downloaded {file_path}")
                break
            except Exception as e:
                retry -= 1
                if retry == 0:
                    logger.error(f"Failed to download {file_path} - {str(e)}")
                    failed.append(file_path)
            except (urllib3.exceptions.MaxRetryError, requests.exceptions.SSLError,requests.exceptions.ConnectionError) as e:
                logger.info(f'{repo_name}:{tree_sha} max retries exceeded or SSL error, retry again')
                time.sleep(5)
                continue
            
    return downloaded, failed

def get_gitlab_all_files(
    commit_info: RawCommitInfo,
    dir_path: str = "gitlab_test",
    logger: logging.Logger = global_logger
) -> None:
    # commit_info = get_gitlab_commit_info(commit_url, logger)
    if not commit_info or not commit_info.file_paths:
        logger.error("Invalid commit info or missing files")
        return

    base_dir = Path(dir_path)
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir/"patch_after").mkdir(exist_ok=True)
    (base_dir/"patch_before").mkdir(exist_ok=True)

    current_downloaded, current_failed = download_gitlab_files(
        commit_info, False, base_dir, logger)
    parent_downloaded, parent_failed = download_gitlab_files(
        commit_info, True, base_dir, logger) if commit_info.parent_commit_sha else ([], [])

    
    rawcode_path = base_dir/"rawcode.jsonl"
    error_count = len(current_failed) + len(parent_failed)
    
    with tqdm(commit_info.file_paths, desc="Generating metadata") as pbar:
        for idx, file_path in enumerate(pbar, 1):
            try:
            
                save_name = Path(file_path).name
                
    
                current_file = base_dir/"patch_after"/save_name
                before_file = base_dir/"patch_before"/save_name
                
                if not current_file.exists():
                    continue

                result_data = {
                    "patches_id": idx,
                    "files_id": idx,
                    "file_name": file_path,
                    "language": Path(file_path).suffix[1:],
                    "raw_url": f"{commit_info.tree_url}/{file_path}",
                    "file_path": str(current_file),
                    "raw_code": current_file.read_text(encoding='utf-8'),
                    "raw_code_before": before_file.read_text(encoding='utf-8') if before_file.exists() else "",
                    # "patch": get_gitlab_patch(commit_info, file_path)
                }

                
                with rawcode_path.open('a', encoding='utf-8') as f:
                    json.dump(result_data, f)
                    f.write('\n')

            except Exception as e:
                logger.error(f"Metadata error for {file_path}: {str(e)}")
                error_count += 1

    success_count = len(current_downloaded) - len(current_failed)
    logger.info(
        f"Process completed: {success_count} files processed, {error_count} errors"
    )


## repo download
def get_gitlab_sha_repo_from_url(commit_url: str, save_dir: Path, logger: logging.Logger):
    if 'gitlab' not in commit_url:
        logger.error(f"Invalid gitlab url")
        return
    dir_path = os.path.join(save_dir, 'old_repos/')
    os.makedirs(dir_path,exist_ok=True)

    commit_info = handle_gitlab_commit(commit_url, logger)
    commit_sha, repos_url = commit_info.commit_sha, commit_info.repo_download_url

    repos_name = str(commit_sha) + ".tar.gz"
    repos_file = os.path.join(dir_path, repos_name)

    # print(repos_url)
    try:
        subprocess.run(["wget", "-O", repos_file, repos_url], check=True)
        subprocess.run(["tar", "-xzvf", repos_file, "-C", dir_path], check=True)
        os.remove(repos_file)
        logger.info(f"Successfully downloaded repo: {commit_url}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error downloading repo: {e}")

def get_gitlab_sha_repo_from_clone(commit_url: str, save_dir: Path, logger: logging.Logger):
    if 'gitlab' not in commit_url:
        logger.error(f"Invalid gitlab url")
        return
    old_repos_dir = save_dir / "old_repos"
    old_repos_dir.mkdir(parents=True, exist_ok=True)

    try:
        commit_info = handle_gitlab_commit(commit_url, logger)
        if not commit_info:
            logger.error("Failed to parse commit info")
            return None
    except Exception as e:
        logger.exception("Error parsing gitlab commit")
        return None

    try:
        cloner = Cloner(platform="gitlab")
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
   


def test_gitlab_integration():
    save_dir = ""
    test_urls = [
        "https://gitlab.com/openconnect/openconnect/-/commit/eef4c1f9d24478aa1d2dd9ac7ec32efb2137f474",
    ]
    raw = handle_gitlab_commit(test_urls[0],global_logger) # get commit info
    print(raw)
    get_gitlab_all_files(raw, save_dir, global_logger) # download patch files after
    # download_gitlab_files(raw, False, save_dir,  global_logger) # download patch files after
    # download_gitlab_files(raw, True, save_dir, global_logger) # download  patch files before
    # get_gitlab_sha_repo_from_clone(test_urls[0], save_dir, global_logger) # download repo
    


if __name__ == "__main__":
    # print("OK")
    test_gitlab_integration()