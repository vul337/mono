import logging
import base64
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Optional, List, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from pyparsing import Dict
import requests
from dataclasses import dataclass
from tqdm import tqdm
import json

from git_clone import Cloner
from logging_helper import global_logger

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
    pr_info:str = None  ####


def is_google_url(url: str) -> bool:
    return 'googlesource.com' in urlparse(url).netloc


# fetch html
def fetch_html(url: str, logger: logging.Logger, retry: int = 3) -> Optional[BeautifulSoup]:
    for attempt in range(1, retry+1):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return BeautifulSoup(response.text, "html.parser")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Attempt {attempt}: Failed to fetch {url} - {str(e)}")
    return None

def parse_google_date(date_str: str) -> int:
    from datetime import datetime
    try:
        dt = datetime.strptime(date_str, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        dt = datetime.strptime(date_str, "%a %b %d %H:%M:%S %Y %z")
    return int(dt.timestamp())


# get commit info
def handle_google_commit(url: str, logger: logging.Logger) -> Optional[RawCommitInfo]:
    parsed = urlparse(url)
    # https://android.googlesource.com/platform/external/webkit/+/109d59bf6fe4abfd001fc60ddd403f1046b117ef
    # repo_name = platform/external/webkit 
    repo_name = parsed.path.strip('/').split('/+')[0]
    soup = fetch_html(url, logger)

    commit_table = soup.find('table')
    if not commit_table or len(commit_table.find_all('tr')) != 5:
        logger.debug("Invalid commit table structure")
        return None

    # print(commit_table)
    rows = commit_table.find_all('tr')
    try:
        commit_sha = rows[0].td.text.strip()

        commit_date = parse_google_date(rows[1].find_all('td')[-1].text.strip())
        tree_url = f'{rows[3].a["href"]}'
        parent_sha = rows[4].a.text.strip() if rows[4].a else None
        commit_msg = soup.find('pre', class_='MetadataMessage').text.strip()
        try:
            repo_download_url = rows[0].find_all('a')[1]['href']
        except (IndexError, KeyError):
            repo_download_url = None
    except AttributeError as e:
        logger.error(f"Parse error: {str(e)}")
        return None

    tree_url = f"{parsed.scheme}://{parsed.netloc}{'/'.join(tree_url.split('/')[:-1])}/"
    repo_download_url = f"{parsed.scheme}://{parsed.netloc}{repo_download_url}" if repo_download_url else None
    # print(repo_download_url)

    diff_tree = soup.find('ul', class_='DiffTree')
    file_paths = [
        li.a.text.strip()
        for li in diff_tree.find_all('li')
        if not li.find('span', class_=lambda x: x and '--add' in x)
    ] if diff_tree else []
    # tree_url https://android.googlesource.com/platform/external/webkit/+/7e4405a7a12750ee27325f065b9825c25b40598c/
    # git_url https://android.googlesource.com/platform/external/webkit
    git_url = f"{parsed.scheme}://{parsed.netloc}/{repo_name}"
    return RawCommitInfo(
        repo_name=repo_name.replace('/', '-'),
        commit_msg=commit_msg,
        commit_sha=commit_sha,
        parent_commit_sha=parent_sha,
        commit_date=commit_date,
        file_paths=file_paths,
        tree_url=tree_url,
        commit_url=url,
        repo_download_url=repo_download_url,
        git_url=git_url
    )


# download patch files
def download_google_files(
    commit_info: RawCommitInfo,
    download_parent_commit: bool,
    save_dir: Path,
    logger: logging.Logger,
) -> Tuple[List[str], List[str]]:
    
    downloaded = []
    failed = []

    tree_hash = commit_info.parent_commit_sha if download_parent_commit else commit_info.commit_sha
    tree_url = re.match(r"https://.*?/\+/", commit_info.tree_url).group() + tree_hash + "/"
    dir_path = os.path.join(save_dir, 'patch_before/') if download_parent_commit else os.path.join(save_dir, 'patch_after/')

    for file_path in commit_info.file_paths:
        # print(file_path)
        safe_name = file_path.replace('..', '__').replace('/', '_')[:200]
        # safe_name = Path(file_path).name
        save_path = Path(os.path.join(dir_path, safe_name))
        # print(save_path)
        if save_path.exists() and save_path.stat().st_size > 0:
            downloaded.append(file_path)
            continue
        
        download_url = f"{tree_url}{file_path}?format=TEXT"
        # print(download_url)
        if (content := fetch_html(download_url, logger)) and content:
            try:
                decoded = base64.b64decode(str(content))
                save_path.parent.mkdir(parents=True, exist_ok=True)
                save_path.write_bytes(decoded)
                downloaded.append(file_path)
                # logger.info(f"Downloaded {file_path}")
            except (OSError, ValueError) as e:
                failed.append(file_path)
                logger.error(f"Save failed: {str(e)}")

    return downloaded, failed

def get_google_all_files(
    commit_info: RawCommitInfo,
    dir_path: str = "./google_test",
    logger: logging.Logger = global_logger
) -> None:
    if not commit_info or not commit_info.file_paths:
        logger.error("Invalid commit info or missing files")
        return

    base_dir = Path(dir_path)
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir/"patch_after").mkdir(exist_ok=True)
    (base_dir/"patch_before").mkdir(exist_ok=True)

    current_downloaded, current_failed = download_google_files(
        commit_info, False, base_dir, logger)
    parent_downloaded, parent_failed = download_google_files(
        commit_info, True, base_dir, logger) if commit_info.parent_commit_sha else ([], [])

    rawcode_path = base_dir/"rawcode.jsonl"
    error_count = len(current_failed) + len(parent_failed)
    
    with tqdm(commit_info.file_paths, desc="Generating metadata") as pbar:
        for idx, file_path in enumerate(pbar, 1):
            try:
            
                save_name = file_path.replace('..', '__').replace('/', '_')[:200]
                
                current_file = base_dir/"patch_after"/save_name
                before_file = base_dir/"patch_before"/save_name
                
                if not current_file.exists():
                    print(current_file)
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
                    # "patch": get_google_patch(commit_info, file_path)
                }
                print(rawcode_path)
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


def get_google_sha_repo_from_url(commit_url: str, save_dir: Path, logger: logging.Logger):
    if not is_google_url(commit_url):
        return
    dir_path = os.path.join(save_dir, 'old_repos/')
    os.makedirs(dir_path,exist_ok=True)

    commit_info = handle_google_commit(commit_url, logger)
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


def get_google_sha_repo_from_clone(commit_url: str, save_dir: Path, logger: logging.Logger):
    if not is_google_url(commit_url):
        logger.error(f"Not a google URL: {commit_url}")
        return None
    old_repos_dir = save_dir / "old_repos"
    old_repos_dir.mkdir(parents=True, exist_ok=True)

    try:
        commit_info = handle_google_commit(commit_url, logger)
        if not commit_info:
            logger.error("Failed to parse commit info")
            return None
    except Exception as e:
        logger.exception("Error parsing google commit")
        return None

    try:
        cloner = Cloner(platform="google")
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
    logger = global_logger
    test_url = "https://android.googlesource.com/platform/external/webkit/+/109d59bf6fe4abfd001fc60ddd403f1046b117ef"

    if is_google_url(test_url):
        commit_info = handle_google_commit(test_url, logger)
        # print(commit_info)
        if commit_info:
            # download_google_files(
            #     commit_info,
            #     True,
            #     Path("./google_test"),
            #     logger=logger
            # )
            # download_google_files(
            #     commit_info,
            #     False,
            #     Path("./google_test"),
            #     logger=logger
            # )

            # get_google_sha_repo_from_clone(test_url, Path("./google_test"), logger)
            get_google_all_files(commit_info, "./google_test", logger)



if __name__ == "__main__":
    test()