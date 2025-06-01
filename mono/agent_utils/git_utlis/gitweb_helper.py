import logging
import os
import subprocess
import time
import unicodedata
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, Dict
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
from dataclasses import dataclass
from tqdm import tqdm
import json
from git_clone import Cloner
from github_helper import GITHUB_TOKEN, handle_github_commit, get_github_all_files
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
    git_url: str
    pr_info: str = None  
    # repo_download_url: str
    ####


GITWEB_PLATFORMS = {
    'sourceware.org', 'git.videolan.org', 'git.openssl.org' # 'git.moodle.org', 'git.savannah.gnu.org'
}

def is_gitweb_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.netloc in GITWEB_PLATFORMS or
        'git.savannah.gnu.org/gitweb' in url
    )

# fetch html
def fetch_html(url: str, logger: logging.Logger, retry: int = 3) -> Optional[BeautifulSoup]:
    for attempt in range(1, retry+1):
        if attempt >2:
            header = ''
        else:
            header = {
                'Authorization': f'token {GITHUB_TOKEN}',
                'Accept': 'application/vnd.github.v3+json'
            }
        try:
            timeout_config = (3.05, 15) 
            response = requests.get(
                url,
                timeout=timeout_config,
                allow_redirects=True,
                headers=header
            )
            if url != response.url:
                logger.warning(f"Original URL redirected: {url} -> {response.url}")
                if not is_gitweb_url(response.url):
                    logger.warning(f"[!] Redirected to non-GitWeb platform: {response.url}")
                    return response.url
                    
            return BeautifulSoup(response.text, "html.parser")
            
        except requests.RequestException as e:
            logger.warning(f"Attempt {attempt} failed for {url}: {str(e)}")
            if isinstance(e, requests.Timeout):
                logger.debug("Consider reducing timeout duration")
            return None
    return None


def safe_extract_text(element) -> str:
    return element.text.strip() if element else ''

def extract_repo_name(soup: BeautifulSoup) -> str:
    header_links = soup.find('div', class_='page_header').find_all('a')[2:]
    name_parts = [a.text for a in header_links if a]
    return '/'.join(name_parts).split('.')[0] # a-b-c

def clean_commit_message(soup: BeautifulSoup) -> str:
    msg_div = soup.find('div', class_='page_body')
    return unicodedata.normalize('NFKD', msg_div.text).strip()


# get commit info
def handle_gitweb_commit(url: str, logger: logging.Logger) -> Optional[RawCommitInfo]:
   
    try:
        soup = fetch_html(url,logger)
        if soup is None:
            return None
        elif isinstance(soup, str):
            return handle_github_commit(soup, logger)
        else:
            pass
        # print(soup)

        base_url = urlparse(url)
        base_url = f"{base_url.scheme}://{base_url.netloc}"
        # url = "http://git.videolan.org/?p=ffmpeg.git;a=commit;h=668494acd8b20f974c7722895d4a6a14c1005f1e"
        # git_url = "https://git.videolan.org/git/ffmpeg.git"
        # url = "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=d527c860f5a3f0ed687bd03f0cb464612dc23408"
        # git_url = "https://sourceware.org/git/glibc.git"
        
        # url = "http://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=ebc71865f0506a293242bd4aec97cdc7a8ef24b0"
        # this is a redirected url
        # git_url = "https://git.openssl.org/openssl.git"
        git_url = f"{base_url}/git/{extract_repo_name(soup)}.git"
        object_table = soup.find('table', class_='object_header')
        if not object_table:
            logger.error(f"GitWeb header table not found: {url}")
            return None

        rows = object_table.find_all('tr')
        # url = " https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=d527c860f5a3f0ed687bd03f0cb464612dc23408"s
        if len(rows) < 7:
            logger.error(f"Invalid table structure: {url}")
            return None

        commit_sha = safe_extract_text(rows[4].find_all('td')[1])
        parent_sha = safe_extract_text(rows[6].find_all('td')[1])
        date_str = safe_extract_text(rows[1].find('span', class_='datetime'))
        # Mon, 9 Feb 2015 19:38:41 +0800
        commit_date = int(datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z").timestamp())

        # remove tree_hash and commit_hash
        tree_url_prefix, tree_url_postfix = rows[5].find('td', class_='link').a['href'].split('?')
        tree_url_postfix = tree_url_postfix.split(';')
        tree_url_postfix = list(filter(lambda s: s.startswith('p='), tree_url_postfix))
        tree_url = f'{base_url}{tree_url_prefix}?{";".join(tree_url_postfix)}'
        
        # print(tree_url)
        diff_table = soup.find('table', class_='diff_tree')
        file_paths = [
            safe_extract_text(row.find('td').a)
            for row in diff_table.find_all('tr') if row.find('td')
        ] if diff_table else []

        repo_name = extract_repo_name(soup)

        return RawCommitInfo(
            repo_name=repo_name.replace('/', '-'),
            commit_msg=clean_commit_message(soup),
            commit_sha=commit_sha,
            parent_commit_sha=parent_sha,
            commit_date=commit_date,
            file_paths=file_paths,
            tree_url=tree_url,
            commit_url=url,
            git_url=git_url
        )

    except Exception as e:
        logger.exception(f"Failed to parse GitWeb commit: {str(e)}")
        return None

def save_content(content: str, path: Path, logger: logging.Logger) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return True
    except OSError as e:
        logger.error(f"Save failed: {path} - {str(e)}")
        return False

# if download_parent_commit is True, download the parent commit files
def download_gitweb_files(
    commit_info: RawCommitInfo,
    download_parent_commit: bool,
    save_dir: Path,
    logger: logging.Logger,
    retry: int = 3
) -> Tuple[List[str], List[str]]:
    
    faild = []
    downloaded = []
    tree_hash = commit_info.parent_commit_sha if download_parent_commit else commit_info.commit_sha
    dir_path = os.path.join(save_dir, 'patch_after/') if not download_parent_commit else os.path.join(save_dir, 'patch_before/')
    base_url = f"{commit_info.tree_url};a=blob_plain;hb={tree_hash};f="
    # print(base_url)
    for file_path in commit_info.file_paths:
        safe_name = file_path.replace('..', '__').replace('/', '_')[:200]
        # save_name = Path(file_path).name
        save_path = os.path.join(dir_path, safe_name)
        save_path = Path(save_path)

        if save_path.exists() and save_path.stat().st_size > 0:
            downloaded.append(file_path)
            continue

        file_url = base_url + file_path
        content = None
        for attempt in range(1, retry+1):
            try:
                response = requests.get(file_url, timeout=15)
                response.raise_for_status()
                content = response.text
                break
            except requests.RequestException as e:
                logger.warning(f"Attempt {attempt} failed: {file_url} - {str(e)}")

        if content and save_content(content, save_path, logger):
            downloaded.append(file_path)
            # logger.info(f"Downloaded: {file_url}")
        else:
            logger.error(f"Failed to download: {file_url}")

    return downloaded,faild


def get_gitweb_all_files(
    commit_info: RawCommitInfo,
    dir_path: str = "gitweb_test",
    logger: logging.Logger = global_logger
) -> None:

    if "github" in commit_info.commit_url: # Redirected to github
        get_github_all_files(commit_info, dir_path, logger)
        return

    if not commit_info or not commit_info.file_paths:
        logger.error("Invalid commit info or missing files")
        return

    base_dir = Path(dir_path)
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir/"patch_after").mkdir(exist_ok=True)
    (base_dir/"patch_before").mkdir(exist_ok=True)

    current_downloaded, current_failed = download_gitweb_files(
        commit_info, False, base_dir, logger)
    parent_downloaded, parent_failed = download_gitweb_files(
        commit_info, True, base_dir, logger) if commit_info.parent_commit_sha else ([], [])

    
    rawcode_path = base_dir/"rawcode.jsonl"
    error_count = len(current_failed) + len(parent_failed)
    
    with tqdm(commit_info.file_paths, desc="Generating metadata") as pbar:
        for idx, file_path in enumerate(pbar, 1):
            try:
            
                # save_name = Path(file_path).name
                save_name = file_path.replace('..', '__').replace('/', '_')[:200]
    
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
                    # "patch": get_gitweb_patch(commit_info, file_path)
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



def get_gitweb_sha_repo_from_clone(commit_url: str, save_dir: Path, logger: logging.Logger) -> Optional[str]:
    if not is_gitweb_url(commit_url) and "github" not in commit_url:
        logger.error(f"Not a GitWeb URL or Github URL: {commit_url}")
        return None
    old_repos_dir = save_dir / "old_repos"
    old_repos_dir.mkdir(parents=True, exist_ok=True)

    try:
        if "github" in commit_url:
            commit_info = handle_github_commit(commit_url, logger)
        else:
            commit_info = handle_gitweb_commit(commit_url, logger)
        if not commit_info:
            logger.error("Failed to parse commit info")
            return None
    except Exception as e:
        logger.exception("Error parsing gitweb commit")
        return None

    try:
        cloner = Cloner(platform="gitweb")
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
    

if __name__ == "__main__":
    # Redirected to github
    # url = "http://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=ebc71865f0506a293242bd4aec97cdc7a8ef24b0"
    #        https://github.com/openssl/openssl/commit/ebc71865f0506a293242bd4aec97cdc7a8ef24b0

    logger = global_logger
    
    # url = "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=d527c860f5a3f0ed687bd03f0cb464612dc23408"
    url = "http://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=ebc71865f0506a293242bd4aec97cdc7a8ef24b0"
    save_dir = Path("")
    os.makedirs(save_dir,exist_ok=True)
    commit_info = handle_gitweb_commit(url,global_logger)
    print(commit_info)
    
    get_gitweb_all_files(commit_info, save_dir, logger)
    get_gitweb_sha_repo_from_clone(commit_info.commit_url, save_dir, logger)
    # if commit_info:
    #     download_gitweb_files(commit_info, False, save_dir, global_logger)
    #     download_gitweb_files(commit_info, True, save_dir, global_logger)
    #     print("Downloaded")
    # else:
    #     print("Failed")
    # get_gitweb_sha_repo_from_clone(url, save_dir, global_logger)