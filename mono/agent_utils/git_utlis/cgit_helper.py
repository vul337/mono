import logging
import os
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, Dict
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dataclasses import dataclass
from tqdm import tqdm
import json

import sys
from git_clone import Cloner
from logging_helper import global_logger
from gitweb_helper import handle_gitweb_commit, get_gitweb_all_files


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
    
# cgit url
def is_cgit_url(url: str) -> bool:
    netloc = urlparse(url).netloc
    return netloc in {
        'git.kernel.org',
        'cgit.freedesktop.org',
        'git.savannah.gnu.org'
    } and 'gitweb' not in url

# fetch html
def _fetch_html(url: str, logger: logging.Logger, retry: int = 3) -> Optional[BeautifulSoup]:
    for attempt in range(1, retry+1):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return BeautifulSoup(response.text, "html.parser")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Attempt {attempt}: Failed to fetch {url} - {str(e)}")
    return None

# parse commit table
def _parse_commit_table(soup: BeautifulSoup, logger: logging.Logger) -> Optional[Dict]:
    table = soup.find('table', class_='commit-info')
    if not table:
        logger.error("Commit info table not found")
        return None
    
    rows = table.find_all('tr')
    try:
        return {
            'date': rows[0].find('td', class_='right').text.strip(),
            'hash': rows[2].a.text.strip(),
            'tree': rows[3].a.text.strip(),
            'parent': rows[4].a.text.strip() if rows[4].a else None,
            'tree_url': rows[3].a['href']
        }
    except (AttributeError, IndexError) as e:
        logger.error(f"Error parsing commit table: {str(e)}")
        return None

# extract repo name
def _extract_repo_name(soup: BeautifulSoup, logger: logging.Logger) -> str:
    try:
        return soup.find('td', class_='main').find_all('a')[1].text.split('.')[0].replace('git/', '').replace('/', '-')
    except Exception as e:
        logger.warning(f"Failed to extract repo name: {str(e)}")
        return "unknown"

def _get_true_git_url(soup: BeautifulSoup, logger: logging.Logger) -> str:
#     </select> <input type="submit" value="switch"/></form></td></tr>
# <tr><td class="sub">X server  (mirrored from https://gitlab.freedesktop.org/xorg/xserver)</td><td class="sub right">keithp</td></tr></table>
# <table class="tabs"><tr><td>
    if "gitlab" in soup.text:
        logger.info("[!] cgit url but is gitlab")
        return "gitlab"
    else:
        return "cgit"

    
# handle cgit commit
def handle_cgit_commit(url: str, logger: logging.Logger) -> Optional[RawCommitInfo]:
    if "gitweb" in url:
        logger.error("gitweb in cgit URL")
        return handle_gitweb_commit(url, logger)

    parsed = urlparse(url)
    if "kernel" in url:
        repo = "kernel"
    elif "freedesktop" in url:
        repo = "freedesktop"
    elif "savannah" in url:
        repo = "freetype2"
    else:
        repo = "unknown"
    
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    soup = _fetch_html(url, logger)
    if not soup or soup.find('div', class_='error'):
        logger.error("Invalid repository page")
        return None
    
    get_true_git_url = _get_true_git_url(soup, logger)
    
    commit_data = _parse_commit_table(soup, logger)
    # print(commit_data)
    if not commit_data:
        return None

    git_url = f"{base_url}{urlparse(commit_data['tree_url']).path}".replace('/tree/', '')
    if get_true_git_url == 'gitlab':
        # https://gitlab.freedesktop.org/xorg/xserver
        git_url = git_url.replace('cgit', 'gitlab')
    if "git/" not in git_url:
        git_url = git_url.replace('org/', 'org/git/')
    # if git_url = "https://cgit.freedesktop.org/systemd/systemd":
    #     git_url = "https://anongit.freedesktop.org/git/systemd/systemd.git"
    # if git_url = "https://cgit.freedesktop.org/udisks":
    #     git_url = "https://anongit.freedesktop.org/git/udisks.git"
    # if git_url = "https://cgit.freedesktop.org/systemd/systemd":
    #     git_url = "https://anongit.freedesktop.org/git/systemd/systemd.git"
    if "cgit." in git_url:
        git_url = git_url.replace('cgit', 'anongit')
        if not git_url.endswith(".git"):
            git_url = git_url + ".git"
    if "cgit" in git_url:
        git_url = git_url.replace('cgit', 'git')

    # print(git_url)
    try:
        commit_date = datetime.strptime(commit_data['date'], "%Y-%m-%d %H:%M:%S %z").timestamp()
    except ValueError:
        logger.error("Invalid date format")
        return None
    
    tree_url = f"{base_url}{urlparse(commit_data['tree_url']).path}".replace('/tree/', '/plain/')
    # print(tree_url)
    diff_files = _parse_diff_files(soup, base_url, logger)
    if not diff_files:
        return None
    
    repo_name = _extract_repo_name(soup, logger)
    # http://git.kernel.org/?p=linux/kernel/git/torvalds/linux.git;a=commit;h=9ef1d4c7c7aca1cd436612b6ca785b726ffb8ed8  commit_url
    # https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9ef1d4c7c7aca1cd436612b6ca785b726ffb8ed8    raw
    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/   tree
    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-9ef1d4c7c7aca1cd436612b6ca785b726ffb8ed8.tar.gz   download
    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git   git url

    repo_download_url = f"{base_url}{urlparse(commit_data['tree_url']).path}".replace('/tree/', '/snapshot/') + f"{repo}-{commit_data['hash']}.tar.gz"
    # print(repo_download_url)

    
    return RawCommitInfo(
        repo_name=repo_name,
        commit_msg=soup.find('div', class_='commit-msg').text.strip(),
        commit_sha=commit_data['hash'],
        parent_commit_sha=commit_data['parent'],
        commit_date=int(commit_date),
        file_paths=diff_files,
        tree_url=tree_url,
        commit_url=url,
        repo_download_url=repo_download_url,
        git_url=git_url
    )


# parse diff files
def _parse_diff_files(soup: BeautifulSoup, base_url: str, logger: logging.Logger) -> List[str]:
    diff_link = soup.find('div', class_='diffstat-header')
    if not diff_link or not diff_link.a:
        logger.error("Diff link not found")
        return []
    
    diff_url = f"{base_url}{diff_link.a['href']}"
    diff_soup = _fetch_html(diff_url, logger)
    if not diff_soup:
        return []
    
    return [
        head.a.text.strip()
        for head in diff_soup.find_all('div', class_='head')
        if head.a and head.a.text
    ]

# fetch file content
def _fetch_file_content(url: str, logger: logging.Logger, retry: int) -> Optional[str]:
    for attempt in range(1, retry+1):
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.warning(f"Attempt {attempt}: Failed to download {url} - {str(e)}")
    return None


# save str to file
def _save_content(content: str, path: Path, logger: logging.Logger) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return True
    except OSError as e:
        logger.error(f"Failed to save {path}: {str(e)}")
        return False

# download patch files from cgit *bool download_parent_commit: download files from parent commit
def download_cgit_files(
    commit_info: RawCommitInfo,
    download_parent_commit: bool,
    save_dir: Path,
    logger: logging.Logger,
    retry: int = 3
) -> Tuple[List[str], List[str]]:
    
    if not is_cgit_url(commit_info.commit_url):
        logger.error("Invalid cgit url")
        return
    downloaded = []
    failed = []
    tree_hash = commit_info.parent_commit_sha if download_parent_commit else commit_info.commit_sha
    dir_path = os.path.join(save_dir, 'patch_before/') if download_parent_commit else os.path.join(save_dir, 'patch_after/')

    for file_path in commit_info.file_paths:
        safe_name = file_path.replace('..', '__').replace('/', '_')[:200]
        save_path = Path(os.path.join(dir_path, safe_name))
        
        if save_path.exists() and save_path.stat().st_size > 0:
            downloaded.append(file_path)
            continue
            
        file_url = f"{commit_info.tree_url}{file_path}?id={tree_hash}"
        content = _fetch_file_content(file_url, logger, retry)
        
        if content and _save_content(content, save_path, logger):
            downloaded.append(file_path)
            # logger.info(f"Downloaded {file_path}")
        else:
            logger.error(f"Failed to download {file_path}")
            failed.append(file_path)
    
    return downloaded, failed


def get_cgit_all_files(
    commit_info: RawCommitInfo,
    dir_path: str = "cgit_test",
    logger: logging.Logger = global_logger
) -> None:
    if "gitweb" in commit_info.commit_url:
        get_gitweb_all_files(commit_info, dir_path, logger)
        return

    if not commit_info or not commit_info.file_paths:
        logger.error("Invalid commit info or missing files")
        return

    base_dir = Path(dir_path)
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir/"patch_after").mkdir(exist_ok=True)
    (base_dir/"patch_before").mkdir(exist_ok=True)

    current_downloaded, current_failed = download_cgit_files(
        commit_info, False, base_dir, logger)
    parent_downloaded, parent_failed = download_cgit_files(
        commit_info, True, base_dir, logger) if commit_info.parent_commit_sha else ([], [])

    rawcode_path = base_dir/"rawcode.jsonl"
    error_count = len(current_failed) + len(parent_failed)
    
    with tqdm(commit_info.file_paths, desc="Generating metadata") as pbar:
        for idx, file_path in enumerate(pbar):
            try:
        
                safe_name = file_path.replace('..', '__').replace('/', '_')[:200]
                
                current_file = base_dir/"patch_after"/safe_name
                before_file = base_dir/"patch_before"/safe_name
                
                if not current_file.exists():
                    continue
                
                result_data = {
                    "patches_id": idx+1,
                    "files_id": idx+1,
                    "file_name": file_path,
                    "language": Path(file_path).suffix[1:],
                    "raw_url": f"{commit_info.tree_url}{file_path}",
                    "file_path": str(current_file),
                    "raw_code": current_file.read_text(encoding='utf-8'),
                    "raw_code_before": before_file.read_text(encoding='utf-8') if before_file.exists() else "",
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

# get cgit sha repo
def get_cgit_sha_repo_from_url(commit_url: str, save_dir: Path, logger: logging.Logger):
    if not is_cgit_url(commit_url):
        logger.error("Invalid cgit url")
        return
    dir_path = os.path.join(save_dir, "old_repos/")  
    os.makedirs(dir_path, exist_ok=True) 

    commit_info = handle_cgit_commit(commit_url, logger)
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

def get_cgit_sha_repo_from_clone(commit_url: str, save_dir: Path, logger: logging.Logger) -> Optional[Path]:
    
    if not is_cgit_url(commit_url):
        logger.error(f"Invalid cgit URL: {commit_url}")
        return None
    old_repos_dir = save_dir / "old_repos"
    old_repos_dir.mkdir(parents=True, exist_ok=True)


    try:
        commit_info = handle_cgit_commit(commit_url, logger)
        if not commit_info:
            logger.error("Failed to parse commit info")
            return None
    except Exception as e:
        logger.exception("Error parsing cgit commit")
        return None

    try:
        cloner = Cloner(platform="cgit")
       
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
    # test_url = "http://git.kernel.org/?p=linux/kernel/git/torvalds/linux.git;a=commit;h=9ef1d4c7c7aca1cd436612b6ca785b726ffb8ed8"
    test_url = "https://cgit.freedesktop.org/xorg/xserver/commit/?id=0c1a93d319558fe3ab2d94f51d174b4f93810afd"
    if is_cgit_url(test_url):
        commit_info = handle_cgit_commit(test_url, logger)
        print(commit_info)
        save_path = Path("./cgit_test")
        get_cgit_all_files(commit_info, save_path, logger)
        # if commit_info:
        #     logger.info(f"Processing commit: {commit_info.commit_sha}")
            
        #     
        #     downloaded, failed = download_cgit_files(commit_info, save_path, download_parent_commit=False, logger=logger) # patch_after
        #     downloaded_parent, failed_parent = download_cgit_files(commit_info, save_path, download_parent_commit=True, logger=logger) # patch_before
         
        # get_cgit_sha_repo_from_clone(test_url, save_path, logger)
        # work_dir = get_cgit_sha_repo_from_clone(test_url, save_path, logger)



if __name__ == "__main__":
    test()