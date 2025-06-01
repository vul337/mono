import subprocess
import os
import shutil
from pathlib import Path
from typing import List, Optional, Union
from dataclasses import dataclass
import json
import sys

from logging_helper import global_logger
from config_helper import config_file


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


class Cloner:
    """Git repository manager with caching and efficient checkout capabilities"""
    
    def __init__(self, platform: str = "github") -> None:
        """
        Initialize cloner with configuration from config_file
        
        :param platform: Version control platform name (e.g. github/gitlab)
        """
        self.platform = platform
        # Get base directory from configuration
        self.repo_cache = Path(config_file["repo_cache_path"]).resolve()
        # Platform-specific cache directory
        self.platform_dir = self.repo_cache / platform
        self.platform_dir.mkdir(parents=True, exist_ok=True)
    

    def clone(self, commit_info: RawCommitInfo, save_dir: Path) -> Path:
        """
        Clone or reuse cached repository with automatic reponame_sha directory naming
        :param commit_info: Commit metadata object
        :return: Path to the created working directory
        """

        if save_dir.exists() and len(list(save_dir.iterdir())) > 1:
            print(len(list(save_dir.iterdir())))
            global_logger.warning(f"Existing directory reused: {save_dir}")
            return save_dir
        elif save_dir.exists() and len(list(save_dir.iterdir())) == 1:
            shutil.rmtree(save_dir)
            os.makedirs(save_dir)
        else:
            os.makedirs(save_dir, exist_ok=True)

        latest_cache_dir = self.platform_dir / commit_info.repo_name
        self._ensure_cache_exists(latest_cache_dir, commit_info.git_url)
        self._store_copy_repository_path(latest_cache_dir, save_dir, commit_info)
        
        global_logger.info(f"Repository info ready at: {save_dir}")
        return save_dir

    def _store_copy_repository_path(self, source: Path, destination: Path, commit_info: RawCommitInfo) -> None:
        json_info = {
            "cache_repo_path": str(source), 
            "commit_sha": commit_info.commit_sha,
        }
     
        json_file = destination.parent / "info.json"

        if not json_file.exists():
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(json_info, f, indent=2)   
        return

    def clone_bak(self, commit_info: RawCommitInfo, save_dir: Path) -> Path:
        """
        Clone or reuse cached repository with automatic reponame_sha directory naming
        
        :param commit_info: Commit metadata object
        :return: Path to the created working directory
        """
        
        if save_dir.exists() and len(list(save_dir.iterdir())) > 1:
            print(len(list(save_dir.iterdir())))
            global_logger.warning(f"Existing directory reused: {save_dir}")
            return save_dir
        elif save_dir.exists() and len(list(save_dir.iterdir())) == 1:
            shutil.rmtree(save_dir)
            os.makedirs(save_dir)
        else:
            os.makedirs(save_dir, exist_ok=True)

        latest_cache_dir = self.platform_dir / commit_info.repo_name
        self._ensure_cache_exists(latest_cache_dir, commit_info.git_url)
        self._copy_repository(latest_cache_dir, save_dir)
        self._checkout_commit(save_dir, commit_info.commit_sha)
        
        global_logger.info(f"Repository ready at: {save_dir}")
        return save_dir

    def checkout(self, work_dir: Union[str, Path], commit_sha: str) -> None:
        """Checkout specific commit in the working directory"""
        self._execute_git(work_dir, ["checkout", "--quiet", "--force", commit_sha])

    def checkout_to_parent(self, work_dir: Union[str, Path], commit_sha: str) -> None:
        """Checkout parent commit (assumed to be vulnerable state)"""
        self._execute_git(work_dir, ["checkout", "--quiet", "--force", f"{commit_sha}^"])

    def _ensure_cache_exists(self, cache_dir: Path, git_url: str) -> None:
        """Create cache repository if not exists"""
        if cache_dir.exists() and len(list(cache_dir.iterdir())) > 1:
            global_logger.info(f"Existing cache reused: {git_url}")
            return
        elif cache_dir.exists() and len(list(cache_dir.iterdir())) == 1:
            global_logger.warning(f"Empty cache directory found: {cache_dir}")
            shutil.rmtree(cache_dir)
            os.makedirs(cache_dir)
        else:
            os.makedirs(cache_dir, exist_ok=True)
    
        global_logger.info(f"Creating new cache: {git_url}")
        self._execute_git(cache_dir.parent, ["clone", git_url, cache_dir.name])

        # Optimize cache performance
        self._execute_git(cache_dir, ["config", "--local", "core.preloadIndex", "true"])
        self._execute_git(cache_dir, ["config", "--local", "core.fscache", "true"])

    def _copy_repository(self, source: Path, destination: Path) -> None:
        """Copy repository using hard links when possible"""
        try:
            shutil.copytree(source, destination, copy_function=os.link, dirs_exist_ok=True)
            global_logger.debug("Used hard links for fast copy")
        except OSError:
            global_logger.warning("Falling back to standard copy (cross-device?)")
            if destination.exists():
                shutil.rmtree(destination)
                shutil.copytree(source, destination, dirs_exist_ok=True)


    def _checkout_commit(self, work_dir: Path, commit_sha: str) -> None:
        """Perform git checkout and validate success""" 
        self.checkout(work_dir, commit_sha)
        # Verify checkout result
        actual_sha = self._get_current_commit(work_dir)
        if actual_sha != commit_sha:
            error_msg = f"Checkout mismatch: Expected {commit_sha}, got {actual_sha}"
            global_logger.error(error_msg)
            raise RuntimeError(error_msg)

    def _get_current_commit(self, work_dir: Path) -> str:
        """Get current commit SHA of the working directory"""
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=work_dir,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        return result.stdout.strip()

    def _execute_git(self, path: Union[str, Path], commands: list) -> None:
        """Execute git command with error handling"""
        try:
            subprocess.run(
                ["git"] + commands,
                cwd=str(path),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
        except subprocess.CalledProcessError as e:
            error_msg = f"Git command failed: {' '.join(e.cmd)}\nOutput: {e.stdout}"
            global_logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    def cleanup(self, work_dir: Union[str, Path]) -> None:
        """Remove working directory"""
        work_dir = Path(work_dir)
        if work_dir.exists():
            shutil.rmtree(work_dir)
            global_logger.info(f"Cleaned up directory: {work_dir}")


