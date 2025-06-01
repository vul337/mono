import json
import shutil
import subprocess
import os
from pathlib import Path

from logging_helper import global_logger
import shutil as _shutil

def find_git() -> str:
    for path in ("/usr/bin/git", "/bin/git"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return _shutil.which("git") or "git"

GIT = find_git()
logger = global_logger

def get_sha(repo_path: Path) -> str:
    try:
        out = subprocess.run(
            [GIT, "rev-parse", "HEAD"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True
        )
        return out.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"rev-parse failed: {e.stderr}")
        return ""
def get_parent_sha(sha: str, repo_path: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", f"{sha}^"],  # Use sha^ to get the parent
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        return out.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"get_parent_sha: Failed to get parent SHA of {sha}: {e.stderr}")
        return ""
    except Exception as e:
        logger.error(f"get_parent_sha: An unexpected error occurred: {e}")
        return ""
    
def check_git_sha(snapshot_dir: Path, target_sha: str) -> bool:
    tmp = str(snapshot_dir)
    if not os.path.isdir(tmp):
        logger.error(f"check_git_sha: {tmp} is not a directory")
        return False
    dir_contents = [f.name for f in snapshot_dir.iterdir() if f.name != "sha_info.json"]
    if not dir_contents:
        logger.error(f"check_git_sha: {tmp} contains only sha_info.json or is empty.")
        return False 
    f = snapshot_dir / "sha_info.json"
    if not f.exists():
        current_sha = get_sha(snapshot_dir)
        if current_sha == target_sha:
            return True
        else:
            return False
    try:
        data = json.loads(f.read_text())
        file_sha = data.get("now_sha")
        if file_sha == target_sha:
            return True
        else:
            current_sha = get_sha(snapshot_dir)
            if current_sha == target_sha:
                return True
            else:
                return False
    except json.JSONDecodeError:
        return False
    except Exception:
        return False

def save_sha(sha: str, d: Path):
    d.mkdir(parents=True, exist_ok=True)
    (d / "sha_info.json").write_text(json.dumps({"now_sha": sha}, indent=4))

def ensure_commit(repo_path: Path, sha: str) -> bool:
    if subprocess.run([GIT, "cat-file", "-e", sha], cwd=repo_path).returncode == 0:
        logger.info(f"Commit {sha} already exists in {repo_path}")
        return True
    if subprocess.run([GIT, "fetch", "origin", sha], cwd=repo_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        logger.info(f"Fetched commit {sha} in {repo_path}")
        return True
    logger.error(f"Cannot fetch commit {sha}")
    return False

# fast_copy is a function that uses rsync to copy files from src to dst
def fast_copy(src: Path, dst: Path) -> bool:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["rsync", "-az", "--exclude=.git/", f"{src}/", str(dst)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

def process_single_cve(cve_dir: str) -> dict:
    base = Path(cve_dir)
    info = base / "old_repos" / "info.json"

    repo_base = base / "old_repos"
    # repo_dir = list(repo_base.glob("*/"))
    # if repo_dir:
    #     logger.info(f"Found existing repositories in {repo_base}, use them directly.")
    #     return {"success": True, "message": "Existing repositories found, no need to process."}

    if not info.exists():
        return {"success": False, "error": f"Info file {info} does not exist"}
    
    try:
        data = json.loads(info.read_text())
    except Exception as e:
        return {"success": False, "error": f"Failed to parse info.json: {e}"}

    if "/mnt/d/agent_c/repo_cache" in data["cache_repo_path"]:
        data["cache_repo_path"] = data["cache_repo_path"].replace("/mnt/d/agent_c/repo_cache", "/mnt/data/agent_cache/repo_cache")

    repo = Path(data["cache_repo_path"])
    now_sha = data["commit_sha"]
    sha = get_parent_sha(now_sha, repo)  # Get the parent SHA repos

   
    name = repo.name
    short = sha[:7]
    snap = base / "old_repos" / f"{name}_{short}"

    # linux_tmp = base / "old_repos" / snap.name[:-2]
    # if linux_tmp.exists() and check_git_sha(linux_tmp, sha):
    #     logger.info(f"Snapshot {linux_tmp} already exists and matches SHA {sha}")
    #     return {"success": True}
    # if linux_tmp.exists():
    #     logger.info(f"Removing existing snapshot {linux_tmp}")
    #     shutil.rmtree(linux_tmp, ignore_errors=True)

    # if snap.exists() and check_git_sha(snap, sha):
    if snap.exists() and snap.is_dir():
        logger.info(f"Snapshot {snap} already exists and matches SHA {sha}")
        return {"success": True}

    # if snap.exists():
    #     logger.info(f"Removing existing snapshot {snap}")
    #     shutil.rmtree(snap, ignore_errors=True)

    if not ensure_commit(repo, sha):
        return {"success": False, "error": f"Commit {sha} not available and cannot be fetched."}

    try:
        logger.info(f"Creating worktree {snap} for {sha}")
        subprocess.run(
            [GIT, "worktree", "add", "--detach", "--quiet", str(snap), sha],
            cwd=repo,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        return {"success": False, "error": f"Failed to create worktree: {e.stderr}"}

    actual_sha = get_sha(snap)
    if not actual_sha:
        logger.error(f"Failed to get SHA from snapshot directory {snap}")
        save_sha(sha, snap)
    else:
        logger.info(f"Snapshot {snap} created with SHA {actual_sha}")
        save_sha(actual_sha, snap)
    
    return {"success": True}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: get_repos.py <CVE_DIR>")
        sys.exit(1)
    success = process_single_cve(sys.argv[1])
    sys.exit(0 if success else 1)
