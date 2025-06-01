import os
import sys
import json
import shutil
import subprocess
import threading
import queue
from pathlib import Path
import re
import time
import difflib
import concurrent.futures
import time


from server_tools import JoernService
from get_repos import process_single_cve
from patch_analyzer import analyze_patch
from logging_helper import global_logger
from utils import get_cve_description

platform = "github"
NUM = 20
root_cve_folder     = "/Project/My_Agent/Agent4Vul/storage/result/Part2_result/" + platform

processed_cves_file = f"./processed_cves/{platform}.txt"
error_repo_file     = f"./error_repo/{platform}.txt"

in_joern_repos      = "/app/repos"
scripts_dir         = "/Project/My_Agent/Agent4Vul/3_Contextual Enhancer Module/Data_preproccess/joern_scripts"

num_containers      = 3
container_ports     = [2001 + i for i in range(num_containers)]
base_cache          = "/Project/My_Agent/Agent4Vul/agent_utils/multi_static_utils/joern_tools/app/cache"
base_url            = "http://localhost:{}"
ALL_WS_ROOT         = "./all_workspace"

task_queue         = queue.Queue()
processed_counter  = 0
counter_lock       = threading.Lock()

os.makedirs(os.path.dirname(processed_cves_file), exist_ok=True)
os.makedirs(os.path.dirname(error_repo_file), exist_ok=True)

if not os.path.exists(processed_cves_file):
    with open(processed_cves_file, 'w') as f:
        pass
if not os.path.exists(error_repo_file):
    with open(error_repo_file, 'w') as f:
        pass

# Prepare workspaces
workspace_dirs = []
for i in range(num_containers):
    ws = os.path.join(ALL_WS_ROOT, f"ws_{i+NUM}")
    os.makedirs(ws, exist_ok=True)
    workspace_dirs.append(ws)

def load_processed_cves():
    s = set()
    if os.path.exists(processed_cves_file):
        with open(processed_cves_file) as f:
            for l in f:
                s.add(l.strip())
    if os.path.exists(error_repo_file):
        with open(error_repo_file) as f:
            for l in f:
                s.add(l.strip().split(":")[0])
    return s


def load_error_repos():
    s = set()
    if os.path.exists(error_repo_file):
        with open(error_repo_file) as f:
            for l in f:
                s.add(l.strip().split(":")[0])
    return s

def save_processed(cve_id):
    with open(processed_cves_file, 'a') as f:
        f.write(cve_id + "\n")


def save_error(cve_id, msg):
    with open(error_repo_file, 'a') as f:
        f.write(f"{cve_id}: {msg}\n")


def run_joern(cmd, workspace, cve_id, stage, timeout=None):
    try:
        if timeout:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=workspace,
                timeout=timeout
            )
        else:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=workspace,
                timeout=1200
            )
    except subprocess.TimeoutExpired:
        raise
    except subprocess.CalledProcessError as e:
        global_logger.error(f"[{cve_id}] {stage} failed: {e.stderr}")
        raise


# ---------------- Patch Extraction ----------------
def extract_vul_info(cve_info):
    vul_info = []
    sec = cve_info.get("stats", {}).get("sec_vul", {})
    queries = sec.get("main_dir", []) + sec.get("no_more_info", [])
    queries = [q.replace(".json", "") for q in queries]
    raw = cve_info.get("raw_data", {})
    idx = 0
    for q in queries:
        data = raw.get(q)
        if not data:
            continue
        if idx == 0:
            vul_info.append({
                "cve_id":        data.get("cve_id", ""),
                "cwe_ids":       data.get("cwe_ids", []),
                "cvss_vector":   data.get("cvss_vector", ""),
                "cvss_is_v3":    data.get("cvss_is_v3", False),
                "description":   get_cve_description(data.get("cve_id", "no more info")),
                "commit_msg":    data.get("commit_msg", ""),
                "commit_sha":   data.get("commit_sha", ""),
                "git_url":       data.get("git_url", ""),
            })
        vul_info.append({
            "id":               idx,
            "func_name":        data.get("func_name", ""),
            "file_path":        data.get("file_path", ""),
            "patch":            data.get("diff_func", ""),
            "diff_line_info":   data.get("diff_line_info", {}),
            "func_before":      data.get("func_before", ""),
            "func_after":       data.get("func", ""),
            "Bug Filter":       data.get("Bug Filter", ""),
            "Bug Filter Confidence": data.get("Bug Filter Confidence", 0.0),
            "Bug Filter Response":    data.get("Bug Filter Response", ""),
        })
        idx += 1
    return vul_info

# extract function start line
def normalize_func_name(name: str) -> str:
    return name.split("::")[-1] if "::" in name else name

def find_start_line(func_name, file_path, cve_root):
    target_key = file_path.replace("/", "-")
    patch_before_dir = os.path.join(cve_root, "patch_before")
    fallback_file = None

    try:
        all_files = os.listdir(patch_before_dir)
    except Exception as e:
        global_logger.warning(f"[patch_line_offset] Failed to list patch_before: {e}")
        return 0

    for f in all_files:
        if target_key.endswith(f):
            fallback_file = os.path.join(patch_before_dir, f)
            break

    if not fallback_file:
        match = difflib.get_close_matches(target_key, all_files, n=1, cutoff=0.5)
        if match:
            fallback_file = os.path.join(patch_before_dir, match[0])

    if not fallback_file or not os.path.exists(fallback_file):
        global_logger.warning(f"[patch_line_offset] Backup file not found: {fallback_file}")
        return 0

    pattern = re.compile(
        r"^\s*(?:(?:[\w\*\s]|/\*.*?\*/|//.*?)+)?\b{re.escape(func_name)}\b\s*\(.*?\)(?:\s*throws\s+[\w\s,.<>?&|\[\]]+)?\s*(?:\{|;)",
        re.DOTALL 
    )

    try:
        with open(fallback_file) as f:
            for i, line in enumerate(f, 1):
                if pattern.match(line):
                    global_logger.info(f"[patch_line_offset] Fallback matched definition for {func_name} at line {i} in {os.path.basename(fallback_file)}")
                    return i
    except Exception as e:
        global_logger.warning(f"[patch_line_offset] Failed to read {fallback_file}: {e}")

    global_logger.warning(f"[patch_line_offset] No match for {func_name} definition in {os.path.basename(fallback_file)}")
    return 0

def extract_patch_line_ranges(cpg_file, vul_info, workspace, cve_id):
    joern_root = os.path.dirname(os.path.dirname(cpg_file))
    cve_root = os.path.dirname(joern_root)
    out_txt = os.path.join(joern_root, "patchs_before_start_line.txt")
    script_path = os.path.join(scripts_dir, "get_patch_before_func_start.scala")
    overlay_flag = os.path.join(os.path.dirname(cpg_file), ".add_overlay")

    # Step 1: Get Function Start Line (using Joern or fallback) # Upadate CPG
    mapping = {} # Stores file_path -> func_name -> start_line

    if not os.path.exists(out_txt) or not os.path.exists(overlay_flag):
        seen = set()
        unique = []

        for entry in vul_info[1:]:
            if isinstance(entry, dict) and entry.get("Bug Filter") == "Security Vulnerability Fix":
                 func_name = normalize_func_name(entry.get("func_name", ""))
                 file_path = entry.get("file_path", "")
                 if func_name and file_path:
                    key = (func_name, file_path)
                    if key not in seen:
                        seen.add(key)
                        unique.append(key)
                 else:
                     global_logger.warning(f"[{cve_id}] Missing func_name or file_path in entry: {entry}")

        if unique:
            methods = ",".join(fn for fn, _ in unique)
            files = ",".join(fp for _, fp in unique)
            cmd = [
                "joern", "--script", script_path,
                "--param", f"cpgFile={cpg_file}",
                "--param", f"methodList={methods}",
                "--param", f"fileList={files}",
                "--param", f"outFile={out_txt}"
            ]
            retry = 0
            while retry < 2:
                try:
                    global_logger.info(f"[{cve_id}] Run Joern: {methods} | {files}")
                    run_joern(cmd, workspace, cve_id, "extract_patch_line_ranges")
                    update_cpg(cpg_file, workspace, cve_id)
                    break
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                    global_logger.warning(f"[{cve_id}] Retry {retry+1} for extract_patch_line_ranges: {e}")
                    retry += 1
                except Exception as e:
                     global_logger.error(f"[{cve_id}] Unhandled error during Joern run: {e}")
                     break
        else:
             global_logger.info(f"[{cve_id}] No unique vulnerability fix entries found for Joern analysis.")

    try:
        if os.path.exists(out_txt):
            with open(out_txt, 'r') as f:
                for line in f:
                    try:
                        fp, fn, sl = line.strip().split(",", 2)
                        mapping.setdefault(fp, {})[fn] = int(sl)
                    except ValueError:
                         global_logger.warning(f"[{cve_id}] Skipping malformed line in {out_txt}: {line.strip()}")
        else:
             global_logger.warning(f"[{cve_id}] Joern output file not found after execution attempt: {out_txt}")

    except Exception as e:
        global_logger.error(f"[{cve_id}] Failed to read {out_txt}: {e}")

    # Step 2: Get Patch Lines from Git Analysis (PRIORITY)
    git_patch_lines_by_file = {}
    try:
        repo_cache_info = os.path.join(cve_root, "old_repos", "info.json")
        if os.path.exists(repo_cache_info):
            with open(repo_cache_info) as f:
                info = json.load(f)
                sha = info.get("commit_sha", "")
                repo_path = info.get("cache_repo_path", "")

            if sha and repo_path:
                global_logger.info(f"[{cve_id}] Analyzing Git patch for commit {sha} in repo {repo_path}")
                patches_from_git = analyze_patch(repo_path, sha) # Call the external analyze_patch function

                if patches_from_git:
                     for patch_info in patches_from_git:
                         if hasattr(patch_info, 'file_path') and hasattr(patch_info, 'deleted_lines') and hasattr(patch_info, 'added_lines'):
                             fp = patch_info.file_path
                             if fp not in git_patch_lines_by_file:
                                 git_patch_lines_by_file[fp] = {"del_lines": [], "add_lines": []}
                             git_patch_lines_by_file[fp]["del_lines"].extend(sorted(list(map(int, patch_info.deleted_lines.keys()))))
                             git_patch_lines_by_file[fp]["add_lines"].extend(sorted(list(map(int, patch_info.added_lines.keys()))))
                         else:
                             global_logger.warning(f"[{cve_id}] analyze_patch returned unexpected object structure: {patch_info}")

    except Exception as e:
        global_logger.error(f"[{cve_id}] Failed to analyze Git patch: {e}")
        git_patch_lines_by_file = {}


    file_patches = {} 
    extra_lines_to_append = [] 
    hunk_re = re.compile(r'@@\s*-(\d+),(\d+)\s*\+(\d+),(\d+)\s*@@')
    for entry in vul_info[1:]:
        if not isinstance(entry, dict):
            global_logger.warning(f"[{cve_id}] Skipping non-dictionary entry in vul_info: {entry}")
            continue

        fp = entry.get("file_path", "")
        raw_name = entry.get("func_name", "")
        patch_string = entry.get("patch", "") 

        if not fp or not raw_name:
             global_logger.warning(f"[{cve_id}] Skipping entry with missing file_path or func_name: {entry}")
             continue

        func_name = normalize_func_name(raw_name)

        # Get function offset (for context/logging and for patch string adjustment)
        offset = mapping.get(fp, {}).get(func_name, None)
        if offset is None or offset == 0:
            fallback_offset = find_start_line(func_name, fp, cve_root) # Assuming find_start_line is available
            if fallback_offset > 0:
                offset = fallback_offset
                global_logger.info(f"[{cve_id}] Fallback used for {func_name} in {fp} → offset={offset}")
                extra_lines_to_append.append(f"{fp},{func_name},{offset}")
            elif offset is None:
                 global_logger.warning(f"[{cve_id}] Func not found: {raw_name} in {fp} → offset=0")
                 offset = 0
            else:
                 global_logger.info(f"[{cve_id}] Func found (offset 0 from Joern): {func_name} in {fp} → offset=0")
        else:
            global_logger.info(f"[{cve_id}] Func found (from Joern): {func_name} in {fp} → offset={offset}")

        # --- Adjust patch hunk headers based on offset (Modifies entry["patch"]) ---
        if patch_string and offset is not None and offset > 0:
            global_logger.info(f"[{cve_id}] Adjusting patch hunk headers for {func_name} in {fp} using offset {offset}")
            def repl(m):
                old_a, old_b, new_c, new_d = map(int, m.groups())
                return f"@@ -{old_a+offset-1},{old_b} +{new_c+offset-1},{new_d} @@"
            try:
                updated_patch_string = hunk_re.sub(repl, patch_string)
                entry["patch"] = updated_patch_string # Modify the original entry in vul_info
                global_logger.debug(f"[{cve_id}] Patch string adjusted for {fp}")
            except Exception as e:
                global_logger.warning(f"[{cve_id}] Failed to adjust patch hunk headers for {func_name} in {fp}: {e}")
        elif patch_string:
             global_logger.debug(f"[{cve_id}] Patch string exists for {func_name} in {fp} but offset is 0 or None, skipping hunk adjustment.")
        # --- End Adjust patch hunk headers ---


        current_del_lines = []
        current_add_lines = []

        # --- Use Git Source FIRST for patch lines (file-relative) ---
        if fp in git_patch_lines_by_file and (git_patch_lines_by_file[fp]["del_lines"] or git_patch_lines_by_file[fp]["add_lines"]):
            global_logger.info(f"[{cve_id}] Using Git lines for patch related to {func_name} in {fp}")
            current_del_lines = git_patch_lines_by_file[fp]["del_lines"]
            current_add_lines = git_patch_lines_by_file[fp]["add_lines"]

        # --- Fallback to parsing original patch string if Git lines not available/empty for this file ---
        elif patch_string: 
            global_logger.warning(f"[{cve_id}] Git lines not available or empty for {fp}. Using patch string fallback for patch related to {func_name}.")
            temp_del_lines = []
            temp_add_lines = []
            for hunk_match in hunk_re.finditer(patch_string):
                 try:
                     old_a, old_b, new_c, new_d = map(int, hunk_match.groups())
                     if old_b > 0:
                         temp_del_lines.extend(list(range(old_a, old_a + old_b)))
                     if new_d > 0:
                         temp_add_lines.extend(list(range(new_c, new_c + new_d)))
                 except ValueError:
                     global_logger.warning(f"[{cve_id}] Failed to parse hunk header in patch for {fp}: {hunk_match.group(0)}")
                     continue

            current_del_lines = temp_del_lines
            current_add_lines = temp_add_lines

            if not current_del_lines and not current_add_lines:
                 global_logger.warning(f"[{cve_id}] Failed to extract any line ranges from patch string for {fp} after parsing all hunks.")
        else:
            global_logger.warning(f"[{cve_id}] No Git lines and no original patch string for entry related to {func_name} in {fp}. Cannot determine affected lines.")

        rec = file_patches.setdefault(fp, {"del_lines": [], "add_lines": []})

        rec["del_lines"].extend(current_del_lines)
        rec["del_lines"] = sorted(list(set(rec["del_lines"])))

        rec["add_lines"].extend(current_add_lines)
        rec["add_lines"] = sorted(list(set(rec["add_lines"])))
    
    # --- Step 4: Append Fallback Offsets to File ---
    if extra_lines_to_append:
        try:
            with open(out_txt, 'a') as f:
                for line in extra_lines_to_append:
                    f.write(line + "\n")
            global_logger.info(f"[{cve_id}] Wrote {len(extra_lines_to_append)} fallback offsets to {out_txt}")
        except Exception as e:
            global_logger.warning(f"[{cve_id}] Failed to write fallback offsets to {out_txt}: {e}")

    return file_patches

# ---------------- CPG & Joern ----------------
def generate_static_cpg(jq, repo_path, cve_path):
    joern_root = os.path.join(cve_path, "Joern_files")
    os.makedirs(joern_root, exist_ok=True)
    cpgs_dir   = os.path.join(joern_root, "cpgs")
    os.makedirs(cpgs_dir, exist_ok=True)
    target_cpg = os.path.join(cpgs_dir, "cpg.bin")

    old_cpg = os.path.join(joern_root, "cpg.bin")
    if os.path.exists(old_cpg) and os.stat(old_cpg).st_size > 0:
        global_logger.info(f"[CPG] reuse existing non-empty CPG: {old_cpg}")
        shutil.move(old_cpg, target_cpg)
        for name in os.listdir(joern_root):
            path = os.path.join(joern_root, name)
            if path == cpgs_dir:
                continue
            if os.path.isdir(path): shutil.rmtree(path)
            else: os.remove(path)

    if not os.path.exists(target_cpg):
        global_logger.info(f"[CPG] parsing {repo_path} → {target_cpg}")
        jq.static_cpg_gen(project_path=repo_path, output_dir=cpgs_dir)
    else:
        global_logger.info(f"[CPG] already exists at {target_cpg}")

    return target_cpg

# overlay cpg update
def update_cpg(cpg_file, workspace, cve_id):
    overlay_flag = os.path.join(os.path.dirname(cpg_file), ".add_overlay")
    if os.path.exists(overlay_flag):
        return
    updated = False
    for root, dirs, files in os.walk(workspace):
        if "project.json" in files:
            pj_path = os.path.join(root, "project.json")
            try:
                with open(pj_path) as f:
                    info = json.load(f)
                input_path = info.get("inputPath")
                if input_path == cpg_file:
                    cpg_generated = os.path.join(root, "cpg.bin")
                    if os.path.exists(cpg_generated):
                        shutil.move(cpg_generated, cpg_file)
                        global_logger.info(f"[{cve_id}][Updated CPG]: {cpg_generated} → {cpg_file}")
                        updated = True
                        break
            except Exception as e:
                print(f"⚠ Failed to read/parse {pj_path}: {e}")

    if updated:
        with open(overlay_flag, 'w') as f:
            f.write("true")
        
    
def generate_file_cache(cpg_file, cve_path, workspace, version="before"):
    out = os.path.join(cve_path, "Joern_files", f"{version}_context", "file_cache.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out):
        global_logger.info(f"[FileCache] exists {out}")
        return json.load(open(out))

    script_path = os.path.join(scripts_dir, "file_cache.scala")
    cmd = [
        "joern", "--script", script_path,
        "--param", f"cpgFile={cpg_file}",
        "--param", f"outFile={out}"
    ]
    global_logger.info(f"[FileCache] generating for {cpg_file}")
    try:
        run_joern(cmd, workspace, os.path.basename(cve_path), "generate_file_cache", timeout=300)
    except subprocess.TimeoutExpired:
        global_logger.warning(f"[FileCache] timed out, skipping file cache")
        return {}
    except subprocess.CalledProcessError:
        global_logger.error(f"[FileCache] failed, skipping file cache")
        return {}
    return json.load(open(out))

def get_methods_for_file(repo, fp, lines, cve_path, workspace, version="before"):
    ln = ",".join(map(str, sorted(lines))) if lines else "0"
    out_txt = os.path.join(cve_path, "Joern_files", f"{version}_context", f"methods_{os.path.basename(fp)}.txt")
    if not os.path.exists(out_txt):
        script_path = os.path.join(scripts_dir, "get_methods.scala")
        cmd = [
            "joern", "--script", script_path,
            "--param", f"codeFile={os.path.join(repo, fp)}",
            "--param", f"lineNumbers={ln}",
            "--param", f"outFile={out_txt}"
        ]
        global_logger.info(f"[get_methods] {fp}")
        try:
            run_joern(cmd, workspace, os.path.basename(cve_path), "get_methods")
        except subprocess.CalledProcessError:
            global_logger.error(f"[get_methods] failed, skipping")
            return set()

    ms = set()
    with open(out_txt) as f:
        for L in f:
            p = L.strip().split()
            if p: ms.add(p[0])
    return ms

def run_bfs(cpg, repo, fp, methods, lines, cve_path, workspace, version="before"):
    ln = ",".join(map(str, sorted(lines))) if lines else "0"
    out_j = os.path.join(cve_path, "Joern_files", f"{version}_context", f"bfs_{os.path.basename(fp)}.json")
    os.makedirs(os.path.dirname(out_j), exist_ok=True)
    if os.path.exists(out_j):
        global_logger.info(f"[bfs] exists {out_j}")
        return json.load(open(out_j))
    script_path = os.path.join(scripts_dir, "method_bfs.scala")
    cmd = [
        "joern", "--script", script_path,
        "--param", f"cpgFile={cpg}",
        "--param", f"filename={fp}",
        "--param", f"methodnameList={','.join(methods)}",
        "--param", f"lineNumbers={ln}",
        "--param", f"outFile={out_j}"
    ]
    global_logger.info(f"[bfs] {fp}")
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=300, cwd=workspace)
    except subprocess.TimeoutExpired:
        global_logger.warning(f"[bfs] timed out, skipping")
        return {}
    except subprocess.CalledProcessError:
        global_logger.error(f"[bfs] failed, skipping")
        return {}
    return json.load(open(out_j))

def run_pdg(cpg, bfs_json, file_path, cve_path, workspace, version="before"):
    out_dir = os.path.join(cve_path, "Joern_files", f"{version}_context")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"pdg_{os.path.basename(file_path)}.json")
    if os.path.exists(out_file):
        global_logger.info(f"[pdg] exists {out_file}")
        return json.load(open(out_file))

    entries = [(fname, fullName, depth) for (fname, _, fullName, _, depth) in bfs_json.get("relatedMethod", [])]
    candidates = [
        (full, d) for (fname, full, d) in entries
        if fname == file_path and d <= 2 and not full.startswith("<empty>.") and ".<operator>." not in full
    ]
    if not candidates:
        global_logger.info("[pdg] no relevant methods → skip PDG")
        return {}
    depth1 = [f for f, d in candidates if d == 1]
    depth2 = [f for f, d in candidates if d == 2]
    selected = depth1[:10] + depth2[:max(0, 10 - len(depth1))]
    method_list = ",".join(selected)
    global_logger.info(f"[pdg] methods → {method_list}")
    script_path = os.path.join(scripts_dir, "pdg.scala")
    cmd = [
        "joern", "--script", script_path,
        "--param", f"cpgFile={cpg}",
        "--param", f"methodList={method_list}",
        "--param", f"outFile={out_file}"
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=1800, cwd=workspace)
    except Exception:
        global_logger.warning(f"[pdg] failed or timed out, skipping")
        return {}
    return json.load(open(out_file))


def merge_contexts(contexts, patches):
    final = {"relatedMethod": set(), "typeDefs": set(), "globalVars": set(),
             "importContext": set(), "vulnerableMethods": set(),
             "visitedLines": {}, "visitedParams": {}}
    for ctx in contexts.values():
        for cm in ctx.get("relatedMethod", []): final["relatedMethod"].add(tuple(cm))
        for td in ctx.get("typeDefs", []): final["typeDefs"].add(tuple(td))
        for gv in ctx.get("globalVars", []): final["globalVars"].add(gv)
        for ic in ctx.get("importContext", []): final["importContext"].add(ic)
        for vm in ctx.get("vulnerableMethods", []): final["vulnerableMethods"].add(tuple(vm))
        for ln, m, f2 in ctx.get("visitedLines", []): final["visitedLines"].setdefault(f2, set()).add(ln)
        for param, m, f2 in ctx.get("visitedParams", []): final["visitedParams"].setdefault(f2, set()).add(param)
    return {
        "relatedMethod":       [list(x) for x in final["relatedMethod"]],
        "typeDefs":            [list(x) for x in final["typeDefs"]],
        "globalVars":          list(final["globalVars"]),
        "importContext":       list(final["importContext"]),
        "vulnerableMethods":   [list(x) for x in final["vulnerableMethods"]],
        "visitedLines":        {fp: sorted(list(s)) for fp, s in final["visitedLines"].items()},
        "visitedParams":       {fp: sorted(list(s)) for fp, s in final["visitedParams"].items()}
    }


# ---------------- Linux Repo Processing ----------------
def get_parent_commit(repo_path, commit_sha):
    result = subprocess.run(
        # ["/usr/bin/git", "rev-parse", f"{commit_sha}^"],
        ["git", "rev-parse", f"{commit_sha}^"],
        capture_output=True,
        text=True,
        cwd=repo_path,
    )
    return result.stdout.strip()

def get_full_path(repo_path, file_path):
    raw_pro = os.path.abspath(repo_path)
    possible_paths = [
        os.path.join(raw_pro, file_path),
    ]
    
    for full_path in possible_paths:
        if os.path.exists(full_path):
            return full_path
    
    path_parts = file_path.split(os.path.sep)
    target_dir = path_parts[0] 
    
    for root, dirs, _ in os.walk(raw_pro):
        if target_dir in dirs:  
            matched_dir = os.path.join(root, target_dir)
            remaining_path = os.path.sep.join(path_parts[1:])  
            full_path = os.path.join(matched_dir, remaining_path)
            
            if os.path.exists(full_path):
                return full_path
    
    for root, _, files in os.walk(raw_pro):
        for file in files:
            current_file_path = os.path.join(root, file)
            if file_path in current_file_path:  
                return current_file_path


def get_bigrepo_related_topdirs(cve_path):
    info_path = Path(cve_path) / "old_repos" / "info.json"
    with info_path.open() as f:
        info = json.load(f)
        commit_sha = info.get("commit_sha", {})
        repo_cache = info.get("cache_repo_path", {})
    short = commit_sha[:7]

    repo_root = Path(cve_path) / "old_repos" 

    parent_hash = get_parent_commit(repo_cache, commit_sha)
    repo_path = repo_root / f"{Path(repo_cache).name}_{parent_hash[:7]}"
    new_tmp_repos = repo_root / f"{repo_path.name[:-2]}"

    if os.path.exists(new_tmp_repos) and os.path.isdir(new_tmp_repos):
        shutil.rmtree(new_tmp_repos, ignore_errors=True)
        # global_logger.info(f"old_repos already exists: {new_tmp_repos}")
        # sha_info = os.path.join(repo_path, "sha_info.json")
        # if os.path.exists(sha_info):
        #     shutil.copy(sha_info, new_tmp_repos)
        # tmp_sha = os.path.join(new_tmp_repos, "sha_info.json")
        # if os.path.exists(tmp_sha) and len(os.listdir(new_tmp_repos)) > 1:
        #     shutil.rmtree(repo_path, ignore_errors=True)
        # return new_tmp_repos

    patches = analyze_patch(repo_cache, commit_sha)
    changed_files = set()
    for patch in patches:
        if patch.file_path not in changed_files:
            changed_files.add(patch.file_path)
    
    need_dir = set()
    for file_path in changed_files:
        full_path = get_full_path(repo_path, file_path)
        if full_path and os.path.exists(full_path):
            rel_path = Path(full_path).relative_to(repo_path)
            if len(rel_path.parts) == 1:
                need_dir.add("")
            elif len(rel_path.parts) > 1:
                need_dir.add(rel_path.parts[0])
        else:
            global_logger.warning(f"not found linux file: {file_path}")

    if "linux" in repo_path.name.lower(): 
        need_dir.add("include")
        need_dir.add("kernel")
    new_tmp_repos.mkdir(exist_ok=True, parents=True)
    sorted_need_dir = sorted(list(need_dir))
    folded_dirs = []
    for d in sorted_need_dir:
        if not any(d == kept or d.startswith(kept + os.path.sep) for kept in folded_dirs):
            folded_dirs.append(d)
    
    for rel_dir in folded_dirs:
        src_dir = repo_path / rel_dir
        dst_dir = new_tmp_repos / rel_dir

        if not src_dir.exists():
            global_logger.warning(f"Source directory does not exist: {src_dir}. Skipping copy.")
            continue

        try:
            if rel_dir == "":
                for item in src_dir.iterdir():
                    if item.name == ".git" or item.name == "sha_info.json": 
                        continue
                    if item.is_dir():
                        shutil.copytree(item, new_tmp_repos / item.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, new_tmp_repos / item.name)
            else:
                shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
        except Exception as e:
            global_logger.error(f"Copy {src_dir} -> {dst_dir} failed: {e}")
    
    sha_info = repo_path / "sha_info.json"
    if sha_info.exists():
        try:
            shutil.copy(sha_info, new_tmp_repos)
        except Exception as e:
            global_logger.error(f"Failed to copy sha_info.json to {new_tmp_repos}: {e}")

    tmp_sha = new_tmp_repos / "sha_info.json"
    has_other_content = any(item.name != tmp_sha.name for item in Path(new_tmp_repos).iterdir())

    if tmp_sha.exists() and has_other_content:
        shutil.rmtree(repo_path, ignore_errors=True) 
        global_logger.info(f"old_repos created: {new_tmp_repos}")
        return new_tmp_repos
    else:
        global_logger.warning(f"New temporary repository {new_tmp_repos} does not contain expected content or sha_info.json. Returning None.")
        shutil.rmtree(new_tmp_repos, ignore_errors=True) 
        return None

### final check
def check_root_cause(cve_path): # all_analysis ---> Root_cause_analysis.json
    final_root = None
    root_cause = os.path.join(cve_path, "root_cause_analysis.json")
    Root_cause = os.path.join(cve_path, "Root_cause_analysis.json")
    root_cause_06 = os.path.join(cve_path, "Root_cause_analysis_06.json")
    Root_cause_top10 = os.path.join(cve_path, "Root_cause_analysis_top10.json")
    error_analysis = os.path.join(cve_path, "error_analysis.json")
    error_analysis_top10 = os.path.join(cve_path, "error_analysis_top10.json")
    if os.path.exists(error_analysis) or os.path.exists(error_analysis_top10):
        with open("./error_analysis.txt", 'a') as f:
            f.write(f"{cve_id}\n")
    if os.path.exists(root_cause):
        final_root = root_cause
    if os.path.exists(Root_cause):
        final_root = Root_cause
    if os.path.exists(root_cause_06):
        final_root = root_cause_06
    if os.path.exists(Root_cause_top10):
        final_root = Root_cause_top10
    if final_root is None:
        global_logger.warning(f"[{cve_path}] no root_cause_analysis found")
        return False
    with open(final_root) as f:
        root_cause_info = json.load(f)
    final_root = os.path.join(cve_path, "Root_cause_analysis.json")
    with open(final_root, 'w') as f:
        json.dump(root_cause_info, f, indent=2)
    if os.path.exists(root_cause):
        os.remove(root_cause)
    if os.path.exists(root_cause_06):
        os.remove(root_cause_06)
    if os.path.exists(Root_cause_top10):
        os.remove(Root_cause_top10)
    # global_logger.info(f"[{cve_path}] root_cause_analysis saved to {final_root}")
    return True

def save_root_cause(cve_id):
    with open("./root_success.txt", 'a') as f:
        f.write(f"{cve_id}\n")


# ---------------- CVE Processing ----------------
def process_cve_task(cve_id, cve_path, jq, workspace):
    global processed_counter
    global_logger.info(f"[{cve_id}] processing {cve_path}")
    root_cause_flag = check_root_cause(cve_path)
    if root_cause_flag:
        global_logger.info(f"[{cve_id}] root_cause_analysis.json already exists, skipping")
        save_root_cause(cve_id)
        return True
    try:
        jf   = os.path.join(cve_path, f"{cve_id}-all-part1.json")
        cinfo= json.load(open(jf))
        vul  = extract_vul_info(cinfo)
        if len(vul) <= 1:
            raise RuntimeError("no patch entries") 

        get_repos = process_single_cve(Path(cve_path))
        if "error" in get_repos:
            global_logger.error(f"[{cve_id}] {get_repos['error']}")
            save_error(cve_id, f'Get Old repos error {get_repos["error"]}')
            return False
        subs = [d for d in (Path(cve_path)/"old_repos").iterdir() if d.is_dir()]
        if not subs:
            raise RuntimeError("no old_repos")

        # repo = str(subs[0]) if "linux" not in vul[0]["git_url"] else str(get_bigrepo_related_topdirs(cve_path))
        repo = str(subs[0]) 
        # repo = str(get_bigrepo_related_topdirs(cve_path))
        if repo is None:
            global_logger.error(f"[{cve_id}] failed to get bigrepo related topdirs")
            save_error(cve_id, "no old_repos generated failed, please check by hand")
            return False
        vul[0]["raw_repo"] = repo

        # generate CPG & file cache
        cpg_file   = generate_static_cpg(jq, repo, cve_path)
        vul[0]["before_cpg_file"]       = cpg_file
        
        # patch ranges && update CPG
        patches = extract_patch_line_ranges(cpg_file, vul, workspace, cve_id)
        if not patches:
            raise RuntimeError("extract_patch_line_ranges failed")
        # file_cache
        file_cache = generate_file_cache(cpg_file, cve_path, workspace)
        vul[0]["before_cpg_file_cache"] = file_cache
        # BFS & PDG before
        ctxs_before = {}
        for fp, rec in patches.items():
            ms = get_methods_for_file(repo, fp, rec["del_lines"], cve_path, workspace)
            if not ms: continue
            bfs = run_bfs(cpg_file, repo, fp, ms, rec["del_lines"], cve_path, workspace)
            run_pdg(cpg_file, bfs, fp, cve_path, workspace)
            ctxs_before[fp] = bfs

        final_before = merge_contexts(ctxs_before, patches)
        vul[0]["before_context"] = final_before
        out_json = os.path.join(cve_path, "context_preprocess.json")
        with open(out_json, 'w') as f:
            json.dump(vul, f, indent=2)
        global_logger.info(f"[{cve_id}] success saved preprocess → {out_json}")

        save_processed(cve_id)
        with counter_lock:
            processed_counter += 1
        
        # clean up 
        preinfo = os.path.join(cve_path, "precess_info.json")
        if os.path.exists(preinfo):
            os.remove(preinfo)

        try:
            shutil.rmtree(workspace)
            os.makedirs(workspace, exist_ok=True)
            global_logger.info(f"[{cve_id}] cleaned workspace {workspace}")
        except Exception as e:
            global_logger.warning(f"[{cve_id}] failed to cleanup {workspace}: {e}")

        return True
    except Exception as e:
        global_logger.error(f"[{cve_id}] ERROR: {e}")
        save_error(cve_id, str(e))
        return False




# ---------------- Worker & Main ----------------
# def worker(idx):
#     ws = workspace_dirs[idx]
#     my_cache = os.path.join(base_cache, f"cache_{idx}")
#     os.makedirs(my_cache, exist_ok=True)
#     jq = JoernService(out_workspace=ws, out_cache=my_cache, base_url=base_url.format(container_ports[idx]))
#     while True:
#         try:
#             cve_id, cve_path = task_queue.get_nowait()
#         except queue.Empty:
#             break
#         process_cve_task(cve_id, cve_path, jq, ws)
#         task_queue.task_done()


def worker(idx, task_timeout_seconds=1800):
    ws = os.path.join(workspace_dirs[idx])
    my_cache = os.path.join(base_cache, f"cache_{idx}")
    os.makedirs(my_cache, exist_ok=True)
    jq = JoernService(out_workspace=ws, out_cache=my_cache, base_url=base_url.format(container_ports[idx]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        while True:
            try:
                cve_id, cve_path = task_queue.get_nowait()
            except queue.Empty:
                break

            future = executor.submit(process_cve_task, cve_id, cve_path, jq, ws)

            try:
                future.result(timeout=task_timeout_seconds)
            except concurrent.futures.TimeoutError:
                print(f"Task {cve_id} timed out after {task_timeout_seconds} seconds.")
            except Exception as e:
                print(f"Error processing {cve_id}: {e}")
            finally:
                task_queue.task_done()

def main():
    processed = load_processed_cves()
    error_cves = load_error_repos()
    global_logger.info(f"Loaded {len(processed)} processed CVEs and {len(error_cves)} error CVEs")
    need_do = processed - error_cves
    global_logger.info(f"Need to process {len(need_do)} CVEs")
    total = 0
    for entry in os.listdir(root_cve_folder):
        # if entry.startswith("CVE-") and entry not in processed:
        if entry.startswith("CVE-") and entry in need_do:
            task_queue.put((entry, os.path.join(root_cve_folder, entry)))
            total += 1

    threads = []
    for i in range(num_containers):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    global_logger.info(f"All done. Total queued: {total}")

if __name__ == "__main__":
    main()
    # test()
