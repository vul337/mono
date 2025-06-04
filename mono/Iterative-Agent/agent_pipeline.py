import os
import json
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Dict, List, Set, Union

from agent_worker import VulnWorkflow, AgentState, save_result_to_json
from logging_helper import global_logger
logger = global_logger

PROMPT_VERSION = "default" # "pragmatic"
MODEL_NAME = "Qwen/Qwen3-32B"
# MODEL_NAME = "gpt-4o-2024-11-20"

TEMPERATURE = 0.8
NUM_CONTAINERS = 4

platform = "kernel"  
ROOT_CVE_FOLDER = Path(f"/Project/My_Agent/Agent4Vul/storage/result/Part2_result/{platform}")
# SUCCESS_FILE = Path(f"./agent_sucess/success_cves_{platform}.txt")
# FAILED_FILE = Path(f"./agent_fail/failed_cves_{platform}.txt")

PROCESSED_CVES_FILE = Path(f"Project/My_Agent/Agent4Vul/4_Experiment/RQ2/Dataset_Statistic/finals/{platform}/Precess.txt")
SUCCESS_FILE = Path(f"./final_check_success.txt")
FAILED_FILE = Path(f"./final_check_error.txt")
JOERN_PORTS = [2000 + i for i in range(NUM_CONTAINERS)]
PORT_QUEUE = queue.Queue()

for port in JOERN_PORTS:
    PORT_QUEUE.put(port)

os.environ['OPENAI_API_KEY'] = "aaaa"
os.environ['OPENAI_API_BASE'] = "http://127.0.0.1:8082/v1"

global_logger.info(f"Using model: {MODEL_NAME} with podman containers: {NUM_CONTAINERS}\n \t\tplatform: {platform}")

def append_to_success_cves(cve_id: str, cve_path: Path, context_count: int, iteration: int, confidence_score: float) -> None:
    with open(SUCCESS_FILE, 'a') as f:
        f.write(f"{cve_id},{cve_path},{context_count},{iteration},{confidence_score}\n")

def append_to_failed_cves(cve_id: str, cve_path: Path, reason: str) -> None:
    with open(FAILED_FILE, 'a') as f:
        f.write(f"{cve_id},{cve_path},{reason}\n")

def load_success_cves() -> Set[str]:
    success_cves = set()
    if SUCCESS_FILE.exists():
        with open(SUCCESS_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    cve_id = line.strip().split(',')[0]
                    try:
                        iteration = int(line.strip().split(',')[3])
                        context_count = int(line.strip().split(',')[2])
                        confidence_score = float(line.strip().split(',')[4])
                        if context_count == 0 and iteration > 0:
                            global_logger.warning(f"{line.strip()}")
                    except ValueError:
                        continue
                    success_cves.add(cve_id)
    # if FAILED_FILE.exists():
    #     with open(FAILED_FILE, 'r') as f:
    #         for line in f:
    #             if line.strip():
    #                 cve_id = line.strip().split(',')[0]
    #                 success_cves.add(cve_id)
    # global_logger.info(f"Loaded {len(success_cves)} success CVEs.")
    return success_cves

def load_processed_cves() -> List[str]:
    success = load_success_cves()
    result = []
    if PROCESSED_CVES_FILE.exists():
        with open(PROCESSED_CVES_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip() and line.strip() not in success]
    return []     


def load_cve_data(cve_id: str) -> Union[Dict, None]:
    path = ROOT_CVE_FOLDER / cve_id / "context_preprocess.json"
    if not path.exists():
        logger.warning(f"Missing context_preprocess.json for {cve_id}")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def count_valid_contexts(enriched_data: List[Dict]) -> int:
    count = 0
    for item in enriched_data:
        result = item.get("result")
        if isinstance(result, str):
            if "no valid" not in result:
                count += 1
        elif isinstance(result, list) and result:
            count += 1
        else: 
            count += 1
    return count

def process_cve(cve_id: str, config: Dict) -> None:
    vul_info = load_cve_data(cve_id)
    if not vul_info:
        append_to_failed_cves(cve_id, ROOT_CVE_FOLDER / cve_id, "context_preprocess.json missing")
        return

    msg = vul_info[0]["commit_msg"]
    description = vul_info[0]["description"]
    project_dir = vul_info[0]["raw_repo"]
    file_cache = vul_info[0]["before_cpg_file_cache"]
    cpg_file = vul_info[0]["before_cpg_file"]

    if not os.path.exists(cpg_file):
        if "Joern_files" in cpg_file:
            # Handle the case where the CPG file is in a different directory
            cpg_file = cpg_file.replace("Joern_files", "Joern_file")
        elif "Joern_file" in cpg_file:
            # Handle the case where the CPG file is in a different directory
            cpg_file = cpg_file.replace("Joern_file", "Joern_files")
        else:
            pass
        if not os.path.exists(cpg_file):
            logger.warning(f"Missing CPG file for {cve_id}: {cpg_file}")
            append_to_failed_cves(cve_id, ROOT_CVE_FOLDER / cve_id, "CPG file missing")
            return

    # patch_with_file = [{"func_name": p["func_name"], "before_func": p["func_before"], "patch": p["patch"], "file_path": p["file_path"]} for p in vul_info[1:]]
    patch_with_file = [{"func_name": p["func_name"], "patch": p["patch"], "file_path": p["file_path"]} for p in vul_info[1:]]
    try:
        port = PORT_QUEUE.get()
        base_url = f"http://localhost:{port}"

        initial_state = AgentState(
            project_dir=project_dir,
            patch=patch_with_file,
            description=description,
            msg=msg,
            joern=0,
            file_cache=file_cache,
            cpg_file=cpg_file,
            base_url=base_url,
            prompt_version=PROMPT_VERSION,
            enriched_data=[],
            analysis={},
            root_cause="",
            confidence_score=0.0,
            iteration=0,
            need_context=True,
            history=[],
            debug_trace=[],
            status=None,
            error=None
        )

        workflow = VulnWorkflow(config)
        result = workflow.graph.invoke(initial_state)
        enriched_data = result.get("enriched_data", [])
        context_count = count_valid_contexts(enriched_data)
        iteration = result.get("iteration", 0)
        confidence_score = result.get("confidence_score", 0.0)

        if result.get("status") == "completed":
            analysis = result.get("analysis")
            need_context = analysis.get("need_context")
            if need_context == False or need_context == "False":
                save_result_to_json(result, ROOT_CVE_FOLDER / cve_id, "Root_cause_analysis.json")
                append_to_success_cves(cve_id, ROOT_CVE_FOLDER / cve_id, context_count, iteration, confidence_score)
            else:
                save_result_to_json(result, ROOT_CVE_FOLDER / cve_id, "error_analysis.json")
                append_to_failed_cves(cve_id, ROOT_CVE_FOLDER / cve_id, "Need context analysis")
        else:
            error_msg = result.get("error")
            if error_msg:
                save_result_to_json(result, ROOT_CVE_FOLDER / cve_id, "error_analysis.json")
                append_to_failed_cves(cve_id, ROOT_CVE_FOLDER / cve_id, error_msg)
            else:
                save_result_to_json(result, ROOT_CVE_FOLDER / cve_id, "error_analysis.json")
                append_to_failed_cves(cve_id, ROOT_CVE_FOLDER / cve_id, "Maximum iterations reached")

    except Exception as e:
        append_to_failed_cves(cve_id, ROOT_CVE_FOLDER / cve_id, str(e))
        logger.error(f"Exception in processing {cve_id}: {str(e)}")
    finally:
        PORT_QUEUE.put(port)


def worker(task_queue: queue.Queue):
    while True:
        try:
            cve_id, config = task_queue.get_nowait()
        except queue.Empty:
            break

        try:
            logger.info(f"Thread-{threading.current_thread().name} processing {cve_id}")
            process_cve(cve_id, config)
        finally:
            task_queue.task_done()


def main():
    config = {
        # "model": "Qwen/Qwen3-32B",
        "model": MODEL_NAME,
        "temperature": TEMPERATURE,
        "api_key": os.getenv("OPENAI_API_KEY"),
        "base_url": os.getenv("OPENAI_API_BASE"),
    }

    if not config["api_key"] or not config["base_url"]:
        logger.error("Missing API configuration")
        return

    processed_cves = load_processed_cves()
    if not processed_cves:
        logger.warning("No CVEs to process")
        return

    task_queue = queue.Queue()
    for cve_id in processed_cves:
        task_queue.put((cve_id, config))
    logger.info(f"Loaded {len(processed_cves)} CVEs to process")
    threads = []
    for _ in range(NUM_CONTAINERS):
        t = threading.Thread(target=worker, args=(task_queue,))
        t.start()
        threads.append(t)
        time.sleep(0.3)

    for t in threads:
        t.join()

    success_count = sum(1 for _ in open(SUCCESS_FILE)) if SUCCESS_FILE.exists() else 0
    fail_count = sum(1 for _ in open(FAILED_FILE)) if FAILED_FILE.exists() else 0

    logger.info(f"Done. Success: {success_count}, Failed: {fail_count}, Total: {len(processed_cves)}")


if __name__ == "__main__":
    main()