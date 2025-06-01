import json
import os
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

import requests
import tiktoken
import yaml
import sys
from logging_helper import global_logger
from threading import Lock                       


OPENAI_BASE_URL = "http://127.0.0.1:8081/v1/chat/completions"
OPENAI_KEY = ""                              
MODEL_NAME = "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"

# MyVul


# CleanVul


# # PrimeVul


ZERO_SHOT_PATH = "../prompt/bug-zero-shot/zero-shot.yaml"
COT_YAML_PATH = "../prompt/main.yaml"

DATASET_TYPE = "CleanVul"  # "MegaVul", "CleanVul", "PrimeVul" "BROKEN"
MAX_WORKERS = 8

# Shared state (protected by a single global lock)
lock = Lock()                               
COUNTERS: Dict[str, int] = {
    "TYPE1NUM": 0,
    "TYPE2NUM": 0,
    "TYPE3NUM": 0,
    "SECNUM": 0,
    "TOKEN_COUNT": 0,
    "PROCESSED": 0,
}

def load_json_file(file_path: str) -> Dict:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_yaml_file(file_path: str) -> Dict:
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def generate_input_from_file(file_path: str) -> Dict[str, str]:
    content = load_json_file(file_path)

    # Re‑encode diff with func name prefix
    func_name = content.get("func_name", "")
    diff_func = f"func_name@@{func_name}@@" + content.get("diff_func", "")
    content["diff_func"] = diff_func

    field_mapping = {
        "Commit Message": "commit_msg",
        "Code Diff": "diff_func",
        # "More Ground Truth": "ground_truth",
    }
    return {tgt: content.get(src, "") for tgt, src in field_mapping.items()}


def concatenate_prompt(yaml_data: Dict, zero_shot_text: str, input_data: Dict) -> str:
    sections = ["role", "inst", "cot", "format_ask", "step_ask"]
    parts = []

    for sec in sections:
        if sec == "step_ask":
            step_ask = yaml_data[sec]
            break
        if sec in yaml_data:
            parts.append(f"[{sec.upper()}]\n{yaml_data[sec]}")

    # parts.append("[ZEROSHOTINST]\n" + str(zero_shot_text) + "\n")
    parts.append("[INPUT]\n" + str(input_data))
    parts.append(step_ask)
    return "\n\n".join(parts)


def calculate_prompt_token_length(prompt: str) -> int:
    enc = tiktoken.encoding_for_model("gpt-4")
    return len(enc.encode(prompt))


def query_llm(content: str, model: str = MODEL_NAME) -> Optional[str]:
    payload = {
        "model": model,
        "temperature": 0.6,
        "top_p": 0.95,
        "messages": [
            {
            "role": "user",
            "content": content
            },
            {
            "role": "system",
            "content": "You are a patch classification expert. Your task is to analyze code changes to identify and categorize defect fixes in software, with a primary focus on detecting security vulnerability fixes. You will classify patches into one of four specific categories: 'Security Vulnerability Fix', 'Testing & Validation Updates', 'Supporting & Non-Core Improvements', or 'Defect Remediation & Feature Upgrades'. Your analysis must prioritize code-level evidence over commit messages and other external information when discrepancies arise. For security vulnerabilities, specifically determine if the patch aims to fix a defect that has already caused harm to system security. Provide your analysis following a step-by-step thinking process, ending with a final classification and a confidence score."

            }
        ]
        }

    try:
        rsp = requests.post(OPENAI_BASE_URL, json=payload, timeout=60)
        if rsp.status_code == 200:
            rsp_js = rsp.json()
            time.sleep(0.5)  # rate limit
            with lock:
                COUNTERS["TOKEN_COUNT"] += int(rsp_js["usage"]["total_tokens"])
            return rsp_js["choices"][0]["message"]["content"]

        # Simple retry on overloaded server
        if rsp.status_code == 503:
            time.sleep(5)
            return None

        global_logger.error(f"LLM request failed: {rsp.status_code}")
        return None

    except Exception as e:
        global_logger.error("Error querying LLM", exc_info=True)
        return None


# ──────────────────────────────────────────────────────────────────────────────
def process_classification_result(message: str, input_file: str, output_folder: str) -> None:
    base = os.path.splitext(os.path.basename(input_file))[0]
    output_filename = f"{base}.json"

    try:
        data = load_json_file(input_file)

        if "Classification:" not in message:
            # Write error file
            err_file = os.path.join(output_folder, f"{base}_error.json")
            with open(err_file, "w", encoding="utf-8") as f:
                json.dump(
                    {**data, "Bug Filter": "classification error",
                     "Bug Filter Confidence": "N/A",
                     "Bug Filter Response": message},
                    f, ensure_ascii=False, indent=2,
                )
            global_logger.error(f"[-] {err_file} | classification string missing")
            return

        # ── Parse classification and confidence score ──────────────────────────
        classification = message.split("Classification:", 1)[-1].strip()

        if "Security Vulnerability Fix" in classification:
            bucket = "sec_vul"
            with lock:
                COUNTERS["SECNUM"] += 1
        elif "Testing & Validation Updates" in classification:
            bucket = "non_sec_vul/type_1"
            classification = "Testing & Validation Updates"
            with lock:
                COUNTERS["TYPE1NUM"] += 1
        elif "Defect Remediation & Feature Upgrades" in classification:
            bucket = "non_sec_vul/type_2"
            classification = "Defect Remediation & Feature Upgrades"
            with lock:
                COUNTERS["TYPE2NUM"] += 1
        elif "Supporting & Non-Core Improvements" in classification:
            bucket = "non_sec_vul/type_3"
            classification = "Supporting & Non-Core Improvements"
            with lock:
                COUNTERS["TYPE3NUM"] += 1
        else:
            bucket = "non_sec_vul"  # fallback

        # confidence
        score_match = re.search(r"\b(1\.0|0\.\d+)\b", message)
        confidence = float(score_match.group()) if score_match else "error score"

        # ensure dir
        out_dir = os.path.join(output_folder, bucket)
        os.makedirs(out_dir, exist_ok=True)

        out_file = os.path.join(out_dir, output_filename)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(
                {**data,
                 "Bug Filter": classification,
                 "Bug Filter Confidence": confidence,
                 "Bug Filter Response": message},
                f, ensure_ascii=False, indent=2,
            )
        global_logger.info(f"[+] {out_file} | {classification} | Conf: {confidence}")

    except Exception:
        global_logger.error(f"Error processing result for {input_file}", exc_info=True)


# ──────────────────────────────────────────────────────────────────────────────
def process_single_file(file_path: str) -> None:
    try:
        # MegaVul filtering: skip files w/o underscore
        if DATASET_TYPE == "MegaVul" and "_" not in Path(file_path).stem:
            global_logger.info(f"Skipping {file_path}")
            return

        main_prompt = load_yaml_file(COT_YAML_PATH)
        zero_shot_text = load_yaml_file(ZERO_SHOT_PATH)
        input_data = generate_input_from_file(file_path)
        final_prompt = concatenate_prompt(main_prompt, zero_shot_text, input_data)

        # debug: token length
        tok_len = calculate_prompt_token_length(final_prompt)
        global_logger.debug(f"{file_path} | prompt tokens: {tok_len}")

        # LLM call
        answer = query_llm(final_prompt)
        if answer:
            process_classification_result(answer, file_path, OUTPUT_FOLDER)

        # increment processed counter
        with lock:
            COUNTERS["PROCESSED"] += 1
            processed = COUNTERS["PROCESSED"]

        if processed % 10 == 0:
            global_logger.info(
                f"Progress {processed} files | "
                f"T1={COUNTERS['TYPE1NUM']} "
                f"T2={COUNTERS['TYPE2NUM']} "
                f"T3={COUNTERS['TYPE3NUM']} "
                f"Sec={COUNTERS['SECNUM']} | "
                f"Tokens={COUNTERS['TOKEN_COUNT']}"
            )

    except Exception:
        global_logger.error(f"Unhandled exception processing {file_path}", exc_info=True)


# ──────────────────────────────────────────────────────────────────────────────
def get_files_to_process(input_dir: str) -> List[str]:
    if DATASET_TYPE == "MegaVul":
        return [
            str(Path(input_dir) / f)
            for f in os.listdir(input_dir)
            if f.startswith("CVE-") and "_patched" not in f
        ]
    if DATASET_TYPE == "BROKEN":
        return [
            str(Path(input_dir) / f)
            for f in os.listdir(input_dir)
            if f.endswith(".json") and f in broken_files
        ]
    if DATASET_TYPE == "CleanVul":
        return [
            str(Path(input_dir) / f)
            for f in os.listdir(input_dir)
            if f.endswith(".json") and "error" not in f
        ]

    if DATASET_TYPE == "PrimeVul":
        return [
            str(Path(input_dir) / f)
            for f in os.listdir(input_dir)
            if f.endswith(".json")
        ]

    raise ValueError(f"Unknown DATASET_TYPE {DATASET_TYPE}")


def main() -> None:
    global_logger.info(f"Starting classification with {MODEL_NAME} on {INPUT_DIR}")

    # output dirs
    for p in (
        OUTPUT_FOLDER,
        Path(OUTPUT_FOLDER) / "non_sec_vul/type_1",
        Path(OUTPUT_FOLDER) / "non_sec_vul/type_2",
        Path(OUTPUT_FOLDER) / "non_sec_vul/type_3",
        Path(OUTPUT_FOLDER) / "sec_vul",
    ):
        os.makedirs(p, exist_ok=True)

    file_paths = get_files_to_process(INPUT_DIR)
    total_files = len(file_paths)
    global_logger.info(f"Found {total_files} files to process")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_file, fp): fp for fp in file_paths}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception:
                global_logger.error(f"Worker failed for {futures[fut]}", exc_info=True)

    global_logger.info(
        f"Finished {COUNTERS['PROCESSED']}/{total_files} files | "
        f"T1={COUNTERS['TYPE1NUM']} T2={COUNTERS['TYPE2NUM']} "
        f"T3={COUNTERS['TYPE3NUM']} Sec={COUNTERS['SECNUM']} | "
        f"Total tokens {COUNTERS['TOKEN_COUNT']}"
    )


if __name__ == "__main__":
    main()