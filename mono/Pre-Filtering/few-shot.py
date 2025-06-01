import random
import time
import tiktoken
import yaml
import json
import re
import os
import requests
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
import multiprocessing
from pathlib import Path

import sys
from logging_helper import global_logger

#### LLM
# OPENAI_BASE_URL = os.environ.get('API_BASE')
# OPENAI_KEY = os.environ.get('API_KEY')
# MODEL_NAME = os.environ.get('API_MODEL')
OPENAI_BASE_URL = None
OPENAI_KEY = None
MODEL_NAME = None
TOKEN_COUNT = 0
if OPENAI_BASE_URL is None:
    OPENAI_BASE_URL = "http://127.0.0.1:8080/v1/chat/completions"

if OPENAI_KEY is None:
    OPENAI_KEY = ''
    
if MODEL_NAME is None:
    MODEL_NAME = "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"

  
# input_path = '../data/test.json'

output_folder = ''
few_shot_path = '../prompt/bug-few-shot/few-shot.yaml'
cot_yaml_path = '../prompt/main.yaml'

# input_dir = '../data'

##### count
TYPE1NUM = 0
TYPE2NUM = 0
TYPE3NUM = 0
SECNUM = 0

global_logger.info(f"Few-shot Running! +++++++{MODEL_NAME} on {input_dir}")

def load_json_file(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)
    
def load_yaml_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def load_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()
    
# def input_generator(file_path):
#     content = load_json_file(file_path)
#     sections = ['Commit Message', 'Code Diff', 'Vulnerability Description']
#     input = {section: content.get(section, '') for section in sections}
#     return input

def input_generator(file_path):
    content = load_json_file(file_path)
    
    field_mapping = {
        'Commit Message': 'commit_msg',
        # 'Vulnerability Description': 'description',
        ####ClenVul####
        'Vulnerability Description': 'pr_info',
        ####ClenVul####
        'Code Diff': 'diff_func'
    }
    func_name = content.get('func_name', '')
    diff_func = content.get('diff_func', '')
    diff_func = f"func_name@@{func_name}@@{diff_func}"
    content['diff_func'] = diff_func
    if content.get('pr_info') == None:
        content['pr_info'] = "no more info"
    input = {target_field: content.get(origin_field, '') for target_field, origin_field in field_mapping.items()}
    # print(input)
    # input()
    return input

def load_few_shot_examples(file_path):
    data = load_yaml_file(file_path)
    # order = ['example1', 'example2', 'example3', 'example4', 'example5']
    order = ['example1', 'example2', 'example3', 'example4']
    parts = []
    for key in order:
        if key in data:
            parts.append(f"{data[key]}\n")
    return "\n".join(parts)

def concatenate_prompt(yaml_data, few_shot_text, input):
    sections = ['role', 'inst', 'cot', 'format_ask', "step_ask"]
    parts = []
    for section in sections:
        if section == 'step_ask':
            step_ask = yaml_data[section]
            break
        if section in yaml_data:
            parts.append(f"[{section.upper()}]\n{yaml_data[section]}\n")
    parts.append("[FEWSHOTEXAMPLE]\n" + str(few_shot_text) + "\n")
    parts.append("[INPUT]\n" + str(input))
    parts.append(step_ask)
    return "\n".join(parts)

def prompt_token_len(prompt):
    encoding = tiktoken.encoding_for_model("gpt-4")
    token_len = len(encoding.encode(prompt))
    print(f"prompt OpenAI tokens: {token_len}")


def FewShotChatOpenAI(content,model=MODEL_NAME):
    global TOKEN_COUNT
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": content}],
    }
    response_ = requests.post(OPENAI_BASE_URL, json=payload)
    if response_.status_code == 200:
        response_json = response_.json()
        response = response_json['choices'][0]['message']['content']
        total_token = int(response_json['usage']['total_tokens'])
        TOKEN_COUNT += total_token
        # print("response:",  response)
        return response
    else:
        # print(f"Please retry: {response_.status_code}")
        if response_.status_code == 503:
            global_logger.error(f"Model Wait: {response_.status_code}")
            time.sleep(5)
        return None
    

def process_json_file(message, input_file, output_folder, non_sec_vul_folder=f'{output_folder}/non_sec_vul', sec_vul_folder=f'{output_folder}/sec_vul'):
    global TYPE1NUM, TYPE2NUM, TYPE3NUM, SECNUM
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    if not os.path.exists(non_sec_vul_folder):
        os.makedirs(non_sec_vul_folder)
    if not os.path.exists(sec_vul_folder):
        os.makedirs(sec_vul_folder)

    non_sec_type_1_path = os.path.join(non_sec_vul_folder, 'type_1')
    non_sec_type_2_path = os.path.join(non_sec_vul_folder, 'type_2')
    non_sec_type_3_path = os.path.join(non_sec_vul_folder, 'type_3')

    if not os.path.exists(non_sec_type_1_path):
        os.makedirs(non_sec_type_1_path)
    if not os.path.exists(non_sec_type_2_path):
        os.makedirs(non_sec_type_2_path)
    if not os.path.exists(non_sec_type_3_path):
        os.makedirs(non_sec_type_3_path)
    
    try:
        data = load_json_file(input_file)
        
        if "Classification:" in message: 
            # classification = message.split("Final Classification:")[1].split("\n")[0].strip()
            # if not classification:
            #     classification = message.split("Final Classification:")[1].split("\n")[1].strip()
            start_index = message.find("Classification:") + len("Classification:")
            classification = message[start_index:].strip()  
            if "Security Vulnerability Fix" not in classification:
                if "Testing & Validation Updates" in classification:
                    classification = "Testing & Validation Updates"
                    output_subfolder = non_sec_type_1_path
                    TYPE1NUM += 1
                elif "Defect Remediation & Feature Upgrades" in classification:
                    classification = "Defect Remediation & Feature Upgrades"
                    output_subfolder = non_sec_type_2_path
                    TYPE2NUM += 1
                elif "Supporting & Non-Core Improvements" in classification:
                    classification = "Supporting & Non-Core Improvements"
                    output_subfolder = non_sec_type_3_path
                    TYPE3NUM += 1
                else:
                    output_subfolder = non_sec_vul_folder
            else:    
                classification = "Security Vulnerability Fix"
                output_subfolder = sec_vul_folder
                SECNUM += 1
            # confidence = message.split("Confidence:")[1].split("\n")[0].strip()
                # if '** ' in confidence:
                #     confidence = confidence.split('** ')[1].split(' **')[0]
            if "1.0" in message:
                confidence = 1.0
            elif "0." in message: 
                if re.search(r"0\.\d+", message) == None:
                    confidence = "error score"
                else:
                    confidence = float(re.search(r"0\.\d+", message).group())
            else:
                confidence = "error score"

            new_data = {
                "Bug Filter": classification,
                "Bug Filter Confidence": confidence,
                "Bug Filter Response": message
            }
            print(f"Classification: {classification}")
            merged_data = {**data, **new_data} 


            base_name = os.path.splitext(os.path.basename(input_file))[0]
            output_filename = f"{base_name}_part1.json"

            # for no more info des
            if data.get("description") == "no more info":
                output_subfolder = os.path.join(output_subfolder, "no_more_info")
                if not os.path.exists(output_subfolder):
                    os.makedirs(output_subfolder)

            output_file = os.path.join(output_subfolder, output_filename)
            
            ### PrimeVul
            if os.path.exists(output_file):
                output_file = os.path.join(output_subfolder, f"{base_name}_part1_{random.randint(0, 1000)}.json")
            ### PrimeVul
           
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(merged_data, f, ensure_ascii=False, indent=2)

            global_logger.info(f"[+] File saved: {output_file}")
            global_logger.info(f"Classification: {classification}")
            global_logger.info(f"Confidence: {confidence}")
            global_logger.info(f"-----------------------------")
            
        
        else:
            new_data = {
                "Bug Filter": 'classification error',
                "Bug Filter Confidence": 'sonething wrong',
                "Bug Filter Response": message
            }
            merged_data = {**data, **new_data} 
            error_file = os.path.join(output_folder, f"{base_name}_error.json")
            with open(error_file, 'w', encoding='utf-8') as f:
                json.dump(merged_data, f, ensure_ascii=False, indent=2)
            # print(message)
            global_logger.error(f"[-] File saved: {output_file}")
            global_logger.error(f"Response address Error : {input_file}")

    except Exception as e:
        print(f"Error: {e}")



def run(input_path):
    main_prompt = load_yaml_file(cot_yaml_path)
    few_shot_text = load_few_shot_examples(few_shot_path)
    input = input_generator(input_path)
    final_prompt = concatenate_prompt(main_prompt, few_shot_text, input)
    # print(final_prompt)
    # input()
    prompt_token_len(final_prompt)
    answer = FewShotChatOpenAI(final_prompt)
    # print(answer)
    # input()
    if answer:
        process_json_file(answer, input_path, output_folder)
    else: 
        global_logger.error(f"run Error: {input_path}")

MegaVul  --myfile
def process_cve_files_in_directory(input_dir):
    cve_files = []
    for filename in os.listdir(input_dir):
        if filename.startswith("CVE-") and os.path.isfile(os.path.join(input_dir, filename)):
            if "_patched" not in filename:
                cve_files.append(os.path.join(input_dir, filename))

    return cve_files

# # ClenVul
# def process_cve_files_in_directory(input_dir):
#     global romdom_number
#     num_files = []
#     # romdom_number = []
#     # for i in range(500):
#     #     romdom_number.append(random.randint(0, 8000))
#     global_logger.info(f"romdom_number: {romdom_number}")
#     i = 0
#     for filename in os.listdir(input_dir):
#         i += 1
#         if filename.endswith(".json") and i in romdom_number and os.path.isfile(os.path.join(input_dir, filename)):
#             if "error" not in filename:
#                 num_files.append(os.path.join(input_dir, filename))
#     return num_files

# PrimeVul 
# def process_cve_files_in_directory(input_dir, samples_per_folder=150):
#     seed = random.randint(0, 999999)
#     random.seed(23582)
#     global_logger.info(f"Random seed for reproducibility: {23582}")
    
#     selected_files = []
#     seen_ids = set() 
    
#     for folder in ["test", "train", "valid"]:
#         folder_path = Path(input_dir) / folder
        
#         if not folder_path.exists():
#             raise FileNotFoundError(f"Directory {folder_path} not found")
            
#         all_files = list(folder_path.glob("*.json"))
#         random.shuffle(all_files) 
    
#         selected_count = 0
#         folder_selected = []
        
#         for file_path in all_files:
#             if selected_count >= samples_per_folder:
#                 break
                
#             try:

#                 with open(file_path, "r", encoding='utf-8') as f:
#                     data = json.load(f)
                    
#                 file_id = data.get("idx")
#                 if not file_id:
#                     print(f"Skipping {file_path}: missing 'idx' field")
#                     continue
                    
    
#                 if file_id in seen_ids:
#                     print(f"Skipping duplicate ID: {file_id} in {file_path}")
#                     continue
                
#                 seen_ids.add(file_id)
#                 folder_selected.append(str(file_path))
#                 selected_count += 1
                
#             except json.JSONDecodeError:
#                 print(f"Skipping invalid JSON: {file_path}")
#             except UnicodeDecodeError:
#                 print(f"Skipping non-UTF8 file: {file_path}")

#         if selected_count < samples_per_folder:
#             print(f"Warning: Only found {selected_count} valid files in {folder}")
            
#         selected_files.extend(folder_selected)
        
#     return selected_files


def main():
    file_paths = process_cve_files_in_directory(input_dir)
    i = 0
    for file_path in file_paths:
        global_logger.info(f"Processing {i} entries:{file_path}")
        i += 1
        # megalvul patch
        # base_name = os.path.splitext(os.path.basename(file_path))[0]
        # if "_" not in base_name:
        #     global_logger.info(f"Skip {file_path}")
        #     continue
        run(file_path)
        if i % 100 == 0:
            global_logger.info(f"Running! +++++++{MODEL_NAME} Processed {i} entries, Token Count: {TOKEN_COUNT}")
            global_logger.info(f"TYPE1NUM: {TYPE1NUM}, TYPE2NUM: {TYPE2NUM}, TYPE3NUM: {TYPE3NUM}, SECNUM: {SECNUM}")
    global_logger.info(f"Done! [+]{MODEL_NAME} Processed {i} entries, Token Count: {TOKEN_COUNT}")
    global_logger.info(f"TYPE1NUM: {TYPE1NUM}, TYPE2NUM: {TYPE2NUM}, TYPE3NUM: {TYPE3NUM}, SECNUM: {SECNUM}")
    

if __name__ == "__main__":
    main()





