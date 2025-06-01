import os
import json
import shutil
import sys
from logging_helper import global_logger

VULNUM = 0
TOTAL = 0

GITHUB_NUM = 0
GITLAB_NUM = 0
GOOGLE_NUM = 0
KERNEL_NUM = 0
VIDEOLAN_NUM = 0
OPENSSL_NUM = 0
FREEDESKTOP_NUM = 0
SAVANNAH_NUM = 0
OTHER_NUM = 0

ALLFILES = 0
FILES09 = 0

def count_platforms(platforms):
    global GITHUB_NUM, GITLAB_NUM, GOOGLE_NUM, OTHER_NUM, KERNEL_NUM, VIDEOLAN_NUM, OPENSSL_NUM, FREEDESKTOP_NUM, SAVANNAH_NUM
    for platform in platforms:
        if platform == 'github':
            GITHUB_NUM += 1
        elif platform == 'gitlab':
            GITLAB_NUM += 1
        elif platform == 'google':
            GOOGLE_NUM += 1
        elif platform == 'kernel':
            KERNEL_NUM += 1
        elif platform == 'videolan':
            VIDEOLAN_NUM += 1
        elif platform == 'openssl':
            OPENSSL_NUM += 1
        elif platform == 'freedesktop':
            FREEDESKTOP_NUM += 1
        elif platform == 'savannah':
            SAVANNAH_NUM += 1
        else:
            OTHER_NUM += 1
        
def classify_and_copy_cve_dirs(input_roots, output_root):
    global VULNUM, TOTAL, FILES09, ALLFILES
    platforms = ['github', 'gitlab', 'google', 'kernel', 'videolan', 'openssl', 'freedesktop', 'savannah', 'other']
    for platform in platforms:
        os.makedirs(os.path.join(output_root, platform), exist_ok=True)
    
    for input_root in input_roots:
        global_logger.info(f"Processing {input_root}")
        for cve_dir in os.listdir(input_root):
            TOTAL = TOTAL + 1
            cve_path = os.path.join(input_root, cve_dir)
            if not os.path.isdir(cve_path):
                continue
            should_process = False
            target_platform = None
            
            for json_file in os.listdir(cve_path):
                if not json_file.endswith('.json'):
                    continue
                print(f"Processing {json_file}")
                json_path = os.path.join(cve_path, json_file)
                try:
                    with open(json_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                except Exception as e:
                    print(f"Error loading {json_path}: {e}")
                    continue
                
      
                sec_vul_num = data.get('stats', {}).get('sec_vul', {}).get('num', 0)
                # if sec_vul_num == 0:
                #     continue
              
                no_more_info = data['stats']['sec_vul'].get('no_more_info', [])
                main_dir = data['stats']['sec_vul'].get('main_dir', [])
                all_files = no_more_info + main_dir
                
                for file_name in all_files:
                    key = os.path.splitext(file_name)[0]
                    entry = data.get('raw_data', {}).get(key)
                    ALLFILES += 1
                    if not entry or entry.get('Bug Filter Confidence') == 'error score':
                        continue
                    
                    if entry.get('Bug Filter') == 'Security Vulnerability Fix' and entry.get('Bug Filter Confidence', 0) >= 0.9:
                        FILES09 += 1
                        git_url = entry.get('git_url', '')
                        git_url_lower = git_url.lower()
                        if 'github.com' in git_url_lower:
                            target_platform = 'github'
                        elif 'gitlab.com' in git_url_lower:
                            target_platform = 'gitlab'
                        elif 'googlesource' in git_url_lower:
                            target_platform = 'google'
                        elif 'kernel.org' in git_url_lower:
                            target_platform = 'kernel'
                        elif 'videolan' in git_url_lower:
                            target_platform = 'videolan'
                        elif 'openssl' in git_url_lower:
                            target_platform = 'openssl'
                        elif 'freedesktop' in git_url_lower:
                            target_platform = 'freedesktop'
                        elif 'savannah' in git_url_lower:
                            target_platform = 'savannah'
                        else:
                            target_platform = 'other' # more git
                        # should_process = True
                        # break
                # if should_process:
                #     break 
    
            # if should_process and target_platform:
            #     dest_dir = os.path.join(output_root, target_platform, cve_dir)
            #     count_platforms([target_platform])
                # if os.path.exists(dest_dir):
                #     try:
                #         shutil.rmtree(dest_dir)
                #     except Exception as e:
                #         print(f"Error removing {dest_dir}: {e}")
                #         continue
                try:
                    # shutil.copytree(cve_path, dest_dir)
                    VULNUM += 1
                    global_logger.info(f"[+] {cve_dir} ==> {target_platform}")
                except Exception as e:
                    global_logger.error(f"[-] Error copying {cve_path} to {dest_dir}: {e}")



input_roots = [
    '/result/merge_result_all/c_cpp',
    # '/result/merge_result_all/java'
]
output_root = './output'

classify_and_copy_cve_dirs(input_roots, output_root)
global_logger.info(f"GITHUB_NUM: {GITHUB_NUM} GITLAB_NUM: {GITLAB_NUM} GOOGLE_NUM: {GOOGLE_NUM} KERNEL_NUM: {KERNEL_NUM} VIDEOLAN_NUM: {VIDEOLAN_NUM} ")
global_logger.info(f"OPENSSL_NUM: {OPENSSL_NUM} FREEDESKTOP_NUM: {FREEDESKTOP_NUM} SAVANNAH_NUM:{SAVANNAH_NUM} OTHER_NUM: {OTHER_NUM}")
global_logger.info(f"Total Vulnerability Score >= 0.9: {VULNUM}")
global_logger.info(f"VULNUM:{VULNUM} TOTAL: {TOTAL}")
global_logger.info(f"VULNUM/TOTAL = {VULNUM/TOTAL}")
global_logger.info(f"ALLFILES: {ALLFILES} FILES09: {FILES09}")
global_logger.info(f"FILES09/ALLFILES = {FILES09/ALLFILES}")


# 03/03/2025 11:07:16 PM - sort_score_0_9.py:205 - [INFO]: GITHUB_NUM: 4759 GITLAB_NUM: 70 GOOGLE_NUM: 321 KERNEL_NUM: 623 VIDEOLAN_NUM: 154 
# 03/03/2025 11:07:16 PM - sort_score_0_9.py:206 - [INFO]: OPENSSL_NUM: 104 FREEDESKTOP_NUM: 109 SAVANNAH_NUM:53 OTHER_NUM: 83
# 03/03/2025 11:07:16 PM - sort_score_0_9.py:207 - [INFO]: Total Vulnerability Score >= 0.9: 6276
# 03/03/2025 11:07:16 PM - sort_score_0_9.py:208 - [INFO]: VULNUM/TOTAL = 0.6783398184176395



