import os
import random
import shutil
import json
import time

# choose dir by hand
# vul = cpp ：260 java ：90       
# non_vul = cpp ：75  java ：75
# all = 500
source_folder = "result/zero_dpR1_c_cpp_all/non_sec_vul/"
target_folder = "./random_data/non_vul_1"

os.makedirs(target_folder, exist_ok=True)

json_files = []
for root, dirs, files in os.walk(source_folder):
    for file in files:
        if file.endswith(".json"):
            json_files.append(os.path.join(root, file))

random.seed(2025*2025)
selected_files = random.sample(json_files, min(1000, len(json_files)))


count = 0
for file_path in selected_files:
    with open(file_path, "r") as f:
        data = json.load(f)

    if float(data["Bug Filter Confidence"]) < 0.90:
        continue
    # mark
    if "Bug Filter" in data:
        del data["Bug Filter"]
    if "Bug Filter Confidence" in data:
        del data["Bug Filter Confidence"]
    if "Bug Filter Response" in data:
        del data["Bug Filter Response"]
    
    target_path = os.path.join(target_folder, os.path.basename(file_path))
    print(f"copying {file_path} to {target_path}")
    with open(target_path, "w") as f:
        json.dump(data, f, indent=4)
    
    count += 1

    if count == 75:
        break


print(f"done {count}")
