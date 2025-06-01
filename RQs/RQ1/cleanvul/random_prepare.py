import os
import random
import shutil
import json


def copy_random_json_files(source_dir, target_dir, num_files=500):
    random.seed(42)
    os.makedirs(target_dir, exist_ok=True)
    
    json_files = [f for f in os.listdir(source_dir) if f.endswith('.json') and "error" not in f]
    selected_files = random.sample(json_files, min(num_files, len(json_files)))
    
    for file_name in selected_files:
        shutil.copy2(os.path.join(source_dir, file_name), 
                    os.path.join(target_dir, file_name))

if __name__ == "__main__":
    source = "../cleanvul/dataset/csv_to_each_json"
    target = "../cleanvul/dataset/random_data_1"
    copy_random_json_files(source, target)
