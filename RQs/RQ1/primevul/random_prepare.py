import os

def count_json_files(base_dir):
    subdirs = ['test', 'train', 'valid']
    total_count = 0
    
    for subdir in subdirs:
        dir_path = os.path.join(base_dir, subdir)
        if os.path.exists(dir_path):
            count = len([f for f in os.listdir(dir_path) if f.endswith('.json')])
            print(f"{subdir}: {count} JSON files")
            total_count += count
        else:
            print(f"Warning: {subdir} directory not found")
    
    print(f"\nTotal JSON files: {total_count}")

# test: 610 JSON files
# train: 1004 JSON files
# valid: 609 JSON files

import random
import shutil
import time
def select_json_files_safe(base_dir, target_dir, total_select=500, seed=time.time()):
    print(f"seed: {seed}")
    # seed: 1747056000.662555
    random.seed(seed)
    os.makedirs(target_dir, exist_ok=True)
    
    # Count files and build file paths
    file_map = {}
    for subdir in ['test', 'train', 'valid']:
        dir_path = os.path.join(base_dir, subdir)
        if os.path.exists(dir_path):
            files = [f for f in os.listdir(dir_path) if f.endswith('.json')]
            file_map[subdir] = {
                'count': len(files),
                'files': files,
                'path': dir_path
            }
        else:
            print(f"Warning: {subdir} directory not found")
            file_map[subdir] = {'count': 0, 'files': [], 'path': None}
    
    total_files = sum(v['count'] for v in file_map.values())
    if total_files < total_select:
        print(f"Warning: Only {total_files} files available, selecting all")
        total_select = total_files
    
    # Calculate selections maintaining proportions
    selections = {}
    remaining = total_select
    for subdir in file_map:
        if total_files > 0:
            proportion = file_map[subdir]['count'] / total_files
            selections[subdir] = min(file_map[subdir]['count'], 
                                  int(round(proportion * total_select)))
            remaining -= selections[subdir]
    
    # Distribute remaining selections
    for subdir in sorted(file_map, 
                        key=lambda x: file_map[x]['count'], 
                        reverse=True):
        if remaining <= 0:
            break
        available = file_map[subdir]['count'] - selections.get(subdir, 0)
        add = min(available, remaining)
        selections[subdir] = selections.get(subdir, 0) + add
        remaining -= add
    
    # Perform selection and copying with safe filenames
    copied_count = 0
    for subdir, count in selections.items():
        if count <= 0 or not file_map[subdir]['files']:
            continue
            
        selected = random.sample(file_map[subdir]['files'], count)
        
        for filename in selected:
            src = os.path.join(file_map[subdir]['path'], filename)
            # Add subdir prefix to avoid duplicates (e.g. "test_1.json")
            new_name = f"{subdir}_{filename}"
            dst = os.path.join(target_dir, new_name)
            shutil.copy2(src, dst)
            copied_count += 1
        
        print(f"Selected {count} files from {subdir}")
    
    print(f"\nTotal copied files: {copied_count}")

if __name__ == "__main__":
    base_dir = "../primevul/dataset/big_to_each_json"
    target_dir = "../primevul/dataset/random_data"
    select_json_files_safe(base_dir, target_dir)

# Selected 137 files from test
# Selected 226 files from train
# Selected 137 files from valid

# Total copied files: 500

