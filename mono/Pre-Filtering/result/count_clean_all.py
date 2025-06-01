import os
import re
import json
from collections import OrderedDict
input_dir = ""
output_dir = ""
def process_json_files(input_dir, output_dir):
    folder_counts = {}

    for root, dirs, files in os.walk(input_dir):
        relative_path = os.path.relpath(root, input_dir)
        current_output_dir = os.path.join(output_dir, relative_path)

        if not os.path.exists(current_output_dir):
            os.makedirs(current_output_dir)

        for file in files:
            if file.endswith('.json'):
                input_file_path = os.path.join(root, file)
                output_file_path = os.path.join(current_output_dir, file)


                try:
                    with open(input_file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    message = data.get("Bug Filter Response", "").lower()
                    confidence = "error score"
                    if "1.0" in message:
                        confidence = 1.0
                    elif "0." in message:
                        match = re.search(r"0\.\d+", message)
                        if match:
                            confidence = float(match.group())
                        else:
                            confidence = "error score"
                    else:
                        confidence = "error score"

                    data["Bug Filter Confidence"] = confidence

                    description = data.get("description", "").strip() if isinstance(data.get("description", ""), str) else ""
                    if not description:
                        data["description"] = "no more info"

                    ordered_data = OrderedDict()

                    other_keys = [k for k in data if k not in ["Bug Filter", "Bug Filter Confidence", "Bug Filter Response"]]
                    for key in other_keys:
                        ordered_data[key] = data[key]
    
                    ordered_data["Bug Filter"] = data.get("Bug Filter", "")
                    ordered_data["Bug Filter Confidence"] = data["Bug Filter Confidence"]
                    ordered_data["Bug Filter Response"] = data.get("Bug Filter Response", "")


                    with open(output_file_path, 'w', encoding='utf-8') as f:
                        json.dump(ordered_data, f, indent=4, ensure_ascii=False)

                    parent_dir = root
                    while True:
                        folder_counts[parent_dir] = folder_counts.get(parent_dir, 0) + 1
                        new_parent = os.path.dirname(parent_dir)
                        if new_parent == parent_dir:
                            break
                        parent_dir = new_parent

                except Exception as e:
                    print(f"Error processing {input_file_path}: {e}")

    with open(os.path.join(output_dir, "folder_counts.txt"), 'w') as f:
        sorted_folders = sorted(folder_counts.keys(), key=lambda x: len(x.split(os.path.sep)), reverse=True)
        for folder in sorted_folders:
            f.write(f"{folder}: {folder_counts[folder]} files\n")

    print("Processing completed.")

process_json_files(input_dir, output_dir)


# 