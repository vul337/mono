import os
import json
import shutil

def process_cve_json_files():
    base_path = "../result"
    target_samples_path = "../RQ4/GroundTruth/samples"

    os.makedirs(target_samples_path, exist_ok=True)

    tech_stacks = ["zero_dpR1_java_all", "zero_dpR1_c_cpp_all"]
    vul_types = ["non_sec_vul", "sec_vul"]
    non_sec_subtypes = ["type_1", "type_2", "type_3"]

    processed_files_count = 0

    for tech_stack in tech_stacks:
        for vul_type in vul_types:
            if vul_type == "non_sec_vul":
                for subtype in non_sec_subtypes:
                    current_dir = os.path.join(base_path, tech_stack, vul_type, subtype)
                    print(f"Scanning directory: {current_dir}")
                    if os.path.exists(current_dir) and os.path.isdir(current_dir):
                        for filename in os.listdir(current_dir):
                            if filename.endswith(".json") and filename.startswith("CVE-"):
                                file_path = os.path.join(current_dir, filename)
                                try:
                                    with open(file_path, 'r', encoding='utf-8') as f:
                                        data = json.load(f)
                                        description = data.get("description", "").strip()

                                        # Check conditions
                                        if description.lower() != "no more info" and len(description.split()) > 10:
                                            destination_path = os.path.join(target_samples_path, filename)
                                            shutil.copy2(file_path, destination_path)
                                            processed_files_count += 1
                                            print(f"Copied: {filename} to {target_samples_path}")
                                except json.JSONDecodeError:
                                    print(f"Error decoding JSON in file: {file_path}")
                                except Exception as e:
                                    print(f"An unexpected error occurred with file {file_path}: {e}")
                    else:
                        print(f"Directory not found or is not a directory: {current_dir}")
            else: # sec_vul
                current_dir = os.path.join(base_path, tech_stack, vul_type)
                print(f"Scanning directory: {current_dir}")
                if os.path.exists(current_dir) and os.path.isdir(current_dir):
                    for filename in os.listdir(current_dir):
                        if filename.endswith(".json") and filename.startswith("CVE-"):
                            file_path = os.path.join(current_dir, filename)
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    description = data.get("description", "").strip()

                                    # Check conditions
                                    if description.lower() != "no more info" and len(description.split()) > 10:
                                        destination_path = os.path.join(target_samples_path, filename)
                                        shutil.copy2(file_path, destination_path)
                                        processed_files_count += 1
                                        print(f"Copied: {filename} to {target_samples_path}")
                            except json.JSONDecodeError:
                                print(f"Error decoding JSON in file: {file_path}")
                            except Exception as e:
                                print(f"An unexpected error occurred with file {file_path}: {e}")
                else:
                    print(f"Directory not found or is not a directory: {current_dir}")

    print(f"\nProcessing complete. Total files copied: {processed_files_count}")

# Run the function
if __name__ == "__main__":
    process_cve_json_files()
    # Processing complete. Total files copied: 2326