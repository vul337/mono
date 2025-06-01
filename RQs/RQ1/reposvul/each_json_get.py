import os
import json

def extract_and_save_individual_jsonl_entries(input_filepath, output_directory, num_entries=6500):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    extracted_count = 0

    try:
        with open(input_filepath, 'r', encoding='utf-8') as infile:
            for line_num, line in enumerate(infile, 1):
                if extracted_count >= num_entries:
                    break

                try:
                    json_obj = json.loads(line.strip())
                
                    output_filename = f"{line_num}.json"
                    output_filepath = os.path.join(output_directory, output_filename)
                    with open(output_filepath, 'w', encoding='utf-8') as outfile:
                        json.dump(json_obj, outfile, indent=4, ensure_ascii=False)
                    
                    extracted_count += 1
                    if extracted_count % 100 == 0:
                        print(f"have done {extracted_count} ...")

                except json.JSONDecodeError as e:
                    continue

    except FileNotFoundError:
        print(f"file '{input_filepath}' not found.")
    except Exception as e:
        print(f"error：{e}")


if __name__ == "__main__":
    big_jsonl_file = "./ReposVul.jsonl" 
    output_folder = "../reposvul/dataset"

    extract_and_save_individual_jsonl_entries(big_jsonl_file, output_folder, 7000)

    # 568 / 6321 vul