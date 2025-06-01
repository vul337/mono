import ijson
import json
import os
from decimal import Decimal

def read_large_json_stream(file_path):
    with open(file_path, 'r') as f:
        for item in ijson.items(f, 'item'):
            yield item

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)  
        return super().default(obj)

def get_file_name(output_dir, cve_id):
    file_path = os.path.join(output_dir, f"{cve_id}.json")
    for i in range(50):
        file_path = os.path.join(output_dir, f"{cve_id}_{i}.json")
        if not os.path.exists(file_path):
            return file_path
        else:
            file_path = os.path.join(output_dir, f"{cve_id}_broken.json")
    return file_path


def save_to_json_file(data, output_dir, cve_id, formatted=True):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if data.get("is_vul") == True:
        output_dir = os.path.join(output_dir, "vul")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    else:
        output_dir = os.path.join(output_dir, "non_vul")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    file_path = os.path.join(output_dir, f"{cve_id}.json")
    if os.path.exists(file_path):
        file_path = get_file_name(output_dir, cve_id)
    with open(file_path, 'w') as f:
        if formatted:
            json.dump(data, f, cls=DecimalEncoder, indent=4)
        else:
            json.dump(data, f, cls=DecimalEncoder)

def save_each_json_to_dir(input_file, output_dir):
    i = 0
    for entry in read_large_json_stream(input_file):
        cve_id = entry.get("cve_id")
        if cve_id:
            save_to_json_file(entry, output_dir, cve_id, formatted=True)
        i += 1
        if i % 100 == 0:
            print(f"Processed {i} entries")

def main():
    base = ""
    # c_cpp
    input_file = base + "/2024-04/c_cpp/megavul.json"
    output_dir = base + "/mysort_1/c_cpp/megavul"
    save_each_json_to_dir(input_file, output_dir)

    simple_input_file = base + "/2024-04/c_cpp/megavul_simple.json"
    simple_output_dir = base + "/mysort_1/c_cpp/megavul_simple"
    save_each_json_to_dir(simple_input_file, simple_output_dir)

    cve_with_graph_input_file = base + "/2024-04/c_cpp/cve_with_graph_abstract_commit.json"
    cve_with_graph_output_dir = base + "/mysort_1/c_cpp/cve_with_graph_abstract_commit"
    save_each_json_to_dir(cve_with_graph_input_file, cve_with_graph_output_dir)

    # java
    input_file = base + "/2024-04/java/megavul.json"
    output_dir = base + "/mysort_1/java/megavul"
    save_each_json_to_dir(input_file, output_dir)

    simple_input_file = base + "/2024-04/java/megavul_simple.json"
    simple_output_dir = base + "/mysort_1/java/megavul_simple"
    save_each_json_to_dir(simple_input_file, simple_output_dir)

    cve_with_graph_input_file = base + "/2024-04/java/cve_with_graph_abstract_commit.json"
    cve_with_graph_output_dir = base + "/mysort_1/java/cve_with_graph_abstract_commit"
    save_each_json_to_dir(cve_with_graph_input_file, cve_with_graph_output_dir)


if __name__ == '__main__':
    main()