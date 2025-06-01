import time
import tiktoken
import yaml
import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage


## path  
zero_shot_path = '../prompt/bug-zero-shot/zero-shot.yaml'
few_shot_path = '../prompt/bug-few-shot/few-shot.yaml'
cot_yaml_path = '../prompt/main.yaml'
num = [1623, 6930, 3269, 349, 1267, 5601, 430, 4929, 4319, 7449, 4246, 3746, 7322, 2505, 5363, 4491, 2065, 1096, 3574, 6730, 1875, 4656, 1880, 7347, 2350, 1431, 4527, 4270, 7916, 5166, 6585, 6537, 1651, 2652, 2688, 4435, 2894, 7092, 3886, 7947, 5411, 7336, 7283, 4687, 5579, 6192, 7429, 5128, 7984, 917, 5019, 5036, 6599, 7904, 3898, 1234, 3114, 446, 2009, 5043, 4352, 6505, 2108, 3283, 7148, 5016, 4019, 3481, 7862, 3204, 560, 1153, 2118, 4904, 2682, 644, 5486, 1666, 1954, 4312, 5337, 5997, 7248, 1977, 4497, 3354, 3437, 3478, 4330, 2509, 4909, 2001, 6498, 3855, 5738, 166, 1194, 488, 7631, 2693, 4965, 2691, 2576, 5220, 2545, 135, 2322, 4204, 779, 7000, 4044, 345, 3479, 1388, 5850, 684, 1633, 6265, 3005, 5780, 1962, 7315, 6478, 1567, 2379, 1276, 6743, 2168, 4532, 7657, 2356, 7422, 7639, 2109, 4019, 808, 3829, 3119, 6559, 5819, 3676, 1420, 2011, 3155, 1606, 4868, 3772, 5045, 2132, 373, 570, 6431, 6330, 967, 2234, 2178, 285, 3711, 7012, 4970, 4838, 2614, 6293, 6960, 551, 3167, 4754, 3616, 4741, 5846, 3413, 2340, 3209, 7042, 3947, 5713, 2197, 3012, 1856, 1781, 5002, 1495, 4984, 1999, 1615, 6615, 6451, 6425, 2304, 2163, 3506, 887, 2513, 2586, 4835, 3066, 7221, 1902, 3162, 98]

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
        'Code Diff': 'diff_func'
    }
    func_name = content.get('func_name', '')
    diff_func = content.get('diff_func', '')
    diff_func = f"func@@{func_name}@@{diff_func}"
    content['diff_func'] = diff_func
    input = {target_field: content.get(origin_field, '') for target_field, origin_field in field_mapping.items()}
    # print(input)
    return input


def concatenate_prompt(yaml_data, zero_shot_text, input):
    sections = ['role', 'inst', 'cot', 'format_ask', "step_ask"]
    parts = []
    for section in sections:
        if section == 'step_ask':
            step_ask = yaml_data[section]
            break
        if section in yaml_data:
            parts.append(f"[{section.upper()}]\n{yaml_data[section]}")
    # parts.append("[ZEROSHOTINST]\n" + str(zero_shot_text) + "\n")
    parts.append("[INPUT]\n" + str(input))
    parts.append(step_ask)
    return "\n".join(parts)

def prompt_token_len(prompt):
    encoding = tiktoken.encoding_for_model("gpt-4")
    token_len = len(encoding.encode(prompt))
    print(f"prompt OpenAI tokens: {token_len}")



def load_few_shot_examples(file_path):
    data = load_yaml_file(file_path)
    # order = ['example1', 'example2', 'example3', 'example4', 'example5']
    order = ['example1', 'example2', 'example3']
    parts = []
    for key in order:
        if key in data:
            parts.append(f"{data[key]}\n")
    return "\n".join(parts)

def few_concatenate_prompt(yaml_data, few_shot_text, input):
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

def token_len(prompt):
    encoding = tiktoken.encoding_for_model("gpt-4")
    token_len = len(encoding.encode(prompt))
    print(f"prompt OpenAI tokens: {token_len}")

def few_shot_print(input_path):
    main_prompt = load_yaml_file(cot_yaml_path)
    few_shot_text = load_few_shot_examples(few_shot_path)
    input = input_generator(input_path)
    final_prompt = few_concatenate_prompt(main_prompt, few_shot_text, input)
    token_len(final_prompt)
    # print(final_prompt)
    with open('few_shot.txt', 'w', encoding='utf-8') as f:
        f.write(final_prompt)

def zero_shot_print(input_path):
    main_prompt = load_yaml_file(cot_yaml_path)
    zero_shot_text = load_yaml_file(zero_shot_path)
    input = input_generator(input_path)
    final_prompt = concatenate_prompt(main_prompt, zero_shot_text, input)
    print(final_prompt)
    token_len(final_prompt)
    with open('zero_shot.txt', 'w', encoding='utf-8') as f:
        f.write(final_prompt)


if __name__ == "__main__":
    input_path = './data_show/Part1/merge/CVE-2024-0607/non_sec_vul/type_2/no_more_info/CVE-2024-0607_0_part1.json'
    zero_shot_print(input_path)
    few_shot_print(input_path)
# prompt OpenAI tokens: 1088
# prompt OpenAI tokens: 2569




