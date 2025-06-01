import os
import json
from collections import defaultdict


metrics_model = "qn3-32b-0"  

ALL = 1
CONTEXT_ON = 0
JUDGE_ROOT = "/RQ4/result/analysis/judge"

def calculate_derived_metrics(tp, fn, tn, fp, all_pairs, ideal_pairs):
    recall_denom = tp + fn
    recall = tp / recall_denom if recall_denom > 0 else 0.0

    acc_denom = tp + tn + fp + fn
    acc = (tp + tn) / acc_denom if acc_denom > 0 else 0.0

    f1_denom = 2 * tp + fp + fn
    f1 = (2.0 * tp) / f1_denom if f1_denom > 0 else 0.0

    pair_acc_denom = all_pairs
    pair_acc = ideal_pairs / pair_acc_denom if pair_acc_denom > 0 else 0.0

    return recall, acc, f1, pair_acc

def process_files(directory_path, output_filename, model):
    cwe_aggregated_data = defaultdict(lambda: {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0, 'all_pairs': 0, 'ideal_pairs': 0})

    try:
        files = [f for f in os.listdir(directory_path) if f.endswith('_analysis_results_judge.json')]
    except FileNotFoundError:
        print(f"Error: Directory not found at {directory_path}")
        exit()
    except Exception as e:
        print(f"An error occurred listing files: {e}")
        exit()

    print(f"Found {len(files)} files to process in {directory_path}")

    for filename in files:
        file_path = os.path.join(directory_path, filename)
        try:
            cwe_number = filename.split('_')[0]
            cwe_id = f"cwe-{cwe_number}"
        except IndexError:
            print(f"Skipping file with unexpected name format: {filename}")
            continue

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            for cve_id, cve_data in data.items():
                vuln_result = cve_data.get('vuln_result')
                patched_result = cve_data.get('patched_result')
                ret_vuln_eval = cve_data.get('ret_vuln_eval')
                ret_patched_eval = cve_data.get('ret_patched_eval')

                if (vuln_result is not None and patched_result is not None and patched_result != -1):

                    cwe_aggregated_data[cwe_id]['all_pairs'] += 1

                    if (ret_vuln_eval == 1 and ret_patched_eval == 1) or (ret_vuln_eval == 1 and patched_result == 0):
                        cwe_aggregated_data[cwe_id]['ideal_pairs'] += 1

                    if vuln_result == 0:
                        cwe_aggregated_data[cwe_id]['fn'] += 1
                    elif vuln_result == 1:
                        if ret_vuln_eval == 1 or ret_vuln_eval is True:
                            cwe_aggregated_data[cwe_id]['tp'] += 1
                        elif ret_vuln_eval == 0 or ret_vuln_eval is False:
                            cwe_aggregated_data[cwe_id]['fn'] += 1

                    if patched_result == 0:
                        cwe_aggregated_data[cwe_id]['tn'] += 1
                    elif patched_result == 1:
                        if ret_patched_eval == 1 or ret_patched_eval is True:
                            cwe_aggregated_data[cwe_id]['tn'] += 1
                        elif ret_patched_eval == 0 or ret_patched_eval is False:
                            cwe_aggregated_data[cwe_id]['fp'] += 1
                    else:
                        print(f"Warning: Unexpected result value for {cve_id} in {filename}. Skipping TP/TN/FP/FN count.")


        except json.JSONDecodeError:
            print(f"Error decoding JSON from {filename}. Skipping file.")
            continue
        except Exception as e:
            print(f"An error occurred processing {filename}: {e}. Skipping file.")
            continue

    output_data_list = []

    sorted_cwe_ids = sorted(cwe_aggregated_data.keys())

    # Initialize overall metrics
    overall_tp = 0
    overall_tn = 0
    overall_fp = 0
    overall_fn = 0
    overall_all_pairs = 0
    overall_ideal_pairs = 0

    for cwe_id in sorted_cwe_ids:
        counts = cwe_aggregated_data[cwe_id]
        tp = counts['tp']
        tn = counts['tn']
        fp = counts['fp']
        fn = counts['fn']
        all_pairs = counts['all_pairs']
        ideal_pairs = counts['ideal_pairs']

        # Accumulate for overall metrics
        overall_tp += tp
        overall_tn += tn
        overall_fp += fp
        overall_fn += fn
        overall_all_pairs += all_pairs
        overall_ideal_pairs += ideal_pairs

        if all_pairs > 0:
            recall, acc, f1, pair_acc = calculate_derived_metrics(tp, fn, tn, fp, all_pairs, ideal_pairs)
        else:
            recall, acc, f1, pair_acc = 0.0, 0.0, 0.0, 0.0

        output_row = [
            cwe_id,
            str(all_pairs),
            f"{recall:.4f}",
            f"{acc:.4f}",
            f"{f1:.4f}",
            f"{pair_acc:.4f}"
        ]
        output_data_list.append(output_row)

    # Calculate overall derived metrics
    overall_recall, overall_acc, overall_f1, overall_pair_acc = calculate_derived_metrics(
        overall_tp, overall_fn, overall_tn, overall_fp, overall_all_pairs, overall_ideal_pairs
    )


    header = [
        "File Name",
        "Valid Pairs",
        "Recall",
        "Accuracy",
        "F1 Score",
        "Pair Accuracy"
    ]

    final_output = {
        'model': model,
        'context': CONTEXT_ON,
        "header": header,
        "data": output_data_list,
        "overall": {
            "Total Pairs": overall_all_pairs,
            "Total Ideal Pairs": overall_ideal_pairs, # Corrected key name for clarity
            "Recall": f"{overall_recall:.4f}",
            "Accuracy": f"{overall_acc:.4f}",
            "F1 Score": f"{overall_f1:.4f}",
            "Pair Accuracy": f"{overall_pair_acc:.4f}"
        }
    }

    try:
        with open(output_filename, 'w') as outfile:
            json.dump(final_output, outfile, indent=4)
        print(f"Metrics successfully written to {output_filename}")
    except Exception as e:
        print(f"Error writing output file {output_filename}: {e}")

if ALL and CONTEXT_ON:
    print("Processing all directories with context on")
    dir = JUDGE_ROOT + f"/with-con/"
    for i in os.listdir(dir):
        if os.path.isdir(os.path.join(dir, i)):
            directory_path = JUDGE_ROOT + f"/with-con/{i}"
            output_filename = JUDGE_ROOT + f"/with-con/{i}/metrics_output.json"
            print(f"Processing directory: {directory_path}")
            process_files(directory_path, output_filename, i)


if ALL and not CONTEXT_ON:
    print("Processing all directories with context off")
    dir = JUDGE_ROOT + f"/without-con/"
    for i in os.listdir(dir):
        if os.path.isdir(os.path.join(dir, i)):
            directory_path = JUDGE_ROOT + f"/without-con/{i}"
            output_filename = JUDGE_ROOT + f"/without-con/{i}/metrics_output.json"
            print(f"Processing directory: {directory_path}")
            process_files(directory_path, output_filename, i)

   
if not ALL and CONTEXT_ON:
    directory_path = JUDGE_ROOT + f"/with-con/{metrics_model}"
    output_filename = JUDGE_ROOT + f"/with-con/{metrics_model}/metrics_output.json"
    print(f"Processing directory: {directory_path}")
    process_files(directory_path, output_filename, metrics_model)

if not ALL and not CONTEXT_ON:
    directory_path = JUDGE_ROOT + f"/without-con/{metrics_model}"
    output_filename = JUDGE_ROOT + f"/without-con/{metrics_model}/metrics_output.json"
    print(f"Processing directory: {directory_path}")
    process_files(directory_path, output_filename, metrics_model)