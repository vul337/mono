import re
import json
from collections import defaultdict
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from rich import box
import os

# as vul : tp tn
# as non_vul : fp fn

# input = one log file

def calculate_derived_metrics(all_pairs, tp_tp, tp_fp, fp_tp, fp_fp): # (1,0), (1,1), (0,0), (0,1) without judge
    tp = tp_tp + tp_fp # vul tp
    fn = fp_tp + fp_fp # vul tn

    tn = tp_tp + fp_tp # non_vul tn
    fp = tp_fp + fp_fp # non_vul fp

    recall_denom = tp + fn
    recall = tp / recall_denom if recall_denom > 0 else 0

    acc_denom = tp + tn + fp + fn
    acc = (tp + tn) / acc_denom if acc_denom > 0 else 0

    f1_denom = 2 * tp + fp + fn
    f1 = 2 * tp / f1_denom if f1_denom > 0 else 0

    pair_acc = tp_tp / all_pairs if all_pairs > 0 else 0

    return tp, tn, fp, fn, recall, acc, f1, pair_acc


def extract_analysis_results(log):
    """Same as your existing function"""
    summary_pattern = re.compile(
        r"--- Finished Processing (.+?)\.csv ---.*?"
        r"Valid Pairs Processed: (\d+).*?"
        r"TP/TP: (\d+).*?"
        r"TP/FP: (\d+).*?"
        r"FP/TP: (\d+).*?"
        r"FP/FP: (\d+).*?"
        r"RUNERROR: (\d+)",
        re.DOTALL
    )
#     --- Overall Summary Across All Files ---
# 05/18/2025 09:26:22 PM - [INFO]: Total CSV files processed: 10
# 05/18/2025 09:26:22 PM - [INFO]: Total Valid Pairs Processed: 941
# 05/18/2025 09:26:22 PM - [INFO]: Overall (1,0): 200
# 05/18/2025 09:26:22 PM - [INFO]: Overall (1,1): 291
# 05/18/2025 09:26:22 PM - [INFO]: Overall (0,0): 255
# 05/18/2025 09:26:22 PM - [INFO]: Overall (0,1): 195
# 05/18/2025 09:26:22 PM - [INFO]: Overall RUNERROR: 191
    overall_pattern = re.compile(
        r"--- Overall Summary Across All Files ---.*?"
        r"Total Valid Pairs Processed: (\d+).*?"
        r"Overall \(1,0\): (\d+).*?"
        r"Overall \(1,1\): (\d+).*?"
        r"Overall \(0,0\): (\d+).*?"
        r"Overall \(0,1\): (\d+).*?"
        r"Overall RUNERROR: (\d+)",
        re.DOTALL
    )
    
    file_results = defaultdict(dict)
    for match in summary_pattern.finditer(log):
        file_name = match.group(1)
        tp_tp = int(match.group(3))
        tp_fp = int(match.group(4))
        fp_tp = int(match.group(5))
        fp_fp = int(match.group(6))
        runerror = int(match.group(7))
        # valid_pairs_processed = int(match.group(2)) - runerror
        valid_pairs_processed = int(match.group(2))
        tp, tn, fp, fn, recall, acc, f1, pair_acc = calculate_derived_metrics(
            valid_pairs_processed, tp_tp, tp_fp, fp_tp, fp_fp
        )
        file_results[file_name] = {
            "Valid Pairs": valid_pairs_processed,
            "Recall": recall,
            "Accuracy": acc,
            "F1 Score": f1,
            "Pair Accuracy": pair_acc,
        }
    
    overall_match = overall_pattern.search(log)
    if overall_match:
        _,_,_,_,All_recall, All_acc, All_f1, All_pair_acc = calculate_derived_metrics(
            int(overall_match.group(1))-int(overall_match.group(6)),
            int(overall_match.group(2)), 
            int(overall_match.group(3)), 
            int(overall_match.group(4)), 
            int(overall_match.group(5)), 
        )
        overall_results = {
            "Total Pairs": int(overall_match.group(1)),
            "Total Valid Pairs": int(overall_match.group(1))-int(overall_match.group(6)),
            "Recall": All_recall,
            "Accuracy": All_acc,
            "F1 Score": All_f1,
            "Pair Accuracy": All_pair_acc
        }
    else:
        overall_results = None
    
    return file_results, overall_results



def display_results(file_results, overall_results, file):
    """Enhanced visualization using rich library"""
    console = Console()

    # Display individual file results
    if file_results:
        table = Table(title=f"[bold]{file.split('/')[-1].split('.')[0]} File Analysis Results[/bold]", box=box.ROUNDED)
        table.add_column("File Name", style="cyan", no_wrap=True)
        table.add_column("Valid Pairs", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("Accuracy", justify="right")
        table.add_column("F1 Score", justify="right")
        table.add_column("Pair Accuracy", justify="right")
        
        for file_name, metrics in file_results.items():
            table.add_row(
                file_name,
                str(metrics["Valid Pairs"]),
                f"{metrics['Recall']:.4f}",
                f"{metrics['Accuracy']:.4f}",
                f"{metrics['F1 Score']:.4f}",
                f"{metrics['Pair Accuracy']:.4f}"
            )
        
        console.print(table)
    
    # Display overall results
    if overall_results:
        console.print("\n[bold]Overall Summary[/bold]", style="bold green")
        overall_table = Table(box=box.SIMPLE_HEAVY)
        overall_table.add_column("Metric", style="bold")
        overall_table.add_column("Value", justify="right")
        
        for metric, value in overall_results.items():
            if isinstance(value, float):
                overall_table.add_row(metric, f"{value:.4f}")
            else:
                overall_table.add_row(metric, str(value))
        
        console.print(overall_table)


DIR=None
FILE=None
def log_analysis():
    DIR = input("Enter the root log directory: ")
    # DIR = "./with-con"
    FILE = input("Enter the log file name (or leave blank to analyze all logs in the directory): ") 

    if os.path.exists(FILE):
        with open(FILE, "r") as f:
            log_content = f.read()
        file_results, overall_results = extract_analysis_results(log_content)
        display_results(file_results, overall_results, FILE)

    if DIR:
        for filename in os.listdir(DIR):
            if filename.endswith(".log"):
                filepath = os.path.join(DIR, filename)
                with open(filepath, "r") as f:
                    log_content = f.read()
                file_results, overall_results = extract_analysis_results(log_content)
                display_results(file_results, overall_results, filepath)



def display_judge_results(file_results, overall_results, model_name, context_str,METRICS):
    output_filename = METRICS 
    """Enhanced visualization using rich library"""
    console = Console()

    table_title = f"[bold]{model_name} {context_str} context Judge Analysis[/bold]"

    if file_results:
        table = Table(title=table_title, box=box.ROUNDED)
        table.add_column("CWE ID", style="cyan", no_wrap=True) # Changed from "File Name"
        table.add_column("Valid Pairs", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("Accuracy", justify="right")
        table.add_column("F1 Score", justify="right")
        table.add_column("Pair Accuracy", justify="right")

        for row in file_results:
            table.add_row(*row) # Unpack the list directly

        console.print(table)

    # Display overall results
    if overall_results:
        console.print("\n[bold]Overall Summary[/bold]", style="bold green")
        overall_table = Table(box=box.SIMPLE_HEAVY)
        overall_table.add_column("Metric", style="bold")
        overall_table.add_column("Value", justify="right")

        for metric, value in overall_results.items():
            overall_table.add_row(metric, str(value)) # Value is already formatted as string

        console.print(overall_table)

def metrics_analysis():
    METRICS = input("Enter the metrics output file path: ")
    try:
        with open(METRICS , 'r') as f:
            loaded_data = json.load(f)

        model_name_for_display = loaded_data.get("model", "Unknown Model")
        context_bool_for_display = loaded_data.get("context", False)
        context_str_for_display = "with" if context_bool_for_display else "without"

        # The 'data' field contains the CWE-wise results
        cwe_results_for_display = loaded_data.get("data", [])
        # The 'overall' field contains the aggregated results
        overall_results_for_display = loaded_data.get("overall", {})

        display_judge_results(
            cwe_results_for_display,
            overall_results_for_display,
            model_name_for_display,
            context_str_for_display,
            METRICS
        )

    except FileNotFoundError:
        print(f"Error: Output file not found at {output_filename}. Cannot display results.")
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {output_filename}. Cannot display results.")
    except Exception as e:
        print(f"An error occurred during display: {e}")

def no_judge_analysis():
    DIR = input("Enter the root no judge directory: ")
    # DIR = "./wisth-con"
    



if __name__ == "__main__":
    choose = input("Choose the analysis type (1 for log analysis, 2 for metrics analysis): ")
    if choose == '1':
        log_analysis()
    elif choose == '2':
        metrics_analysis()
    else:
        print("Invalid choice. Please enter 1 or 2.")

