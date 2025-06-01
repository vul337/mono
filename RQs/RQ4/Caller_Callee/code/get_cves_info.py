import os
import json


platform = "github"  

def analyze_cve_data(base_path, output_file):
    cve_base_dir = os.path.join(base_path, platform)
    
    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(output_file, 'w') as outfile:
        for cve_dir in os.listdir(cve_base_dir):
            cve_path = os.path.join(cve_base_dir, cve_dir)
            if os.path.isdir(cve_path):
                json_file_path = os.path.join(cve_path, "Root_cause_analysis.json")
                
                if os.path.exists(json_file_path):
                    try:
                        with open(json_file_path, 'r') as f:
                            data = json.load(f)
                            
                            enriched_data = data.get("enriched_data", [])
   
                            # Filter criteria
                            # 1. 'tool' uses 'value_info', 'code_info', or 'query_info'
                            # 2. 'result' is not "no valid result..."
                            
                            filtered_entries = []
                            
                            for entry in enriched_data:
                                tool = entry.get("tool", "")
                                result = entry.get("result", "")
                                
                                if "no valid" in str(result).lower():
                                    continue # Skip if result is "no valid"
                                    
                                if any(keyword in tool for keyword in ["value_info", "code_info", "query_info"]):
                                    filtered_entries.append(entry)
                                    
                            # Check if total enriched_data entries (excluding "no valid" results) > 6
    
                            valid_enriched_data_count = 0
                            for entry in enriched_data:
                                result = entry.get("result", "")
                                if "no valid" not in str(result).lower():
                                    valid_enriched_data_count += 1
                            print(f"Processing {json_file_path}...\nlen:{len(filtered_entries)}, valid count: {valid_enriched_data_count}, confidence score: {data.get('confidence_score', 0)}")     
                            if len(filtered_entries) > 0 and valid_enriched_data_count > 3 and data.get("confidence_score", 0) > 0.9:
                                outfile.write(cve_path + '\n')
                                
                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON in {json_file_path}: {e}")
                    except Exception as e:
                        print(f"An error occurred while processing {json_file_path}: {e}")

base_data_path = "/storage/result/Part2_result"
output_samples_file = "/RQ4/Caller_Callee/samples/cve-500.txt"

analyze_cve_data(base_data_path, output_samples_file)
print(f"Analysis complete. Qualifying CVE paths written to {output_samples_file}")