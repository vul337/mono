import os

def count_cve_files(output_dir):
    if not os.path.exists(output_dir):
        return 0
    
    file_count = 0

    for filename in os.listdir(output_dir):
        if filename.startswith("CVE-") and os.path.isfile(os.path.join(output_dir, filename)):
            if "_" not in filename:
                 file_count += 1
            #file_count += 1
    return file_count


base = "dataset/Part2/MegaVul_dataset"
output_dir = base+"/mysort_1_pr/c_cpp/megavul_simple_vul"
count = count_cve_files(output_dir)
print(f"c_cpp dir '{output_dir}' have {count}  CVE")

output_dir = base+"/mysort_1/java/megavul/vul"
count = count_cve_files(output_dir)
print(f"java dir '{output_dir}' have {count} CVE")

# c_cpp dir '../mysort_1/c_cpp/megavul/vul' have 7476  CVE
# java dir '../mysort_1/java/megavul/vul' have 775 CVE

# c_cpp dir '/mysort_1/c_cpp/megavul/vul' have 17885  CVE_file
# java dir '/java/megavul/vul' have 2425 CVE_file
