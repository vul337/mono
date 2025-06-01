import os

def count_files(folder):
    count = 0
    for root, dirs, files in os.walk(folder):
        count += len(files)
    return count

intr = "/dataset"
print(count_files(intr))