import os
import random
import shutil

def select_random_samples(source_dir, destination_dir, num_samples=500, seed=2025):
    """
    Selects a specified number of random files from a source directory
    and copies them to a destination directory.

    Args:
        source_dir (str): The path to the directory containing the files to choose from.
        destination_dir (str): The path to the directory where the selected files will be copied.
        num_samples (int): The number of files to select.
        seed (int): The seed for the random number generator to ensure reproducibility.
    """
    # Set the random seed for reproducibility
    random.seed(seed)

    # Ensure the destination directory exists
    os.makedirs(destination_dir, exist_ok=True)

    # Get a list of all files in the source directory
    all_files = [f for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]

    if not all_files:
        print(f"No files found in the source directory: {source_dir}")
        return

    if len(all_files) < num_samples:
        print(f"Warning: Only {len(all_files)} files available in {source_dir}, "
              f"which is less than the requested {num_samples}. Copying all available files.")
        files_to_copy = all_files
    else:
        # Randomly select 'num_samples' files
        files_to_copy = random.sample(all_files, num_samples)

    copied_count = 0
    print(f"Attempting to copy {len(files_to_copy)} files from {source_dir} to {destination_dir}...")

    for filename in files_to_copy:
        source_file_path = os.path.join(source_dir, filename)
        destination_file_path = os.path.join(destination_dir, filename)
        try:
            shutil.copy2(source_file_path, destination_file_path)
            copied_count += 1
            # print(f"Copied: {filename}") # Uncomment if you want to see each file being copied
        except Exception as e:
            print(f"Error copying {filename}: {e}")

    print(f"\nSuccessfully copied {copied_count} files to {destination_dir}.")
    if copied_count < num_samples:
        print(f"Note: Some files might not have been copied due to errors or insufficient files in source.")


source_directory = ""../samples"
destination_directory = "../sample500" 

if __name__ == "__main__":
    select_random_samples(source_directory, destination_directory)