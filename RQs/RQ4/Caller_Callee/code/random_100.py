import random
import os

def select_random_lines(input_file_path, output_file_path, num_lines=100, seed=2025):
    random.seed(seed)

    try:
        with open(input_file_path, 'r') as infile:
            lines = infile.readlines()

        # Remove empty lines if any
        lines = [line.strip() for line in lines if line.strip()]

        if len(lines) < num_lines:
            print(f"Warning: The input file only contains {len(lines)} non-empty lines, which is less than the requested {num_lines}.")
            selected_lines = lines
        else:
            selected_lines = random.sample(lines, num_lines)

        # Ensure the output directory exists
        output_dir = os.path.dirname(output_file_path)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_file_path, 'w') as outfile:
            for line in selected_lines:
                outfile.write(line + '\n')

        print(f"Successfully selected {len(selected_lines)} random lines from '{input_file_path}' and saved to '{output_file_path}'.")

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

input_file = '../samples/cve-500.txt'
output_file = '../samples/random-100.txt'

select_random_lines(input_file, output_file)