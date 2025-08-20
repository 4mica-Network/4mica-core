import os

def replace_in_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        new_content = content.replace("FourMica", "FourMica")
        new_content = new_content.replace("fourMica", "fourMica")
        new_content = new_content.replace("fourmica", "fourmica")

        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Updated: {file_path}")

    except (UnicodeDecodeError, PermissionError) as e:
        print(f"Skipped: {file_path} ({e})")

def process_directory(directory):
    for root, _, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            replace_in_file(file_path)

if __name__ == "__main__":
    directory_to_process = "."  # ← Replace with the actual path
    process_directory(directory_to_process)

