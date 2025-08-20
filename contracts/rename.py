import os

# Replacement rules
REPLACEMENTS = {
    "FourMica": "FourMica",
    "fourMica": "fourMica",
    "fourmica": "fourmica",
    "fourmica": "fourmica"
}

def replace_in_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        new_content = content
        for old, new in REPLACEMENTS.items():
            new_content = new_content.replace(old, new)

        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"[MODIFIED CONTENT] {file_path}")

    except (UnicodeDecodeError, PermissionError) as e:
        print(f"[SKIPPED FILE] {file_path} ({e})")

def replace_in_name(path):
    dirname, basename = os.path.split(path)
    new_basename = basename
    for old, new in REPLACEMENTS.items():
        new_basename = new_basename.replace(old, new)

    if new_basename != basename:
        new_path = os.path.join(dirname, new_basename)
        os.rename(path, new_path)
        print(f"[RENAMED] {path} → {new_path}")
        return new_path
    return path

def process_directory(root_dir):
    for current_root, dirs, files in os.walk(root_dir, topdown=False):
        # Rename files
        for name in files:
            file_path = os.path.join(current_root, name)
            file_path = replace_in_name(file_path)
            replace_in_content(file_path)

        # Rename directories
        for name in dirs:
            dir_path = os.path.join(current_root, name)
            replace_in_name(dir_path)

if __name__ == "__main__":
    directory_to_process = "."  # ← Replace with your path
    process_directory(directory_to_process)

