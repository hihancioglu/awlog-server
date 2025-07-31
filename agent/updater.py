import os
import sys
import time
import shutil
import subprocess


def replace_exe(target_path: str, new_path: str, retries: int = 50, delay: float = 0.2) -> bool:
    """Replace the target executable with the new one, waiting until it can be overwritten."""
    for _ in range(retries):
        try:
            # os.replace works atomic and overwrites if exists
            os.replace(new_path, target_path)
            return True
        except PermissionError:
            time.sleep(delay)
        except OSError:
            time.sleep(delay)
    return False


def main():
    if len(sys.argv) < 3:
        print("Usage: updater.py <target_exe> <temp_exe>")
        sys.exit(1)

    target = sys.argv[1]
    new_file = sys.argv[2]

    if not os.path.exists(new_file):
        print("New executable not found")
        sys.exit(1)

    if replace_exe(target, new_file):
        subprocess.Popen([target], shell=False)
    else:
        print("Failed to replace executable")
        sys.exit(1)


if __name__ == "__main__":
    main()
