import subprocess

def run_executable(path, args=[]):
    try:
        result = subprocess.run(
            [path] + args,
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        raise FileNotFoundError(f"Eseguibile non trovato: {path}")

def compare_executables(original_path, permuted_path, args=[]):
    code_orig, out_orig, err_orig = run_executable(original_path, args)
    code_perm, out_perm, err_perm = run_executable(permuted_path, args)

    differences = {
        "exit_code": (code_orig, code_perm),
        "stdout_same": out_orig == out_perm,
        "stderr_same": err_orig == err_perm,
        "stdout_orig": out_orig,
        "stdout_perm": out_perm,
        "stderr_orig": err_orig,
        "stderr_perm": err_perm
    }

    return differences

# Solo se eseguito da terminale
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Uso: python check_exe.py originale.exe permutato.exe [arg1 arg2 ...]")
        sys.exit(1)
    original = sys.argv[1]
    permuted = sys.argv[2]
    args = sys.argv[3:]
    diffs = compare_executables(original, permuted, args)
    print(diffs)
