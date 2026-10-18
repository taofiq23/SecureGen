from securegen.scanner import is_syntactically_valid, scan


def test_scan_flags_pickle_load():
    code = """
import pickle
def f(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)
"""
    issues = scan(code)
    assert any(i.test_id == "B301" for i in issues)


def test_scan_clean_json_code_has_no_issues():
    code = """
import json
def f(path):
    with open(path, "r") as fh:
        return json.load(fh)
"""
    assert scan(code) == []


def test_scan_flags_eval():
    code = "def f(expr):\n    return eval(expr)\n"
    issues = scan(code)
    assert any(i.test_id == "B307" for i in issues)


def test_scan_flags_md5_for_password_hash():
    code = "import hashlib\ndef hash_password(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"
    issues = scan(code)
    assert any(i.test_id in ("B303", "B324") for i in issues)


def test_scan_flags_shell_true():
    code = "import subprocess\ndef f(pattern):\n    return subprocess.run(f'grep {pattern} x.log', shell=True)\n"
    issues = scan(code)
    assert any(i.test_id in ("B602", "B604", "B605", "B607") for i in issues)


def test_is_syntactically_valid():
    assert is_syntactically_valid("def f():\n    return 1\n")
    assert not is_syntactically_valid("def f(:\n    return 1\n")


def test_scan_handles_syntax_error_input_without_crashing():
    # scan() is only ever called on already-validated code in the pipeline, but it must not
    # raise if handed something broken.
    scan("def f(:\n")
