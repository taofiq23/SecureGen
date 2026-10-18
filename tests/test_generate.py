from securegen.generate import extract_code


def test_extract_code_from_fenced_python_block():
    reply = "Here is the function:\n\n```python\ndef f():\n    return 1\n```\n"
    assert extract_code(reply) == "def f():\n    return 1"


def test_extract_code_falls_back_to_full_reply_without_fence():
    reply = "def f():\n    return 1"
    assert extract_code(reply) == reply


def test_extract_code_handles_fence_without_language_tag():
    reply = "```\ndef f():\n    return 1\n```"
    assert extract_code(reply) == "def f():\n    return 1"
