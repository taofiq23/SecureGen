"""Static security scanning with Bandit. Generated code is never executed — only written to a
temp file and statically analyzed, then the temp file is removed."""

import os
import tempfile
from dataclasses import dataclass
from typing import List

from bandit.core import config as bconfig
from bandit.core import manager as bmanager


@dataclass
class Issue:
    test_id: str
    severity: str
    confidence: str
    text: str
    line: int

    def to_dict(self):
        return {"test_id": self.test_id, "severity": self.severity, "confidence": self.confidence, "text": self.text, "line": self.line}


def scan(code: str) -> List[Issue]:
    """Run Bandit's default checks against a string of Python source. Returns [] both when the
    code is clean and when it fails to parse (a syntax error is a generation failure, handled
    separately by the caller, not reported as a security finding)."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "sample.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        conf = bconfig.BanditConfig()
        mgr = bmanager.BanditManager(conf, "file")
        mgr.discover_files([path])
        mgr.run_tests()
        return [
            Issue(test_id=i.test_id, severity=i.severity, confidence=i.confidence, text=i.text, line=i.lineno)
            for i in mgr.get_issue_list()
        ]


def is_syntactically_valid(code: str) -> bool:
    try:
        compile(code, "<generated>", "exec")
        return True
    except SyntaxError:
        return False
