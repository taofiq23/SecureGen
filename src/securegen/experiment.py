"""Runs the three-condition experiment and saves every raw generation plus its Bandit findings,
so any number in the summary can be traced back to the exact code that produced it.

  A. plain            -- no mention of security in the prompt
  B. security_aware    -- same prompt, told to write secure code
  C. scan_and_fix      -- starts from A's own generation; where Bandit found an issue, the model
                          is shown Bandit's findings and asked to rewrite. C is therefore paired
                          with A by construction (same starting code), not an independent arm.

    python -m securegen.experiment --samples 5
"""

import argparse
import json
import time
from pathlib import Path
from typing import List

from .generate import _client, generate, generate_fix
from .prompts import TASKS
from .scanner import is_syntactically_valid, scan

ROOT = Path(__file__).resolve().parent.parent.parent
GEN_DIR = ROOT / "generations"
RESULTS_DIR = ROOT / "study_results"


def _record(task_id: str, condition: str, sample_idx: int, code: str, raw_reply: str, extra: dict = None) -> dict:
    valid = is_syntactically_valid(code)
    issues = scan(code) if valid else []
    row = {
        "task_id": task_id,
        "condition": condition,
        "sample_idx": sample_idx,
        "code": code,
        "raw_reply": raw_reply,
        "syntactically_valid": valid,
        "n_issues": len(issues),
        "has_issue": len(issues) > 0,
        "issues": [i.to_dict() for i in issues],
    }
    if extra:
        row.update(extra)
    return row


def run(n_samples: int = 5, temperature: float = 0.7) -> List[dict]:
    client = _client()
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows: List[dict] = []
    t0 = time.time()

    for task in TASKS:
        print(f"[{task.id}] plain + security_aware ...")
        plain_codes = []
        for i in range(n_samples):
            g = generate(client, task.prompt, security_aware=False, temperature=temperature)
            row = _record(task.id, "plain", i, g.code, g.raw_reply)
            rows.append(row)
            plain_codes.append(row)

            g2 = generate(client, task.prompt, security_aware=True, temperature=temperature)
            rows.append(_record(task.id, "security_aware", i, g2.code, g2.raw_reply))

        print(f"[{task.id}] scan_and_fix ...")
        for i, base_row in enumerate(plain_codes):
            if not base_row["has_issue"]:
                # Nothing for the scanner to flag -- the fixed version is, by definition, the
                # same already-clean code. No second LLM call is made or needed.
                rows.append(_record(task.id, "scan_and_fix", i, base_row["code"], base_row["raw_reply"], extra={"fix_applied": False, "base_had_issue": False}))
                continue
            issues_text = "\n".join(f"- [{iss['test_id']}] {iss['text']} (line {iss['line']})" for iss in base_row["issues"])
            g = generate_fix(client, task.prompt, base_row["code"], issues_text, temperature=temperature)
            row = _record(task.id, "scan_and_fix", i, g.code, g.raw_reply, extra={"fix_applied": True, "base_had_issue": True, "base_n_issues": base_row["n_issues"]})
            rows.append(row)

    elapsed = time.time() - t0
    out_path = GEN_DIR / "raw_generations.json"
    out_path.write_text(json.dumps(rows, indent=2))
    print(f"Done: {len(rows)} generations in {elapsed:.1f}s -> {out_path}")
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--temperature", type=float, default=0.7)
    args = parser.parse_args()
    run(n_samples=args.samples, temperature=args.temperature)
