"""Turns generations/raw_generations.json into the summary numbers reported in the README:
pooled issue rate per condition (raw Bandit verdict and after the manual audit in audit.py),
per-task breakdown, and the paired plain-vs-fixed outcome for scan_and_fix (same starting code,
does feedback remove the issue).

    python -m securegen.analyze
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import List

from .audit import apply_audit
from .metrics import paired_rate_difference_ci, rate_bootstrap_ci

ROOT = Path(__file__).resolve().parent.parent.parent
GEN_PATH = ROOT / "generations" / "raw_generations.json"
RESULTS_DIR = ROOT / "study_results"


def load_rows() -> List[dict]:
    return apply_audit(json.loads(GEN_PATH.read_text()))


def _pooled(items, key):
    flags = [r[key] for r in items]
    point, lo, hi = rate_bootstrap_ci(flags)
    return {
        "n_samples": len(items),
        "issue_rate": point,
        "ci_lo": lo,
        "ci_hi": hi,
        "mean_issues_per_sample": sum(r["n_issues"] for r in items) / len(items),
        "n_invalid_syntax": sum(1 for r in items if not r["syntactically_valid"]),
    }


def analyze(rows: List[dict] = None) -> dict:
    rows = apply_audit(rows) if rows is not None else load_rows()

    by_condition = defaultdict(list)
    for r in rows:
        by_condition[r["condition"]].append(r)

    pooled_raw = {cond: _pooled(items, "has_issue") for cond, items in by_condition.items()}
    pooled_audited = {cond: _pooled(items, "has_issue_audited") for cond, items in by_condition.items()}

    per_task = defaultdict(dict)
    for cond, items in by_condition.items():
        by_task = defaultdict(list)
        for r in items:
            by_task[r["task_id"]].append(r)
        for task_id, task_rows in by_task.items():
            per_task[task_id][cond] = {
                "n": len(task_rows),
                "n_with_issue_raw": sum(r["has_issue"] for r in task_rows),
                "n_with_issue_audited": sum(r["has_issue_audited"] for r in task_rows),
            }

    def paired(key):
        plain_by_key = {(r["task_id"], r["sample_idx"]): r[key] for r in by_condition.get("plain", [])}
        aware_by_key = {(r["task_id"], r["sample_idx"]): r[key] for r in by_condition.get("security_aware", [])}
        common_keys = sorted(set(plain_by_key) & set(aware_by_key))
        plain_vec = [plain_by_key[k] for k in common_keys]
        aware_vec = [aware_by_key[k] for k in common_keys]
        diff_point, diff_lo, diff_hi = paired_rate_difference_ci(plain_vec, aware_vec)
        return {
            "n_pairs": len(common_keys),
            "plain_issue_rate": sum(plain_vec) / len(plain_vec) if plain_vec else None,
            "security_aware_issue_rate": sum(aware_vec) / len(aware_vec) if aware_vec else None,
            "difference_plain_minus_aware": diff_point,
            "ci_lo": diff_lo,
            "ci_hi": diff_hi,
        }

    plain_vs_aware_raw = paired("has_issue")
    plain_vs_aware_audited = paired("has_issue_audited")

    # scan_and_fix outcomes, audited: a base counts as "had an issue" only under the audited
    # verdict, and "fixed" is judged by the audited verdict on the fix output too.
    fix_rows = [r for r in by_condition.get("scan_and_fix", []) if r.get("fix_applied")]
    audited_fix_rows = [r for r in fix_rows if r.get("base_n_issues", 0) > 0]
    fully_fixed = sum(1 for r in audited_fix_rows if not r["has_issue_audited"])
    not_fixed = sum(1 for r in audited_fix_rows if r["has_issue_audited"])
    fix_outcomes = {
        "note": "Counts restricted to bases where a fix call was actually made (Bandit raw flagged an issue); "
        "'fixed' here is judged by the audited verdict, not the raw Bandit verdict.",
        "n_bases_with_raw_issue": len(fix_rows),
        "fully_fixed_by_audited_verdict": fully_fixed,
        "still_flagged_by_audited_verdict": not_fixed,
    }

    summary = {
        "pooled_by_condition_raw": pooled_raw,
        "pooled_by_condition_audited": pooled_audited,
        "per_task": per_task,
        "plain_vs_security_aware_paired_raw": plain_vs_aware_raw,
        "plain_vs_security_aware_paired_audited": plain_vs_aware_audited,
        "scan_and_fix_outcomes": fix_outcomes,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    print(json.dumps(analyze(), indent=2))
