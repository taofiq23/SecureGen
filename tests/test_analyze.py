from securegen.analyze import analyze


def _row(task, cond, idx, has_issue, n_issues=None, extra=None):
    n_issues = n_issues if n_issues is not None else (1 if has_issue else 0)
    row = {
        "task_id": task,
        "condition": cond,
        "sample_idx": idx,
        "code": "...",
        "raw_reply": "...",
        "syntactically_valid": True,
        "n_issues": n_issues,
        "has_issue": has_issue,
        "issues": [{"test_id": "B000"}] if has_issue else [],
    }
    if extra:
        row.update(extra)
    return row


def test_analyze_pooled_rate_and_paired_comparison():
    rows = [
        _row("t1", "plain", 0, True),
        _row("t1", "security_aware", 0, False),
        _row("t1", "plain", 1, True),
        _row("t1", "security_aware", 1, True),
        _row("t1", "scan_and_fix", 0, False, extra={"fix_applied": True, "base_n_issues": 1}),
        _row("t1", "scan_and_fix", 1, True, n_issues=1, extra={"fix_applied": True, "base_n_issues": 2}),
    ]
    summary = analyze(rows)
    assert summary["pooled_by_condition_raw"]["plain"]["issue_rate"] == 1.0
    assert summary["pooled_by_condition_raw"]["security_aware"]["issue_rate"] == 0.5
    assert summary["plain_vs_security_aware_paired_raw"]["n_pairs"] == 2
    fix = summary["scan_and_fix_outcomes"]
    assert fix["n_bases_with_raw_issue"] == 2
    assert fix["fully_fixed_by_audited_verdict"] == 1
    assert fix["still_flagged_by_audited_verdict"] == 1


def test_log_search_advisory_only_rows_counted_as_fixed_in_audited_view():
    rows = [
        _row("log_search", "plain", 0, True, extra={}),  # has_issue True, but test_id B000 is not an advisory id
    ]
    rows[0]["issues"] = [{"test_id": "B603"}]
    summary = analyze(rows)
    assert summary["pooled_by_condition_raw"]["plain"]["issue_rate"] == 1.0
    assert summary["pooled_by_condition_audited"]["plain"]["issue_rate"] == 0.0
