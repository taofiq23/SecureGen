from securegen.audit import audited_has_issue


def _row(task, issues, has_issue=True):
    return {"task_id": task, "has_issue": has_issue, "issues": [{"test_id": t} for t in issues]}


def test_log_search_safe_subprocess_advisories_are_cleared():
    row = _row("log_search", ["B404", "B603", "B607"])
    assert audited_has_issue(row) is False


def test_log_search_real_shell_true_is_not_cleared():
    row = _row("log_search", ["B404", "B602"])
    assert audited_has_issue(row) is True


def test_other_task_keeps_subprocess_advisories_unaudited():
    # the log_search-specific clearing must not leak into unrelated tasks
    row = _row("some_other_task", ["B404", "B603", "B607"])
    assert audited_has_issue(row) is True


def test_xml_import_only_advisory_is_cleared():
    row = _row("parse_feed", ["B405"])
    assert audited_has_issue(row) is False


def test_xml_real_risk_is_not_cleared():
    row = _row("parse_feed", ["B405", "B314"])
    assert audited_has_issue(row) is True


def test_no_issues_stays_false():
    row = _row("anything", [], has_issue=False)
    assert audited_has_issue(row) is False
