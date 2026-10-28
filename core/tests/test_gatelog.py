from securebuilderbot_core.gatelog import HEADER, append_row, epic_column


def test_a_missing_log_starts_with_the_header(tmp_path):
    log = tmp_path / "gate-records" / "gate-log.md"
    assert append_row(log, date="2026-10-15", branch="epic/core", base="a" * 40, head="b" * 40,
                      run_id="r1", findings="0 blocking, 0 advisory", verdict="Scan PASS") is None
    text = log.read_text()
    assert text.startswith(HEADER)
    assert text.splitlines()[-1] == "| 2026-10-15 | core | `aaaaaaa..bbbbbbb` | r1 | 0 blocking, 0 advisory | — | Scan PASS | securebuilderbot core |"


def test_the_empty_old_template_is_replaced_but_a_log_with_rows_is_kept(tmp_path):
    log = tmp_path / "gate-log.md"
    log.write_text("| Date | Story | Quality | Sentinel | Manual Review | User | Commit |\n|---|---|---|---|---|---|---|\n")
    append_row(log, date="d", branch="b", base="1" * 7, head="2" * 7, run_id="r", findings="f", verdict="v")
    assert log.read_text().startswith(HEADER)
    before = log.read_text()
    append_row(log, date="d2", branch="b", base="1" * 7, head="2" * 7, run_id="r2", findings="f", verdict="v")
    assert log.read_text().startswith(before) and log.read_text().count("\n") == before.count("\n") + 1


def test_a_log_that_cannot_be_written_warns_and_never_raises(tmp_path):
    blocker = tmp_path / "gate-records"
    blocker.write_text("a file where the directory should be")
    warning = append_row(blocker / "gate-log.md", date="d", branch="b", base="1", head="2", run_id="r", findings="f", verdict="v")
    assert warning and warning.startswith("gate log not written")


def test_epic_column():
    assert epic_column("epic/core") == "core"
    assert epic_column("fix-x") == "fix-x (branch `fix-x`)"
