from classify import classify, launched_id, REJECT, EXEC_ERROR, MISMATCH, CORRECT


def rec(**kw):
    base = {"policy": "path", "decision": "APPROVE", "exec_errno": 0, "signal": 0,
            "exit_status": 0, "child_output": "RACEPROOF_ID=A PID=42", "torn": 0}
    base.update(kw)
    return base


def test_correct():
    o = classify(rec())
    assert o.primary == CORRECT and o.launched_id == "A"


def test_mismatch_when_b_runs():
    o = classify(rec(child_output="RACEPROOF_ID=B PID=7"))
    assert o.primary == MISMATCH and o.launched_id == "B"


def test_reject_beats_everything():
    o = classify(rec(decision="REJECT", child_output=""))
    assert o.primary == REJECT and o.launched_id is None


def test_exec_errno_is_exec_error_not_mismatch():
    o = classify(rec(exec_errno=8, child_output=""))
    assert o.primary == EXEC_ERROR


def test_signal_death_is_exec_error():
    o = classify(rec(signal=11, child_output=""))
    assert o.primary == EXEC_ERROR


def test_no_id_line_is_exec_error():
    o = classify(rec(child_output="garbage"))
    assert o.primary == EXEC_ERROR and o.launched_id is None


def test_torn_flag_is_independent():
    o = classify(rec(decision="REJECT", child_output="", torn=1, policy="sealed"))
    assert o.primary == REJECT and o.flags["torn"] is True


def test_unsupported_only_for_sealed_eacces():
    assert classify(rec(policy="sealed", exec_errno=13, child_output="")).flags["unsupported"]
    assert not classify(rec(policy="path", exec_errno=13, child_output="")).flags["unsupported"]


def test_etxtbsy_passthrough():
    assert classify(rec(), etxtbsy=True).flags["etxtbsy"]


def test_approved_id_parameter():
    o = classify(rec(child_output="RACEPROOF_ID=B PID=1"), approved_id="B")
    assert o.primary == CORRECT


def test_launched_id_parsing():
    assert launched_id("RACEPROOF_ID=A PID=1\n") == "A"
    assert launched_id("") is None
    assert launched_id(None) is None


def test_as_row_shape():
    row = classify(rec()).as_row()
    assert row["outcome"] == CORRECT and row["launched_id"] == "A"
    assert set(row) >= {"torn", "etxtbsy", "unsupported"}


def test_unknown_decision_raises():
    import pytest
    with pytest.raises(ValueError):
        classify(rec(decision="MAYBE"))
