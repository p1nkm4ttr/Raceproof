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


PAD_A = "0123456789abcdef"
PAD_X = "fedcba9876543210"


def test_pad_match_is_correct():
    o = classify(rec(child_output=f"RACEPROOF_ID=A PID=1\nRACEPROOF_PAD={PAD_A}"), approved_pad=PAD_A)
    assert o.primary == CORRECT and o.launched_pad == PAD_A


def test_pad_mismatch_with_right_id_is_mismatch():
    o = classify(rec(child_output=f"RACEPROOF_ID=A PID=1\nRACEPROOF_PAD={PAD_X}"), approved_pad=PAD_A)
    assert o.primary == MISMATCH and o.launched_id == "A" and o.launched_pad == PAD_X


def test_pad_ignored_when_not_supplied():
    o = classify(rec(child_output=f"RACEPROOF_ID=A PID=1\nRACEPROOF_PAD={PAD_X}"))
    assert o.primary == CORRECT


def test_missing_pad_line_with_expected_pad_is_mismatch():
    o = classify(rec(child_output="RACEPROOF_ID=A PID=1"), approved_pad=PAD_A)
    assert o.primary == MISMATCH and o.launched_pad is None


def test_broker_error_is_exec_error_never_reject():
    o = classify(rec(decision="ERROR", exec_errno=2, child_output=""))
    assert o.primary == EXEC_ERROR and o.flags["broker_error"] is True
    assert o.primary != REJECT


def test_etxtbsy_flag_from_exec_errno():
    o = classify(rec(exec_errno=26, child_output=""))
    assert o.primary == EXEC_ERROR and o.flags["etxtbsy"] is True


def test_etxtbsy_flag_not_set_for_other_errno():
    assert not classify(rec(exec_errno=8, child_output="")).flags["etxtbsy"]


def test_string_fields_from_csv_are_tolerated():
    o = classify(rec(exec_errno="0", signal="0", torn="1", policy="sealed"))
    assert o.primary == CORRECT and o.flags["torn"] is True


def test_unknown_decision_raises():
    import pytest
    with pytest.raises(ValueError):
        classify(rec(decision="MAYBE"))
