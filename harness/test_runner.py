"""Tests for the runner's own guarantees: what it refuses to count and what it refuses to append.

None of these start the broker or the updater; the trial itself is replaced by a stub.
"""
import csv

import pytest

import run_trials as rt

CONFIG_ROW = dict(policy="path", change="replace", stage="post_hash", region="", tear="", size="64k", load="idle")
BROKER_OK = {"policy": "path", "decision": "APPROVE", "exec_errno": 0, "signal": 0, "exit_status": 0,
             "child_output": "RACEPROOF_ID=A PID=42", "torn": 0, "hash_impl": "vendored-c"}


class StubTrial:
    def __init__(self, *args, **kwargs):
        self.lay = {"pad": None}


class StubStress:
    def check(self):
        pass


def updater(writes=1, etxtbsy=0, errors=0):
    return {"summary": False, "writes": writes, "etxtbsy": etxtbsy, "errors": errors, "last_errno": "", "last_t_us": 0}


def run_one_controlled(tmp_path, monkeypatch, upd):
    monkeypatch.setattr(rt, "Trial", StubTrial)
    monkeypatch.setattr(rt, "controlled_configs", lambda *a: iter([dict(CONFIG_ROW)]))
    monkeypatch.setattr(rt, "controlled_trial", lambda t, c, tear: (dict(BROKER_OK), upd, ""))
    out = tmp_path / "c.csv"
    w = rt.Writer(out, "t1", "rev", "controlled")
    rt.run_controlled(rt.CONFIG, tmp_path, {}, w, ["64k"], ["idle"], ["tail"], 1, StubStress())
    w.close()
    return list(csv.DictReader(out.open(newline="")))


def test_parse_updater_reads_the_summary_line():
    info = rt.parse_updater('{"summary":1,"writes":7,"etxtbsy":2,"errors":0,"run_us":900}\n')
    assert info["summary"] is True and info["writes"] == 7 and info["etxtbsy"] == 2 and info["errors"] == 0


def test_parse_updater_without_summary_counts_write_lines():
    text = '{"action":"rename","errno":0,"t_us":5}\n{"action":"pwrite","errno":26,"t_us":9}\n{"action":"pwrite","errno":5,"t_us":11}\n'
    info = rt.parse_updater(text)
    assert info["summary"] is False and info["writes"] == 3 and info["etxtbsy"] == 1 and info["errors"] == 1


def test_parse_updater_of_nothing_reports_no_writes():
    info = rt.parse_updater("")
    assert info["summary"] is False and info["writes"] == 0


def test_delivered_attack_is_classified(tmp_path, monkeypatch):
    rows = run_one_controlled(tmp_path, monkeypatch, updater(writes=1))
    assert len(rows) == 1
    assert rows[0]["outcome"] == "CORRECT" and rows[0]["attack_landed"] == "1" and rows[0]["attempt"] == "1"


def test_attack_with_no_logged_write_is_not_counted(tmp_path, monkeypatch):
    rows = run_one_controlled(tmp_path, monkeypatch, updater(writes=0))
    assert [r["outcome"] for r in rows] == [rt.HARNESS_ERROR] * 3
    assert all("attack not delivered" in r["harness_note"] for r in rows)


def test_attack_with_unexpected_write_error_is_not_counted(tmp_path, monkeypatch):
    rows = run_one_controlled(tmp_path, monkeypatch, updater(writes=1, errors=1))
    assert [r["outcome"] for r in rows] == [rt.HARNESS_ERROR] * 3


def test_etxtbsy_is_a_result_not_a_harness_error(tmp_path, monkeypatch):
    rows = run_one_controlled(tmp_path, monkeypatch, updater(writes=1, etxtbsy=1))
    assert len(rows) == 1
    assert rows[0]["outcome"] == "CORRECT" and rows[0]["attack_landed"] == "0" and rows[0]["etxtbsy"] == "1"


def test_writer_refuses_to_append_the_same_run_and_matrix(tmp_path):
    out = tmp_path / "r.csv"
    w = rt.Writer(out, "run9", "rev", "overhead")
    w.row(dict(matrix="overhead", policy="path", rep=0, attempt=1), dict(BROKER_OK), None)
    w.close()
    with pytest.raises(SystemExit) as e:
        rt.Writer(out, "run9", "rev", "overhead")
    assert "already holds run" in str(e.value)


def test_writer_appends_a_different_run_or_matrix(tmp_path):
    out = tmp_path / "r.csv"
    w = rt.Writer(out, "run9", "rev", "overhead")
    w.row(dict(matrix="overhead", policy="path", rep=0, attempt=1), dict(BROKER_OK), None)
    w.close()
    rt.Writer(out, "run10", "rev", "overhead").close()
    rt.Writer(out, "run9", "rev", "controlled").close()


def test_writer_refuses_a_mismatched_header(tmp_path):
    out = tmp_path / "old.csv"
    out.write_text("policy,outcome\npath,CORRECT\n")
    with pytest.raises(SystemExit) as e:
        rt.Writer(out, "run9", "rev", "overhead")
    assert "different header" in str(e.value)
