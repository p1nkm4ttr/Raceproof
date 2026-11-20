"""The timing check must never report agreement for a comparison it did not make,
and a good file must never stand in for one that failed or was not checked."""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "analysis"))
import hash_rate  # noqa: E402

COLS = ["matrix", "hash_impl", "policy", "size", "load", "outcome", "t_check_us", "bytes_hashed"]
AGREE = "in every idle cell of every file"


def write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    return path


def cell(matrix="overhead", load="idle", size="1m", n=12, us=None, policies=("path", "fd", "sealed")):
    """n launches per policy hashing 1 MiB; us maps a policy to its hash time in microseconds."""
    us = us or {}
    return [dict(matrix=matrix, hash_impl="vendored-c", policy=p, size=size, load=load, outcome="CORRECT",
                 t_check_us=us.get(p, 4000), bytes_hashed=1048576) for p in policies for _ in range(n)]


def test_even_rates_pass(tmp_path, capsys):
    assert hash_rate.check([write(tmp_path / "a.csv", cell())]) == 0
    assert AGREE in capsys.readouterr().out


def test_uneven_overhead_cell_fails(tmp_path, capsys):
    f = write(tmp_path / "a.csv", cell(us={"sealed": 1000}))
    assert hash_rate.check([f]) == 1
    out = capsys.readouterr().out
    assert "UNEVEN" in out and AGREE not in out


def test_uneven_cell_outside_overhead_is_reported_not_failed(tmp_path, capsys):
    f = write(tmp_path / "a.csv", cell(matrix="controlled", us={"sealed": 1000}))
    assert hash_rate.check([f]) == 0
    out = capsys.readouterr().out
    assert "UNEVEN" in out and AGREE not in out


def test_stress_cells_are_not_judged(tmp_path):
    rows = cell() + cell(load="stress", us={"sealed": 1000})
    assert hash_rate.check([write(tmp_path / "a.csv", rows)]) == 0


def test_missing_policy_is_not_agreement(tmp_path, capsys):
    f = write(tmp_path / "a.csv", cell(policies=("path",)))
    assert hash_rate.check([f]) == 2
    out = capsys.readouterr().out
    assert "INCOMPLETE" in out and "NOT CHECKED" in out and AGREE not in out


def test_file_without_hash_timings_is_not_agreement(tmp_path, capsys):
    good = write(tmp_path / "good.csv", cell())
    empty = write(tmp_path / "empty.csv", [])
    assert hash_rate.check([good, empty]) == 2
    out = capsys.readouterr().out
    assert "nothing to compare" in out and AGREE not in out


def test_too_few_launches_are_not_judged(tmp_path, capsys):
    f = write(tmp_path / "a.csv", cell(n=2))
    assert hash_rate.check([f]) == 3
    out = capsys.readouterr().out
    assert "FEW" in out and "NOT JUDGED" in out and AGREE not in out


def test_an_overhead_cell_with_too_few_launches_fails_the_file_even_beside_judged_cells(tmp_path, capsys):
    rows = cell(size="1m") + cell(size="8m", n=2)
    assert hash_rate.check([write(tmp_path / "a.csv", rows)]) == 3
    assert AGREE not in capsys.readouterr().out


def test_few_cells_outside_overhead_are_noted_not_failed(tmp_path, capsys):
    rows = cell(matrix="controlled", size="1m") + cell(matrix="controlled", size="8m", n=2)
    assert hash_rate.check([write(tmp_path / "a.csv", rows)]) == 0
    out = capsys.readouterr().out
    assert "1 more not judged" in out and AGREE not in out


def test_a_good_file_does_not_mask_an_unjudged_overhead_file(tmp_path, capsys):
    few = write(tmp_path / "overhead.csv", cell(n=2))
    good = write(tmp_path / "controlled.csv", cell(matrix="controlled"))
    assert hash_rate.check([few]) == 3
    assert hash_rate.check([few, good]) == 3
    assert hash_rate.check([good, few]) == 3
    assert AGREE not in capsys.readouterr().out


def test_two_files_with_the_same_name_are_judged_separately(tmp_path, capsys):
    bad = write(tmp_path / "first" / "overhead.csv", cell(us={"sealed": 1000}))
    good = write(tmp_path / "second" / "overhead.csv", cell())
    assert hash_rate.check([bad]) == 1
    assert hash_rate.check([bad, good]) == 1
    assert hash_rate.check([good, bad]) == 1
    out = capsys.readouterr().out
    assert str(bad) in out and str(good) in out


def test_the_worst_verdict_wins(tmp_path):
    uneven = write(tmp_path / "u.csv", cell(us={"sealed": 1000}))
    empty = write(tmp_path / "e.csv", [])
    few = write(tmp_path / "f.csv", cell(n=2))
    good = write(tmp_path / "g.csv", cell())
    assert hash_rate.check([good, few]) == 3
    assert hash_rate.check([good, few, empty]) == 2
    assert hash_rate.check([good, few, empty, uneven]) == 1
