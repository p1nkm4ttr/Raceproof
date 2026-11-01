"""Outcome taxonomy for RaceProof trials.

Each trial produces one JSON record from the broker. This module turns that record
into exactly one primary outcome plus independent secondary flags. The order of the
checks is the definition; do not reorder it.

Primary outcomes (first match wins):
  REJECT      broker computed a hash not on the allowlist and did not exec
  EXEC_ERROR  broker approved and called exec, but exec returned an error, or the
              child died by signal, or no ID line came back
  MISMATCH    a program ran and printed an ID that is not the approved one
  CORRECT     the approved program ran and printed its ID

Secondary flags:
  torn        sealed copy was neither all-A nor all-B
  etxtbsy     updater's write was refused with ETXTBSY (set by the harness)
  unsupported exec failed because executable memfds are not permitted here
"""

import re
from dataclasses import dataclass, field

REJECT = "REJECT"
EXEC_ERROR = "EXEC_ERROR"
MISMATCH = "MISMATCH"
CORRECT = "CORRECT"
PRIMARY = (REJECT, EXEC_ERROR, MISMATCH, CORRECT)

_ID_RE = re.compile(r"RACEPROOF_ID=(\S)")


@dataclass
class Outcome:
    primary: str
    launched_id: str | None
    flags: dict = field(default_factory=dict)

    def as_row(self) -> dict:
        row = {"outcome": self.primary, "launched_id": self.launched_id or ""}
        row.update({k: int(bool(v)) for k, v in self.flags.items()})
        return row


def launched_id(child_output: str | None) -> str | None:
    """The ID the launched program printed, or None if no ID line was seen."""
    if not child_output:
        return None
    m = _ID_RE.search(child_output)
    return m.group(1) if m else None


def classify(record: dict, approved_id: str = "A", etxtbsy: bool = False) -> Outcome:
    """Classify one broker record.

    record: the broker's JSON line as a dict.
    approved_id: the ID printed by the program whose hash is on the allowlist.
    etxtbsy: whether the harness saw the updater's write refused with ETXTBSY.
    """
    flags = {
        "torn": bool(record.get("torn", 0)),
        "etxtbsy": bool(etxtbsy),
        "unsupported": record.get("exec_errno", 0) in (13,) and record.get("policy") == "sealed",
    }
    decision = record.get("decision")
    if decision == "REJECT":
        return Outcome(REJECT, None, flags)
    if decision != "APPROVE":
        raise ValueError(f"unknown decision {decision!r}")

    lid = launched_id(record.get("child_output"))
    if record.get("exec_errno", 0) != 0 or record.get("signal", 0) != 0 or lid is None:
        return Outcome(EXEC_ERROR, lid, flags)
    if lid != approved_id:
        return Outcome(MISMATCH, lid, flags)
    return Outcome(CORRECT, lid, flags)
