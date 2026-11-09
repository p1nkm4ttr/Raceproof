"""Outcome taxonomy for RaceProof trials.

Each trial produces one JSON record from the broker. This module turns that record
into exactly one primary outcome plus independent secondary flags. The order of the
checks is the definition; do not reorder it.

Primary outcomes (first match wins):
  REJECT      broker computed a hash not on the allowlist (or the content was not an
              ELF) and did not exec. Only a validation failure counts; a broker-side
              failure (open, read, memfd, seal) is decision ERROR and never a REJECT.
  EXEC_ERROR  broker reported ERROR before launching, or approved and called exec but
              exec returned an error, or the child died by signal, or no ID line came back
  MISMATCH    a program ran and what it printed is not the approved program: either
              the ID differs, or the pad hash differs (the file was modified somewhere
              that does not change the ID, for example a tail rewrite)
  CORRECT     the approved program ran: ID and pad hash both match

Secondary flags:
  torn         sealed copy was neither the pre-attack nor the post-attack image
  etxtbsy      this launch's exec was refused with ETXTBSY (file open for writing), or,
               in a controlled trial, the updater's write was refused with ETXTBSY
  unsupported  exec failed because executable memfds are not permitted here
  broker_error the broker itself failed before launching (decision ERROR)
"""

import re
from dataclasses import dataclass, field

REJECT = "REJECT"
EXEC_ERROR = "EXEC_ERROR"
MISMATCH = "MISMATCH"
CORRECT = "CORRECT"
PRIMARY = (REJECT, EXEC_ERROR, MISMATCH, CORRECT)

_ID_RE = re.compile(r"RACEPROOF_ID=(\S)")
_PAD_RE = re.compile(r"RACEPROOF_PAD=([0-9a-f]{16})")


@dataclass
class Outcome:
    primary: str
    launched_id: str | None
    launched_pad: str | None = None
    flags: dict = field(default_factory=dict)

    def as_row(self) -> dict:
        row = {"outcome": self.primary, "launched_id": self.launched_id or "",
               "launched_pad": self.launched_pad or ""}
        row.update({k: int(bool(v)) for k, v in self.flags.items()})
        return row


def launched_id(child_output: str | None) -> str | None:
    """The ID the launched program printed, or None if no ID line was seen."""
    if not child_output:
        return None
    m = _ID_RE.search(child_output)
    return m.group(1) if m else None


def launched_pad(child_output: str | None) -> str | None:
    """The pad hash the launched program printed, or None if absent."""
    if not child_output:
        return None
    m = _PAD_RE.search(child_output)
    return m.group(1) if m else None


def classify(record: dict, approved_id: str = "A", approved_pad: str | None = None,
             etxtbsy: bool = False) -> Outcome:
    """Classify one broker record.

    record: the broker's JSON line as a dict.
    approved_id: the ID printed by the program whose hash is on the allowlist.
    approved_pad: that program's pad hash from fixtures/layout.txt; when given, a
        launched program whose pad hash differs is a MISMATCH even if its ID matches.
    etxtbsy: whether the harness saw the updater's write refused with ETXTBSY.
    """
    decision = record.get("decision")
    errno_ = int(record.get("exec_errno", 0) or 0)
    flags = {
        "torn": bool(int(record.get("torn", 0) or 0)),
        "etxtbsy": bool(etxtbsy) or (decision == "APPROVE" and errno_ == 26),
        "unsupported": decision == "APPROVE" and errno_ == 13 and record.get("policy") == "sealed",
        "broker_error": decision == "ERROR",
    }
    if decision == "REJECT":
        return Outcome(REJECT, None, None, flags)
    if decision == "ERROR":
        return Outcome(EXEC_ERROR, None, None, flags)
    if decision != "APPROVE":
        raise ValueError(f"unknown decision {decision!r}")

    out = record.get("child_output")
    lid, lpad = launched_id(out), launched_pad(out)
    if errno_ != 0 or int(record.get("signal", 0) or 0) != 0 or lid is None:
        return Outcome(EXEC_ERROR, lid, lpad, flags)
    if lid != approved_id:
        return Outcome(MISMATCH, lid, lpad, flags)
    if approved_pad is not None and lpad != approved_pad:
        return Outcome(MISMATCH, lid, lpad, flags)
    return Outcome(CORRECT, lid, lpad, flags)
