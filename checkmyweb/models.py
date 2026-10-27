from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    PASS = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def ko(self) -> str:
        return _KO[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.upper()]


_KO = {
    Severity.PASS: "양호",
    Severity.INFO: "정보",
    Severity.LOW: "낮음",
    Severity.MEDIUM: "보통",
    Severity.HIGH: "높음",
    Severity.CRITICAL: "심각",
}

# Points subtracted from 100 for each finding of the given severity.
PENALTY = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
}
# Upper bound on the points one check category can take, so a single area
# (e.g. six missing headers) does not drown out everything else.
CHECK_PENALTY_CAP = 40


@dataclass
class Finding:
    check: str
    id: str
    severity: Severity
    title: str
    detail: str = ""
    evidence: str = ""
    fix: str = ""
    refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "id": self.id,
            "severity": self.severity.label,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "fix": self.fix,
            "refs": list(self.refs),
        }


@dataclass
class CheckRun:
    name: str
    title: str
    duration: float = 0.0
    error: str | None = None
    skipped: str | None = None  # why the check did not run (e.g. ownership not verified)


@dataclass
class ScanResult:
    target: str
    started: str
    url: str = ""
    finished: str = ""
    duration: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckRun] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def counts(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def score(self) -> int:
        per_check: dict[str, int] = {}
        for f in self.findings:
            per_check[f.check] = per_check.get(f.check, 0) + PENALTY.get(f.severity, 0)
        return max(0, 100 - sum(min(p, CHECK_PENALTY_CAP) for p in per_check.values()))

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 65:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"
        # A single critical exposure outweighs any amount of good hygiene.
        if self.counts()[Severity.CRITICAL] and grade in "ABC":
            grade = "D"
        return grade

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.PASS)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "url": self.url,
            "started": self.started,
            "finished": self.finished,
            "duration": round(self.duration, 2),
            "score": self.score,
            "grade": self.grade,
            "counts": {s.label: n for s, n in self.counts().items()},
            "meta": self.meta,
            "checks": [
                {"name": c.name, "title": c.title, "duration": round(c.duration, 2),
                 "error": c.error, "skipped": c.skipped}
                for c in self.checks
            ],
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        """Rebuild a result from its JSON report (score and grade are recomputed)."""
        return cls(
            target=data["target"],
            url=data.get("url", ""),
            started=data.get("started", ""),
            finished=data.get("finished", ""),
            duration=data.get("duration", 0.0),
            meta=data.get("meta", {}),
            checks=[CheckRun(c["name"], c["title"], c.get("duration", 0.0), c.get("error"), c.get("skipped"))
                    for c in data.get("checks", [])],
            findings=[Finding(f["check"], f["id"], Severity.parse(f["severity"]), f["title"], f.get("detail", ""),
                              f.get("evidence", ""), f.get("fix", ""), list(f.get("refs", [])))
                      for f in data.get("findings", [])],
        )
