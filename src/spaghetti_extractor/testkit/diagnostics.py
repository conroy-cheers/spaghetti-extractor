"""Actionable diagnostics shared by the test/developer framework."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True, order=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    location: str | None = None
    remediation: str | None = None
    example: str | None = None

    def as_dict(self) -> dict[str, str]:
        row = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.location is not None:
            row["location"] = self.location
        if self.remediation is not None:
            row["remediation"] = self.remediation
        if self.example is not None:
            row["example"] = self.example
        return row

    def render(self) -> str:
        location = f"{self.location}: " if self.location else ""
        lines = [f"{location}{self.severity}[{self.code}]: {self.message}"]
        if self.remediation:
            lines.append(f"  fix: {self.remediation}")
        if self.example:
            lines.append(f"  example: {self.example}")
        return "\n".join(lines)


class TestkitError(ValueError):
    """Raised for invalid inputs with a supported-path remediation."""

    def __init__(self, *diagnostics: Diagnostic):
        if not diagnostics:
            raise ValueError("TestkitError requires at least one diagnostic")
        self.diagnostics = tuple(sorted(diagnostics))
        super().__init__("\n".join(item.render() for item in self.diagnostics))


def fail_on_errors(diagnostics: Iterable[Diagnostic]) -> tuple[Diagnostic, ...]:
    ordered = tuple(sorted(diagnostics))
    errors = tuple(item for item in ordered if item.severity == "error")
    if errors:
        raise TestkitError(*errors)
    return ordered


__all__ = ["Diagnostic", "TestkitError", "fail_on_errors"]
