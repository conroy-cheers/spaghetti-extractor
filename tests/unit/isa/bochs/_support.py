import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import sys
import tempfile
import textwrap
import unittest

from spaghetti_extractor.isa.conformance import (
    ISAConformanceError,
    ObservationStatus,
    ReportQualification,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa.conformance_bochs import (
    BOCHS_BACKEND_ID,
    BOCHS_MACHINE_FORMAT,
    BOCHS_RESULT_FORMAT,
    run_bochs_corpus,
)


GPRS = {
    "eax": 1,
    "ebx": 2,
    "ecx": 3,
    "edx": 4,
    "esi": 5,
    "edi": 6,
    "ebp": 0x70001000,
    "esp": 0x70000FF0,
}

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SOURCE_BOCHS_RUNNER = (
    _REPO_ROOT / "tools/bochs-conformance/spaghetti-bochs-conformance-runner"
)
_CONFIGURED_BOCHS_RUNNER = os.environ.get("SPAGHETTI_BOCHS_INTEGRATION_RUNNER")
_NIX_BOCHS_RUNNER = shutil.which("spaghetti-bochs-conformance-runner")
if _CONFIGURED_BOCHS_RUNNER:
    _REAL_BOCHS_RUNNER = Path(_CONFIGURED_BOCHS_RUNNER)
elif _NIX_BOCHS_RUNNER:
    _REAL_BOCHS_RUNNER = Path(_NIX_BOCHS_RUNNER)
elif (
    (_REPO_ROOT / "tools/bochs-conformance/build/source/bochs").is_file()
    and (_REPO_ROOT / "tools/bochs-conformance/build/guest/guest.img").is_file()
):
    _REAL_BOCHS_RUNNER = _SOURCE_BOCHS_RUNNER
else:
    _REAL_BOCHS_RUNNER = None


def _x87(*, mask=False):
    fill = 0xFF if mask else 0
    return {
        "control_word": 0xFFFF if mask else 0x037F,
        "status_word": 0xFFFF if mask else 0,
        "tag_word": 0xFFFF,
        "last_opcode": 0x7FF if mask else 0,
        "instruction_pointer": 0xFFFFFFFF if mask else 0,
        "data_pointer": 0xFFFFFFFF if mask else 0,
        "registers": [[fill] * 10 for _ in range(8)],
    }


def _state(*, eip=0x00401000):
    return {
        "gprs": dict(GPRS),
        "eip": eip,
        "eflags": 0x202,
        "fs": {"selector": 0x3B, "base": 0x7FFDF000},
        "x87": _x87(),
    }


def _case(case_id):
    expected_state = _state(eip=0x00401001)
    expected_state["gprs"]["eax"] = 2
    return {
        "id": case_id,
        "instruction_bytes": [0x40],
        "profile": {
            "architecture": "x86",
            "cpu": "i686",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": ["x87"],
        },
        "image_base": 0x00400000,
        "initial_state": _state(),
        "memory": [
            {"address": 0x1000, "bytes": [0x10, 0x20], "permissions": "rw"}
        ],
        "defined_outputs": {
            "gprs": {register: 0xFFFFFFFF for register in GPRS},
            "eip": 0xFFFFFFFF,
            "eflags": 0x8D5,
            "fs": {"selector": 0xFFFF, "base": 0xFFFFFFFF},
            "x87": _x87(mask=True),
            "memory": [{"address": 0x1000, "mask": [0xFF, 0xFF]}],
        },
        "expected": {
            "final_state": expected_state,
            "memory": [{"address": 0x1000, "bytes": [0x10, 0x20]}],
            "control": "fallthrough",
            "fault": "none",
        },
    }


def _corpus(*case_ids):
    return parse_isa_conformance_corpus(
        {
            "format": "stage-a-isa-conformance-corpus-v1",
            "id": "bochs-fixture-corpus-v1",
            "cases": [_case(case_id) for case_id in case_ids],
        }
    )


def _zero_x87_mask():
    return {
        "control_word": 0,
        "status_word": 0,
        "tag_word": 0,
        "last_opcode": 0,
        "instruction_pointer": 0,
        "data_pointer": 0,
        "registers": [[0] * 10 for _ in range(8)],
    }


def _bochs_case(
    case_id,
    instruction_bytes,
    *,
    expected_gprs=None,
    expected_eflags=0x202,
    defined_gprs=(),
    defined_eflags=0,
    initial_gprs=None,
    initial_eflags=0x202,
    memory=None,
    expected_memory=None,
    defined_memory=None,
    expected_control="fallthrough",
    expected_fault="none",
    expected_eip=None,
    initial_fs=None,
    expected_fs=None,
    defined_fs=False,
    initial_x87=None,
    expected_x87=None,
    defined_x87=None,
    profile_features=(),
):
    initial = {
        "gprs": {
            "eax": 0x00006000,
            "ebx": 0x55667788,
            "ecx": 0x99AABBCC,
            "edx": 0x00000080,
            "esi": 0x01020304,
            "edi": 0x05060708,
            "ebp": 0x00008F00,
            "esp": 0x00008E00,
        },
        "eip": 0x00401000,
        "eflags": initial_eflags,
        "fs": json.loads(
            json.dumps(initial_fs or {"selector": 0, "base": 0})
        ),
        "x87": json.loads(json.dumps(initial_x87 or _x87())),
    }
    initial["gprs"].update(initial_gprs or {})
    final = json.loads(json.dumps(initial))
    final["eip"] = (
        (
            initial["eip"]
            if expected_fault != "none"
            else initial["eip"] + len(instruction_bytes)
        )
        if expected_eip is None
        else expected_eip
    )
    final["eflags"] = expected_eflags
    final["gprs"].update(expected_gprs or {})
    final["fs"] = json.loads(json.dumps(expected_fs or initial["fs"]))
    final["x87"] = json.loads(json.dumps(expected_x87 or initial["x87"]))
    return {
        "id": case_id,
        "instruction_bytes": instruction_bytes,
        "profile": {
            "architecture": "x86",
            "cpu": "haswell",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": list(profile_features),
        },
        "image_base": 0x00400000,
        "initial_state": initial,
        "memory": memory or [],
        "defined_outputs": {
            "gprs": {
                register: 0xFFFFFFFF if register in defined_gprs else 0
                for register in GPRS
            },
            "eip": 0xFFFFFFFF,
            "eflags": defined_eflags,
            "fs": {
                "selector": 0xFFFF if defined_fs else 0,
                "base": 0xFFFFFFFF if defined_fs else 0,
            },
            "x87": json.loads(json.dumps(defined_x87 or _zero_x87_mask())),
            "memory": defined_memory or [],
        },
        "expected": {
            "final_state": final,
            "memory": expected_memory or [],
            "control": "fault" if expected_fault != "none" else expected_control,
            "fault": expected_fault,
        },
    }


def _private_x87_text(x87):
    return ":".join(
        [
            f"{x87['control_word']:04x}",
            f"{x87['status_word']:04x}",
            f"{x87['tag_word']:04x}",
            f"{x87['last_opcode']:04x}",
            f"{x87['instruction_pointer']:08x}",
            f"{x87['data_pointer']:08x}",
            *(bytes(register).hex() for register in x87["registers"]),
        ]
    )


def _write_runner(directory: Path, body: str) -> Path:
    path = directory / "fake-bochs-runner"
    path.write_text(
        f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


_RUNNER_PREAMBLE = f"""
import hashlib
import json
import sys

MACHINE_FORMAT = {BOCHS_MACHINE_FORMAT!r}
RESULT_FORMAT = {BOCHS_RESULT_FORMAT!r}
BACKEND_ID = {BOCHS_BACKEND_ID!r}

raw = sys.stdin.buffer.read()
corpus = json.loads(raw)
canonical = (json.dumps(corpus, sort_keys=True, separators=(",", ":")) + "\\n").encode("ascii")
if raw != canonical:
    raise SystemExit("input was not canonical corpus JSON")

def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))

def terminal(statuses):
    emit({{
        "format": RESULT_FORMAT,
        "corpus_id": corpus["id"],
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "backend": {{"id": BACKEND_ID, "kind": "emulator", "version": "2.8.1-test"}},
        "case_ids": [case["id"] for case in corpus["cases"]],
        "counts": {{
            "cases": len(statuses),
            "complete": statuses.count("complete"),
            "unsupported": statuses.count("unsupported"),
            "errors": statuses.count("error"),
        }},
    }})
"""


__all__ = tuple(name for name in globals() if not name.startswith("__"))
