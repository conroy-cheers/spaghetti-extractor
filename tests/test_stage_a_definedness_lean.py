from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from spaghetti_extractor.relational.lean.definedness import (
    RELATIONAL_DEFINEDNESS_LEAN_FORMAT,
    relational_definedness_preflight,
    relational_definedness_source,
)


def _row(
    transfer_id: str,
    rva: int,
    target: int | None,
    *,
    flag_writes: list[dict[str, object]] | None = None,
    outcome: dict[str, object] | None = None,
    edge_conditions: list[dict[str, object]] | None = None,
    external_events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if outcome is None:
        outcome = {"kind": "fallthrough", "target_rva": target} if target is not None else {"kind": "return", "value": {"op": "reg", "name": "eax", "width": 32}}
    if edge_conditions is None:
        edge_conditions = [{"condition": {"op": "true"}, "target_rva": target}] if target is not None else []
    external_events = external_events or []
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "expression_model": "stage-a-semantic-ir-v1",
        "id": transfer_id,
        "reachable": True,
        "status": "reimplementable",
        "blocker": None,
        "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
        "register_writes": [],
        "flag_writes": flag_writes or [],
        "memory_events": [],
        "external_events": external_events,
        "ordered_events": [{"family": "external", **event} for event in external_events],
        "faults": [],
        "edge_conditions": edge_conditions,
        "outcome": outcome,
    }


def _machine(path: Path, *, dependent_call: bool = False, cycle: bool = False) -> None:
    source = _row(
        "source",
        0x1000,
        0x1010,
        flag_writes=[{"flag": "cf", "value": {"op": "undefined_flag", "id": "1000:cf", "reason": "architecturally undefined"}}],
    )
    if cycle:
        rows = [source, _row("loop-a", 0x1010, 0x1020), _row("loop-b", 0x1020, 0x1010)]
    else:
        event = {
            "kind": "external_call",
            "arguments": [{"value": {"op": "flag", "name": "cf"} if dependent_call else {"op": "reg", "name": "eax", "width": 32}}],
            "read_footprints": [],
        }
        rows = [
            source,
            _row("call", 0x1010, 0x1020, external_events=[event], flag_writes=[{"flag": "cf", "value": {"op": "false"}}]),
            _row("after", 0x1020, None),
        ]
    path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")


def _bsr_machine(path: Path) -> None:
    undefined = {
        "op": "undefined_bv",
        "id": "1000:eax",
        "reason": "bsr-zero-source",
        "width": 32,
        "defined_value": {
            "op": "reg",
            "name": "eax",
            "width": 32,
        },
    }
    source = _row(
        "source",
        0x1000,
        0x1010,
        flag_writes=[],
    )
    source["register_writes"] = [{
        "register": "eax",
        "value": {
            "op": "ite",
            "args": [
                {"op": "eq", "args": [
                    {"op": "reg", "name": "ecx", "width": 32},
                    {"op": "const", "value": 0, "width": 32},
                ]},
                undefined,
                {"op": "bsr_index", "args": [
                    32, {"op": "reg", "name": "ecx", "width": 32},
                ]},
            ],
        },
    }]
    source["instructions"] = [{
        "rva": 0x1000,
        "size": 3,
        "bytes": "0fbdc1",
        "mnemonic": "bsr",
        "op_str": "eax, ecx",
    }]
    terminal = _row(
        "terminal",
        0x1010,
        None,
        outcome={
            "kind": "terminate",
            "exit_code": {"op": "reg", "name": "eax", "width": 32},
        },
    )
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in (source, terminal)
        ),
        encoding="utf-8",
    )


def test_generator_emits_checked_dependency_graph(tmp_path: Path) -> None:
    machine = tmp_path / "machine.jsonl"
    _machine(machine, cycle=True)
    preflight = relational_definedness_preflight(machine)
    source = relational_definedness_source(machine)
    assert preflight["format"] == RELATIONAL_DEFINEDNESS_LEAN_FORMAT
    assert preflight["status"] == "incomplete"
    assert preflight["proof_authority"] is False
    assert preflight["acceptance_constructible"] is False
    assert preflight["counts"] == {
        "undefined_slots": 1,
        "lean_certificates": 1,
        "unknown_frontiers": 0,
        "unresolved_acceptance_slots": 1,
        "semantic_obligation_slots": 0,
        "semantic_obligation_records": 0,
        "input_derived_slots": 0,
        "synchronized_slots": 0,
    }
    assert "def definednessCertificate0 : DefinednessCertificate" in source
    assert "theorem definednessCertificate0Checked" in source
    assert 'key := "loop-a|flag:cf|frames:"' in source
    assert "dependencies := { locations := [], slot := true }" in source
    assert "policy := .arbitrary" in source
    assert "def stepDependencySoundObligations" in source
    assert "def acceptanceObligations" in source
    assert "theorem generatedDefinednessAcceptanceClosedFromBindings" in source
    assert 'successor := "loop-a|flag:cf|frames:"' in source
    for marker in ("sorry", "axiom", "unsafe"):
        assert re.search(rf"\b{marker}\b", source) is None


def test_dependent_call_without_a_choice_derivation_fails_closed(tmp_path: Path) -> None:
    machine = tmp_path / "machine.jsonl"
    _machine(machine, dependent_call=True)
    preflight = relational_definedness_preflight(machine)
    source = relational_definedness_source(machine)
    assert preflight["status"] == "violated"
    assert preflight["counts"]["lean_certificates"] == 0
    assert preflight["counts"]["unknown_frontiers"] == 1
    assert preflight["counts"]["synchronized_slots"] == 0
    frontier = preflight["frontiers"][0]
    assert frontier["witness_policy"] is None
    assert frontier["behavior_relevant_sites"][0]["category"] == "call_argument_dependency"
    assert frontier["behavior_relevant_sites"][0]["json_pointer"] == "/external_events/0"
    assert "def definednessCertificate0" not in source


def test_bsr_choice_emits_exact_related_input_source(tmp_path: Path) -> None:
    machine = tmp_path / "machine.jsonl"
    _bsr_machine(machine)
    preflight = relational_definedness_preflight(machine)
    source = relational_definedness_source(machine)
    assert preflight["counts"]["synchronized_slots"] == 1
    assert "policy := .synchronized" in source
    assert "choiceSource := .relatedMachineInput" in source
    assert "location := .eax" in source
    assert "instructionRva := 4096" in source
    assert "instructionBytes := [15, 189, 193]" in source


@pytest.mark.skipif(shutil.which("lean") is None, reason="Lean is required")
def test_kernel_generated_graph_and_negative_mutations_are_lean_checked(tmp_path: Path) -> None:
    machine = tmp_path / "machine.jsonl"
    _machine(machine, cycle=True)
    stage_a = tmp_path / "StageA"
    stage_a.mkdir()
    source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
    shutil.copyfile(source_root / "X87.lean", stage_a / "X87.lean")
    shutil.copyfile(source_root / "Formal.lean", stage_a / "Formal.lean")
    shutil.copyfile(
        source_root / "RelationalDefinedness.lean",
        stage_a / "RelationalDefinedness.lean",
    )
    (stage_a / "GeneratedDefinedness.lean").write_text(relational_definedness_source(machine), encoding="utf-8")
    (stage_a / "DefinednessKernelFixture.lean").write_text(_LEAN_FIXTURE, encoding="utf-8")
    environment = dict(os.environ)
    environment["LEAN_PATH"] = str(tmp_path)
    output = ""
    for module in (
        "X87",
        "Formal",
        "RelationalDefinedness",
        "GeneratedDefinedness",
        "DefinednessKernelFixture",
    ):
        result = subprocess.run(
            ["lean", "-o", f"StageA/{module}.olean", f"StageA/{module}.lean"],
            cwd=tmp_path,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        output += result.stdout
        assert result.returncode == 0, output
    assert "sorryAx" not in output


_LEAN_FIXTURE = r"""import StageA.GeneratedDefinedness

namespace StageA.DefinednessKernelFixture

open StageA.Relational.Definedness
open StageA.GeneratedDefinedness

example : definednessCertificate0.checked = true :=
  definednessCertificate0Checked

def dependentObservation : CertifiedNode := {
  key := "bad"
  step := {
    id := "bad"
    writes := []
    observations := [{
      kind := "call"
      dependencies := { locations := [], slot := true }
    }]
    edges := []
    terminal := .terminate
  }
  liveIn := []
  liveOut := []
}

example : dependentObservation.localChecked .arbitrary = false := by native_decide

example : dependentObservation.localChecked .synchronized = true := by native_decide

example : ¬ SlotPolicy.valuesRelated .synchronized 1 2 := by
  simp [SlotPolicy.valuesRelated]

def inertTransition : StepTransition := fun _ _ _ => {
  machine := fun _ => 0
  observations := []
  successor := none
  terminated := false
}

theorem inertTransitionSound (policy : SlotPolicy) (step : FlowStep) :
    StepDependencySound policy step inertTransition := by
  intro live slotLeft slotRight left right choices observations guards agreement
  simp [inertTransition, AgreeOutside]

def emptyPe : StageA.Formal.PE32 := {
  bytes := .ofBytes []
  peOffset := 0
  entrypointRva := 0
  imageBase := 0
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 0
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

example : definednessCertificate0.AcceptanceClosed
    (fun _ _ => 7) (fun _ _ => 0) (fun _ _ => 0) inertTransition
      emptyPe := by
  exact {
    checked := definednessCertificate0Checked
    choiceInstruction := trivial
    choice := {
      sourceChecked := rfl
      runtimeRealized := by intro input; rfl
      candidateRealized := by intro input; rfl
      originalSynchronized := by
        intro impossible
        simp [definednessCertificate0] at impossible
    }
    semantics := {
      localSound := by
        intro graph graphMember node nodeMember
        exact inertTransitionSound definednessCertificate0.policy node.step
    }
  }

def brokenCycle : GraphCertificate := {
  roots := ["a"]
  nodes := [{
    key := "a"
    step := {
      id := "a"
      writes := []
      observations := []
      edges := [{ successor := "b", guard := { locations := [], slot := false } }]
      terminal := .none
    }
    liveIn := [.cf]
    liveOut := [.cf]
  }, {
    key := "b"
    step := {
      id := "b"
      writes := []
      observations := []
      edges := [{ successor := "a", guard := { locations := [], slot := false } }]
      terminal := .none
    }
    liveIn := []
    liveOut := []
  }]
}

example : brokenCycle.checked .arbitrary = false := by native_decide

#print axioms CertifiedNode.checked_noninterference
#print axioms GraphCertificate.checked_edge_relation
#print axioms DefinednessCertificate.checked_noninterference

end StageA.DefinednessKernelFixture
"""
