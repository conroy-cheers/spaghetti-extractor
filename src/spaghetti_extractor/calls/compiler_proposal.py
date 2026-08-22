"""Pinned-compiler call-lowering proposals.

Compiler output is deliberately retained as evidence only.  The IA-32 dialect
checker and machine observations authorize a frame independently.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.formats import CALL_PROTOCOL_PROPOSAL_V1_FORMAT
from ._canonical import CallProtocolError, array, content_id, exact, identifier, object_, text


_LLVM_ABI_ATTRIBUTE = re.compile(r"\b(sret|byval|inreg|signext|zeroext|inalloca|preallocated)\b(?:\([^)]*\))?")


@dataclass(frozen=True)
class CompilerCallProposalV1:
    proposal_id: str
    producer: str
    compiler_path: str
    compiler_version: str
    target: str
    abi_dialect: str
    declaration: str
    source_sha256: str
    ast_sha256: str
    llvm_ir_sha256: str
    lowering_attributes: tuple[str, ...]
    command_lines: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        producer: str,
        compiler_path: str,
        compiler_version: str,
        target: str,
        abi_dialect: str,
        declaration: str,
        source_sha256: str,
        ast_sha256: str,
        llvm_ir_sha256: str,
        lowering_attributes: Sequence[str],
        command_lines: Sequence[str],
    ) -> "CompilerCallProposalV1":
        attributes = tuple(sorted(set(identifier(item, "compiler ABI attribute") for item in lowering_attributes)))
        commands = tuple(text(item, "compiler proposal command") for item in command_lines)
        core = {
            "format": CALL_PROTOCOL_PROPOSAL_V1_FORMAT,
            "authority": "proposal-only",
            "producer": identifier(producer, "compiler proposal producer"),
            "compiler_path": text(compiler_path, "compiler path"),
            "compiler_version": text(compiler_version, "compiler version"),
            "target": identifier(target, "compiler proposal target"),
            "abi_dialect": identifier(abi_dialect, "compiler proposal ABI dialect"),
            "declaration": identifier(declaration, "compiler proposal declaration"),
            "source_sha256": _sha(source_sha256, "source digest"),
            "ast_sha256": _sha(ast_sha256, "AST digest"),
            "llvm_ir_sha256": _sha(llvm_ir_sha256, "LLVM IR digest"),
            "lowering_attributes": list(attributes),
            "command_lines": list(commands),
        }
        return cls(content_id("call-protocol-proposal-v1", core), str(core["producer"]), str(core["compiler_path"]), str(core["compiler_version"]), str(core["target"]), str(core["abi_dialect"]), str(core["declaration"]), str(core["source_sha256"]), str(core["ast_sha256"]), str(core["llvm_ir_sha256"]), attributes, commands)

    @classmethod
    def parse(cls, value: object) -> "CompilerCallProposalV1":
        row = object_(value, "compiler call proposal")
        exact(row, {"format", "id", "authority", "producer", "compiler_path", "compiler_version", "target", "abi_dialect", "declaration", "source_sha256", "ast_sha256", "llvm_ir_sha256", "lowering_attributes", "command_lines"}, "compiler call proposal")
        if row["format"] != CALL_PROTOCOL_PROPOSAL_V1_FORMAT or row["authority"] != "proposal-only":
            raise CallProtocolError("unsupported or authorizing compiler call proposal")
        result = cls.create(producer=str(row["producer"]), compiler_path=str(row["compiler_path"]), compiler_version=str(row["compiler_version"]), target=str(row["target"]), abi_dialect=str(row["abi_dialect"]), declaration=str(row["declaration"]), source_sha256=str(row["source_sha256"]), ast_sha256=str(row["ast_sha256"]), llvm_ir_sha256=str(row["llvm_ir_sha256"]), lowering_attributes=[str(item) for item in array(row["lowering_attributes"], "compiler lowering attributes")], command_lines=[str(item) for item in array(row["command_lines"], "compiler commands")])
        if row["id"] != result.proposal_id:
            raise CallProtocolError("compiler call proposal id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CALL_PROTOCOL_PROPOSAL_V1_FORMAT,
            "id": self.proposal_id,
            "authority": "proposal-only",
            "producer": self.producer,
            "compiler_path": self.compiler_path,
            "compiler_version": self.compiler_version,
            "target": self.target,
            "abi_dialect": self.abi_dialect,
            "declaration": self.declaration,
            "source_sha256": self.source_sha256,
            "ast_sha256": self.ast_sha256,
            "llvm_ir_sha256": self.llvm_ir_sha256,
            "lowering_attributes": list(self.lowering_attributes),
            "command_lines": list(self.command_lines),
        }


def run_clang_call_proposal(
    *,
    compiler: Path | str,
    source: Path | str,
    declaration: str,
    abi_dialect: str,
    include_paths: Sequence[Path | str] = (),
    extra_flags: Sequence[str] = (),
) -> CompilerCallProposalV1:
    compiler_path = str(Path(compiler).resolve())
    source_path = Path(source).resolve()
    source_bytes = source_path.read_bytes()
    target = {
        "pe32-i386-gnu-v1": "i686-w64-windows-gnu",
        "pe32-i386-ms-v1": "i686-pc-windows-msvc",
    }.get(abi_dialect)
    if target is None:
        raise CallProtocolError(f"compiler proposal ABI dialect {abi_dialect!r} is unsupported")
    includes = [flag for path in include_paths for flag in ("-I", str(Path(path).resolve()))]
    common = [compiler_path, f"--target={target}", *includes, *extra_flags, str(source_path)]
    ast_command = [*common, "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", f"-ast-dump-filter={declaration}"]
    ir_command = [*common, "-S", "-emit-llvm", "-o", "-"]
    version = _run([compiler_path, "--version"]).splitlines()[0]
    ast = _run(ast_command)
    try:
        parsed_ast = json.loads(ast)
    except json.JSONDecodeError as exc:
        raise CallProtocolError("Clang did not emit a JSON declaration proposal") from exc
    if not _ast_names_declaration(parsed_ast, declaration):
        raise CallProtocolError(f"Clang AST proposal omits declaration {declaration!r}")
    llvm_ir = _run(ir_command)
    attributes = tuple(sorted(set(match.group(1) for match in _LLVM_ABI_ATTRIBUTE.finditer(llvm_ir))))
    return CompilerCallProposalV1.create(
        producer="clang-call-proposal-v1",
        compiler_path=compiler_path,
        compiler_version=version,
        target=target,
        abi_dialect=abi_dialect,
        declaration=declaration,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        ast_sha256=hashlib.sha256(ast.encode("utf-8")).hexdigest(),
        llvm_ir_sha256=hashlib.sha256(llvm_ir.encode("utf-8")).hexdigest(),
        lowering_attributes=attributes,
        command_lines=(" ".join(ast_command), " ".join(ir_command)),
    )


def _run(command: Sequence[str]) -> str:
    completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip()
        raise CallProtocolError(f"compiler proposal command failed: {diagnostic}")
    return completed.stdout


def _ast_names_declaration(value: object, declaration: str) -> bool:
    if isinstance(value, Mapping):
        if value.get("name") == declaration:
            return True
        return any(_ast_names_declaration(item, declaration) for item in value.values())
    if isinstance(value, list):
        return any(_ast_names_declaration(item, declaration) for item in value)
    return False


def _sha(value: object, context: str) -> str:
    result = text(value, context)
    if re.fullmatch(r"[0-9a-f]{64}", result) is None:
        raise CallProtocolError(f"{context} must be a lowercase SHA-256")
    return result


__all__ = ["CompilerCallProposalV1", "run_clang_call_proposal"]
