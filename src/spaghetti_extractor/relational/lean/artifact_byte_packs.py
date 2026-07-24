"""Generate independently cacheable Lean modules for arbitrary exact bytes.

Each payload module owns one bounded byte literal.  A compact aggregate module
combines those Lean-resident shards in order and exports a plain ``Bytes`` value
for consumers such as the compiled-interpreter kernel.  Content hashes and
range equality remain consumer-side Lean obligations; this layer does not turn
Python digests or manifest statuses into proof facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from ...stage_binary import StageAInputError
from ...util import sha256_bytes, sha256_file, write_json


ARTIFACT_BYTE_PACK_FORMAT = "stage-a-relational-artifact-byte-packs-v1"
DEFAULT_ARTIFACT_BYTE_PACK_SIZE = 64 * 1024
DEFAULT_ARTIFACT_BYTE_CHUNK_SIZE = 1024

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_NAMESPACE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$"
)
_STAGE_A_MODULE = re.compile(
    r"^StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$"
)
_LEAN_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


class ArtifactBytePackGenerationError(StageAInputError):
    """An exact artifact pack graph cannot be generated safely."""


@dataclass(frozen=True)
class ExternalArtifactBytesBinding:
    """Validated Lean name of an externally generated exact ``Bytes`` value."""

    module: str
    namespace: str
    bytes_symbol: str

    def __post_init__(self) -> None:
        _validate_stage_a_module(self.module, "artifact data module")
        _validate_namespace(self.namespace)
        _validate_identifier(self.bytes_symbol, "artifact bytes symbol")

    @property
    def qualified_bytes_name(self) -> str:
        return f"{self.namespace}.{self.bytes_symbol}"


@dataclass(frozen=True)
class ArtifactBytePack:
    index: int
    raw_offset: int
    size: int
    sha256: str
    module: str
    value_name: str

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.size

    def payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "raw_offset": self.raw_offset,
            "bytes": self.size,
            "sha256": self.sha256,
            "module": self.module,
            "value_name": self.value_name,
        }


@dataclass(frozen=True)
class ArtifactBytePackInventory:
    source_path: Path
    source_sha256: str
    source_size: int
    module_prefix: str
    namespace: str
    aggregate_module: str
    aggregate_value_name: str
    aggregate_bytes_name: str
    pack_size: int
    chunk_size: int
    packs: tuple[ArtifactBytePack, ...]
    modules: tuple[dict[str, Any], ...]
    standalone_modules: tuple[str, ...]

    @property
    def binding(self) -> ExternalArtifactBytesBinding:
        return ExternalArtifactBytesBinding(
            module=f"StageA.{self.aggregate_module}",
            namespace=self.namespace,
            bytes_symbol=self.aggregate_bytes_name,
        )

    def payload(self) -> dict[str, Any]:
        return {
            "format": ARTIFACT_BYTE_PACK_FORMAT,
            "source_sha256": self.source_sha256,
            "source_bytes": self.source_size,
            "module_prefix": self.module_prefix,
            "namespace": self.namespace,
            "aggregate_module": self.aggregate_module,
            "aggregate_value_name": self.aggregate_value_name,
            "aggregate_bytes_name": self.aggregate_bytes_name,
            "pack_size": self.pack_size,
            "chunk_size": self.chunk_size,
            "packs": [pack.payload() for pack in self.packs],
            "modules": list(self.modules),
            "standalone_modules": list(self.standalone_modules),
            "lean_binding": {
                "module": self.binding.module,
                "namespace": self.binding.namespace,
                "bytes_symbol": self.binding.bytes_symbol,
            },
            "authority": (
                "Lean-resident exact byte shards; artifact identity remains a "
                "consumer-side Lean hash obligation"
            ),
        }


@dataclass(frozen=True)
class _ExpressionTree:
    expression: str


def _validate_identifier(value: str, label: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ArtifactBytePackGenerationError(
            f"{label} is not a Lean identifier: {value!r}"
        )
    return value


def _validate_namespace(value: str) -> str:
    if _NAMESPACE.fullmatch(value) is None:
        raise ArtifactBytePackGenerationError(f"invalid Lean namespace: {value!r}")
    return value


def _validate_stage_a_module(value: str, label: str) -> str:
    if _STAGE_A_MODULE.fullmatch(value) is None:
        raise ArtifactBytePackGenerationError(
            f"{label} must be a qualified StageA Lean module: {value!r}"
        )
    return value


def _definition_prefix(module_prefix: str) -> str:
    return module_prefix[0].lower() + module_prefix[1:]


def _lean_bytes(data: bytes) -> str:
    if not data:
        return "[]"
    rows = [
        ", ".join(str(byte) for byte in data[offset : offset + 32])
        for offset in range(0, len(data), 32)
    ]
    return "[\n  " + ",\n  ".join(rows) + "\n]"


def _balanced_append(expressions: Sequence[str], *, empty: str) -> _ExpressionTree:
    trees = [_ExpressionTree(expression) for expression in expressions]
    if not trees:
        return _ExpressionTree(empty)
    while len(trees) > 1:
        merged: list[_ExpressionTree] = []
        for index in range(0, len(trees), 2):
            if index + 1 == len(trees):
                merged.append(trees[index])
                continue
            left = trees[index]
            right = trees[index + 1]
            merged.append(
                _ExpressionTree(
                    f"({left.expression}).append ({right.expression})"
                )
            )
        trees = merged
    return trees[0]


def _balanced_bytes_append(expressions: Sequence[str]) -> str:
    if not expressions:
        return "[]"
    current = list(expressions)
    while len(current) > 1:
        merged: list[str] = []
        for index in range(0, len(current), 2):
            if index + 1 == len(current):
                merged.append(current[index])
            else:
                merged.append(f"({current[index]} ++ {current[index + 1]})")
        current = merged
    return current[0]


def _write_text_if_changed(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text(encoding="utf-8") == source:
            return
    except FileNotFoundError:
        pass
    path.write_text(source, encoding="utf-8")


def _module_row(name: str, role: str, source: str, **extra: Any) -> dict[str, Any]:
    encoded = source.encode("utf-8")
    return {
        "name": name,
        "role": role,
        "imports": _LEAN_IMPORT.findall(source),
        "source_bytes": len(encoded),
        "source_sha256": sha256_bytes(encoded),
        **extra,
    }


def _copy_kernel_closure(destination: Path) -> tuple[str, ...]:
    source_root = Path(__file__).parents[2] / "lean" / "StageA"
    pending = ["RelationalArtifactBytePacks"]
    copied: set[str] = set()
    while pending:
        module = pending.pop()
        if module in copied:
            continue
        source = source_root / f"{module}.lean"
        if not source.is_file():
            raise ArtifactBytePackGenerationError(
                f"missing Lean kernel module: {source}"
            )
        text = source.read_text(encoding="utf-8")
        _write_text_if_changed(destination / source.name, text)
        copied.add(module)
        pending.extend(_LEAN_IMPORT.findall(text))
    return tuple(sorted(copied))


def _payload_source(
    *, namespace: str, pack: ArtifactBytePack, data: bytes, chunk_size: int
) -> str:
    prefix = pack.value_name
    chunks = [
        data[offset : offset + chunk_size]
        for offset in range(0, len(data), chunk_size)
    ]
    chunk_bytes_names = [
        f"{prefix}Chunk{index:04d}Bytes" for index in range(len(chunks))
    ]
    definitions = [
        f"def {name} : Bytes := {_lean_bytes(chunk)}"
        for name, chunk in zip(chunk_bytes_names, chunks, strict=True)
    ]
    bytes_expression = _balanced_bytes_append(chunk_bytes_names)
    definitions.append(
        f"def {prefix} : ExactArtifactBytes := {{\n"
        f"  bytes := {bytes_expression}\n"
        "}"
    )
    return f"""import StageA.RelationalArtifactBytePacks

namespace {namespace}

open StageA.Formal
open StageA.Relational.ArtifactBytePacks

set_option maxRecDepth 1000000

{chr(10).join(chr(10) + definition for definition in definitions).lstrip()}

end {namespace}
"""


def _aggregate_source(
    *,
    namespace: str,
    packs: Sequence[ArtifactBytePack],
    aggregate_value_name: str,
    aggregate_bytes_name: str,
) -> str:
    imports = "\n".join(
        ["import StageA.RelationalArtifactBytePacks"]
        + [f"import StageA.{pack.module}" for pack in packs]
    )
    tree = _balanced_append(
        [pack.value_name for pack in packs],
        empty="ExactArtifactBytes.empty",
    )
    return f"""{imports}

namespace {namespace}

open StageA.Formal
open StageA.Relational.ArtifactBytePacks

def {aggregate_value_name} : ExactArtifactBytes :=
  {tree.expression}

def {aggregate_bytes_name} : Bytes :=
  {aggregate_value_name}.bytes

end {namespace}
"""


def generate_artifact_byte_pack_bundle(
    *,
    artifact_path: Path | str,
    out_dir: Path | str,
    module_prefix: str,
    namespace: str = "StageA.GeneratedRelational.ArtifactBytePacks",
    pack_size: int = DEFAULT_ARTIFACT_BYTE_PACK_SIZE,
    chunk_size: int = DEFAULT_ARTIFACT_BYTE_CHUNK_SIZE,
    standalone: bool = True,
    aggregate_module: str | None = None,
    aggregate_value_name: str | None = None,
    aggregate_bytes_name: str | None = None,
    inventory_filename: str = "artifact-byte-packs.json",
) -> ArtifactBytePackInventory:
    """Generate exact payload shards and one compact ordered aggregate."""

    source_path = Path(artifact_path).resolve()
    destination = Path(out_dir)
    module_prefix = _validate_identifier(module_prefix, "module prefix")
    namespace = _validate_namespace(namespace)
    if pack_size <= 0 or chunk_size <= 0 or chunk_size > pack_size:
        raise ArtifactBytePackGenerationError(
            "pack and chunk sizes must be positive, with chunk size at most pack size"
        )
    if not source_path.is_file() or source_path.is_symlink():
        raise ArtifactBytePackGenerationError(
            f"artifact is not a regular file: {source_path}"
        )

    data = source_path.read_bytes()
    source_sha256 = sha256_bytes(data)
    definition_prefix = _definition_prefix(module_prefix)
    aggregate_module = _validate_identifier(
        aggregate_module or f"{module_prefix}Artifact",
        "aggregate module",
    )
    aggregate_value_name = _validate_identifier(
        aggregate_value_name or f"{definition_prefix}Artifact",
        "aggregate value name",
    )
    aggregate_bytes_name = _validate_identifier(
        aggregate_bytes_name or f"{definition_prefix}Bytes",
        "aggregate bytes name",
    )
    inventory_path = Path(inventory_filename)
    if (
        inventory_path.name != inventory_filename
        or inventory_path.suffix != ".json"
    ):
        raise ArtifactBytePackGenerationError(
            "inventory filename must be a basename ending in .json"
        )

    packs = tuple(
        ArtifactBytePack(
            index=index,
            raw_offset=raw_offset,
            size=len(data[raw_offset : raw_offset + pack_size]),
            sha256=sha256_bytes(data[raw_offset : raw_offset + pack_size]),
            module=f"{module_prefix}BytePack{index:04d}",
            value_name=f"{definition_prefix}BytePack{index:04d}",
        )
        for index, raw_offset in enumerate(range(0, len(data), pack_size))
    )
    if sha256_file(source_path) != source_sha256:
        raise ArtifactBytePackGenerationError(
            "artifact changed while byte packs were generated"
        )

    stage_a = destination / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    standalone_modules = _copy_kernel_closure(stage_a) if standalone else ()
    modules: list[dict[str, Any]] = []
    for pack in packs:
        source = _payload_source(
            namespace=namespace,
            pack=pack,
            data=data[pack.raw_offset : pack.raw_end],
            chunk_size=chunk_size,
        )
        _write_text_if_changed(stage_a / f"{pack.module}.lean", source)
        modules.append(
            _module_row(
                pack.module,
                "artifact-byte-pack",
                source,
                pack_index=pack.index,
                raw_offset=pack.raw_offset,
                bytes=pack.size,
                payload_sha256=pack.sha256,
            )
        )

    aggregate = _aggregate_source(
        namespace=namespace,
        packs=packs,
        aggregate_value_name=aggregate_value_name,
        aggregate_bytes_name=aggregate_bytes_name,
    )
    _write_text_if_changed(stage_a / f"{aggregate_module}.lean", aggregate)
    modules.append(
        _module_row(
            aggregate_module,
            "artifact-byte-aggregate",
            aggregate,
            source_artifact_bytes=len(data),
        )
    )
    inventory = ArtifactBytePackInventory(
        source_path=source_path,
        source_sha256=source_sha256,
        source_size=len(data),
        module_prefix=module_prefix,
        namespace=namespace,
        aggregate_module=aggregate_module,
        aggregate_value_name=aggregate_value_name,
        aggregate_bytes_name=aggregate_bytes_name,
        pack_size=pack_size,
        chunk_size=chunk_size,
        packs=packs,
        modules=tuple(modules),
        standalone_modules=tuple(
            [*standalone_modules, *(row["name"] for row in modules)]
        ),
    )
    write_json(destination / inventory_filename, inventory.payload())
    return inventory


__all__ = [
    "ARTIFACT_BYTE_PACK_FORMAT",
    "DEFAULT_ARTIFACT_BYTE_CHUNK_SIZE",
    "DEFAULT_ARTIFACT_BYTE_PACK_SIZE",
    "ArtifactBytePack",
    "ArtifactBytePackGenerationError",
    "ArtifactBytePackInventory",
    "ExternalArtifactBytesBinding",
    "generate_artifact_byte_pack_bundle",
]
