from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from ..stage_binary import StageAInputError
from ..util import json_dumps, sha256_file, write_json


ROUNDTRIP_CORPUS_FORMAT = "stage-a-roundtrip-corpus-v2"
ROUNDTRIP_CASE_FORMAT = "stage-a-roundtrip-case-v2"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")
_ARTIFACT_ROLES = frozenset({
    "semantic_program",
    "candidate_semantic_program",
    "original_source",
    "candidate_source",
    "original_object",
    "candidate_object",
    "original_pe",
    "candidate_pe",
    "original_linker_map",
    "candidate_linker_map",
    "original_inventory",
    "candidate_inventory",
    "violation_witness",
})
_REQUIRED_CASE_ARTIFACT_ROLES = frozenset({
    "semantic_program",
    "original_pe",
    "candidate_pe",
    "candidate_semantic_program",
    "original_inventory",
    "candidate_inventory",
})


class ExpectedDisposition(str, Enum):
    QUALIFIED = "qualified"
    VIOLATED = "violated"
    INCOMPLETE = "incomplete"


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str,
) -> None:
    missing = sorted(expected - set(payload))
    extra = sorted(set(payload) - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing}")
        if extra:
            details.append(f"unexpected fields {extra}")
        raise StageAInputError(f"{context} has " + " and ".join(details))


def _identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a stable lowercase identifier")
    return value


def _nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{context} must be a nonempty string")
    if any(ord(character) < 0x20 for character in value):
        raise StageAInputError(f"{context} must not contain control characters")
    return value


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be 64 lowercase hex characters")
    return value


def _integer(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StageAInputError(f"{context} must be an integer >= {minimum}")
    return value


def _relative_path(value: Any, context: str) -> str:
    raw = _nonempty_string(value, context)
    if "\\" in raw:
        raise StageAInputError(f"{context} must use canonical POSIX separators")
    path = PurePosixPath(raw)
    if path.is_absolute() or raw != path.as_posix() or ".." in path.parts:
        raise StageAInputError(f"{context} must be a canonical contained path")
    if any(part in {"", "."} for part in path.parts):
        raise StageAInputError(f"{context} must not contain empty or dot components")
    return raw


def _string_tuple(
    value: Any, context: str, *, identifiers: bool = False, unique: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result = tuple(
        _identifier(item, f"{context}[{index}]")
        if identifiers
        else _nonempty_string(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    )
    if unique and len(result) != len(set(result)):
        raise StageAInputError(f"{context} must not contain duplicates")
    return result


@dataclass(frozen=True)
class ArtifactRef:
    role: str
    path: str
    sha256: str
    bytes: int

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ArtifactRef":
        _exact_fields(payload, {"role", "path", "sha256", "bytes"}, context)
        role = _identifier(payload["role"], f"{context}.role")
        if role not in _ARTIFACT_ROLES:
            raise StageAInputError(f"{context}.role is not a supported artifact role")
        return cls(
            role=role,
            path=_relative_path(payload["path"], f"{context}.path"),
            sha256=_sha256(payload["sha256"], f"{context}.sha256"),
            bytes=_integer(payload["bytes"], f"{context}.bytes"),
        )

    @classmethod
    def from_path(cls, *, role: str, root: Path, path: Path) -> "ArtifactRef":
        root = Path(root).resolve()
        path = Path(path).resolve()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise StageAInputError(
                f"round-trip artifact {path} is outside case root {root}"
            ) from exc
        if not path.is_file():
            raise StageAInputError(f"round-trip artifact is not a file: {path}")
        return cls.parse({
            "role": role,
            "path": relative.as_posix(),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }, context=f"artifact {role}")

    def to_payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.bytes,
        }

    def verify(self, root: Path) -> Path:
        root = Path(root).resolve()
        path = (root / self.path).resolve()
        if root != path and root not in path.parents:
            raise StageAInputError(f"artifact {self.role} escapes its case root")
        if not path.is_file():
            raise StageAInputError(f"artifact {self.role} is missing: {path}")
        if path.stat().st_size != self.bytes:
            raise StageAInputError(f"artifact {self.role} size does not match its binding")
        if sha256_file(path) != self.sha256:
            raise StageAInputError(f"artifact {self.role} hash does not match its binding")
        return path


@dataclass(frozen=True)
class NegativeMutation:
    id: str
    semantic_delta: str
    location_id: str

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str,
    ) -> "NegativeMutation":
        _exact_fields(payload, {"id", "semantic_delta", "location_id"}, context)
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            semantic_delta=_nonempty_string(
                payload["semantic_delta"], f"{context}.semantic_delta"
            ),
            location_id=_identifier(payload["location_id"], f"{context}.location_id"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "semantic_delta": self.semantic_delta,
            "location_id": self.location_id,
        }


@dataclass(frozen=True)
class CaseExpectation:
    disposition: ExpectedDisposition
    witness_family: str | None
    reason_family: str | None

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str,
    ) -> "CaseExpectation":
        _exact_fields(
            payload, {"disposition", "witness_family", "reason_family"}, context,
        )
        try:
            disposition = ExpectedDisposition(payload["disposition"])
        except (TypeError, ValueError) as exc:
            raise StageAInputError(f"{context}.disposition is unsupported") from exc
        witness = payload["witness_family"]
        reason = payload["reason_family"]
        witness_family = (
            None if witness is None else _identifier(witness, f"{context}.witness_family")
        )
        reason_family = (
            None if reason is None else _identifier(reason, f"{context}.reason_family")
        )
        if disposition is ExpectedDisposition.QUALIFIED:
            if witness_family is not None or reason_family is not None:
                raise StageAInputError(
                    f"{context} qualified expectation cannot name a witness or reason family"
                )
        elif disposition is ExpectedDisposition.VIOLATED:
            if witness_family is None or reason_family is not None:
                raise StageAInputError(
                    f"{context} violated expectation requires only witness_family"
                )
        elif witness_family is not None or reason_family is None:
            raise StageAInputError(
                f"{context} incomplete expectation requires only reason_family"
            )
        return cls(
            disposition=disposition,
            witness_family=witness_family,
            reason_family=reason_family,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "witness_family": self.witness_family,
            "reason_family": self.reason_family,
        }


@dataclass(frozen=True)
class CaseManifest:
    id: str
    semantic_program_sha256: str
    parent_seed: int
    template: str
    transformations: tuple[str, ...]
    expectation: CaseExpectation
    mutation: NegativeMutation | None
    capability_profile: str
    capabilities: tuple[str, ...]
    validation_families: tuple[str, ...]
    artifacts: tuple[ArtifactRef, ...]
    replay: tuple[str, ...]
    shard: int
    format: str = ROUNDTRIP_CASE_FORMAT

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "CaseManifest":
        context = "round-trip case manifest"
        _exact_fields(payload, {
            "format",
            "id",
            "semantic_program_sha256",
            "parent_seed",
            "template",
            "transformations",
            "expectation",
            "mutation",
            "capability_profile",
            "capabilities",
            "validation_families",
            "artifacts",
            "replay",
            "shard",
        }, context)
        if payload["format"] != ROUNDTRIP_CASE_FORMAT:
            raise StageAInputError("unsupported round-trip case format")
        expectation_payload = _object(payload["expectation"], f"{context}.expectation")
        expectation = CaseExpectation.parse(
            expectation_payload, context=f"{context}.expectation"
        )
        mutation_payload = payload["mutation"]
        mutation = (
            None
            if mutation_payload is None
            else NegativeMutation.parse(
                _object(mutation_payload, f"{context}.mutation"),
                context=f"{context}.mutation",
            )
        )
        if (expectation.disposition is ExpectedDisposition.QUALIFIED) != (mutation is None):
            raise StageAInputError(
                "positive cases must omit mutation and negative cases must declare one"
            )
        raw_artifacts = payload["artifacts"]
        if not isinstance(raw_artifacts, list):
            raise StageAInputError(f"{context}.artifacts must be a list")
        artifacts = tuple(
            ArtifactRef.parse(
                _object(item, f"{context}.artifacts[{index}]"),
                context=f"{context}.artifacts[{index}]",
            )
            for index, item in enumerate(raw_artifacts)
        )
        roles = [artifact.role for artifact in artifacts]
        paths = [artifact.path for artifact in artifacts]
        if len(roles) != len(set(roles)):
            raise StageAInputError("round-trip case artifact roles must be unique")
        if len(paths) != len(set(paths)):
            raise StageAInputError("round-trip case artifact paths must be unique")
        missing_roles = sorted(_REQUIRED_CASE_ARTIFACT_ROLES - set(roles))
        if missing_roles:
            raise StageAInputError(
                f"round-trip case is missing required artifacts {missing_roles}"
            )
        declared_violation_roles = {"violation_witness"} & set(roles)
        if (
            expectation.disposition is not ExpectedDisposition.VIOLATED
            and declared_violation_roles
        ):
            raise StageAInputError(
                "only expected-violated cases may declare violation evidence"
            )
        semantic_program_sha256 = _sha256(
            payload["semantic_program_sha256"],
            f"{context}.semantic_program_sha256",
        )
        semantic_artifact = next(
            artifact for artifact in artifacts if artifact.role == "semantic_program"
        )
        if semantic_artifact.sha256 != semantic_program_sha256:
            raise StageAInputError(
                "semantic program hash does not match its artifact binding"
            )
        replay = _string_tuple(
            payload["replay"], f"{context}.replay", unique=False
        )
        if not replay:
            raise StageAInputError("round-trip case replay command must not be empty")
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            semantic_program_sha256=semantic_program_sha256,
            parent_seed=_integer(payload["parent_seed"], f"{context}.parent_seed"),
            template=_identifier(payload["template"], f"{context}.template"),
            transformations=_string_tuple(
                payload["transformations"],
                f"{context}.transformations",
                identifiers=True,
            ),
            expectation=expectation,
            mutation=mutation,
            capability_profile=_identifier(
                payload["capability_profile"], f"{context}.capability_profile"
            ),
            capabilities=_string_tuple(
                payload["capabilities"], f"{context}.capabilities", identifiers=True
            ),
            validation_families=_string_tuple(
                payload["validation_families"], f"{context}.validation_families", identifiers=True
            ),
            artifacts=artifacts,
            replay=replay,
            shard=_integer(payload["shard"], f"{context}.shard"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "id": self.id,
            "semantic_program_sha256": self.semantic_program_sha256,
            "parent_seed": self.parent_seed,
            "template": self.template,
            "transformations": list(self.transformations),
            "expectation": self.expectation.to_payload(),
            "mutation": None if self.mutation is None else self.mutation.to_payload(),
            "capability_profile": self.capability_profile,
            "capabilities": list(self.capabilities),
            "validation_families": list(self.validation_families),
            "artifacts": [artifact.to_payload() for artifact in self.artifacts],
            "replay": list(self.replay),
            "shard": self.shard,
        }

    def artifact(self, role: str) -> ArtifactRef:
        matches = [artifact for artifact in self.artifacts if artifact.role == role]
        if len(matches) != 1:
            raise StageAInputError(f"round-trip case has no unique {role} artifact")
        return matches[0]

    def verify_artifacts(self, root: Path) -> dict[str, Path]:
        return {artifact.role: artifact.verify(root) for artifact in self.artifacts}


@dataclass(frozen=True)
class ToolchainIdentity:
    id: str
    target: str
    compiler: str
    compiler_version: str
    linker: str
    linker_version: str

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str,
    ) -> "ToolchainIdentity":
        _exact_fields(payload, {
            "id", "target", "compiler", "compiler_version", "linker",
            "linker_version",
        }, context)
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            target=_nonempty_string(payload["target"], f"{context}.target"),
            compiler=_nonempty_string(payload["compiler"], f"{context}.compiler"),
            compiler_version=_nonempty_string(
                payload["compiler_version"], f"{context}.compiler_version"
            ),
            linker=_nonempty_string(payload["linker"], f"{context}.linker"),
            linker_version=_nonempty_string(
                payload["linker_version"], f"{context}.linker_version"
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "compiler": self.compiler,
            "compiler_version": self.compiler_version,
            "linker": self.linker,
            "linker_version": self.linker_version,
        }


@dataclass(frozen=True)
class CorpusCaseRef:
    id: str
    path: str
    sha256: str
    shard: int

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str,
    ) -> "CorpusCaseRef":
        _exact_fields(payload, {"id", "path", "sha256", "shard"}, context)
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            path=_relative_path(payload["path"], f"{context}.path"),
            sha256=_sha256(payload["sha256"], f"{context}.sha256"),
            shard=_integer(payload["shard"], f"{context}.shard"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "sha256": self.sha256,
            "shard": self.shard,
        }


@dataclass(frozen=True)
class ExpectedCounts:
    qualified_cases: int
    violated_cases: int
    incomplete_cases: int

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str,
    ) -> "ExpectedCounts":
        _exact_fields(
            payload, {"qualified", "violated", "incomplete"}, context,
        )
        return cls(
            qualified_cases=_integer(payload["qualified"], f"{context}.qualified"),
            violated_cases=_integer(payload["violated"], f"{context}.violated"),
            incomplete_cases=_integer(payload["incomplete"], f"{context}.incomplete"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "qualified": self.qualified_cases,
            "violated": self.violated_cases,
            "incomplete": self.incomplete_cases,
        }


@dataclass(frozen=True)
class CorpusManifest:
    generator_version: str
    root_seed: int
    capability_profile: str
    toolchain: ToolchainIdentity
    cases: tuple[CorpusCaseRef, ...]
    expected_counts: ExpectedCounts
    shard_count: int
    format: str = ROUNDTRIP_CORPUS_FORMAT

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "CorpusManifest":
        context = "round-trip corpus manifest"
        _exact_fields(payload, {
            "format",
            "generator_version",
            "root_seed",
            "capability_profile",
            "toolchain",
            "cases",
            "expected_counts",
            "shard_count",
        }, context)
        if payload["format"] != ROUNDTRIP_CORPUS_FORMAT:
            raise StageAInputError("unsupported round-trip corpus format")
        raw_cases = payload["cases"]
        if not isinstance(raw_cases, list) or not raw_cases:
            raise StageAInputError("round-trip corpus cases must be a nonempty list")
        cases = tuple(
            CorpusCaseRef.parse(
                _object(item, f"{context}.cases[{index}]"),
                context=f"{context}.cases[{index}]",
            )
            for index, item in enumerate(raw_cases)
        )
        ids = [case.id for case in cases]
        paths = [case.path for case in cases]
        if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
            raise StageAInputError("round-trip corpus case ids and paths must be unique")
        shard_count = _integer(payload["shard_count"], f"{context}.shard_count", minimum=1)
        if any(case.shard >= shard_count for case in cases):
            raise StageAInputError("round-trip corpus case shard is out of range")
        return cls(
            generator_version=_nonempty_string(
                payload["generator_version"], f"{context}.generator_version"
            ),
            root_seed=_integer(payload["root_seed"], f"{context}.root_seed"),
            capability_profile=_identifier(
                payload["capability_profile"], f"{context}.capability_profile"
            ),
            toolchain=ToolchainIdentity.parse(
                _object(payload["toolchain"], f"{context}.toolchain"),
                context=f"{context}.toolchain",
            ),
            cases=cases,
            expected_counts=ExpectedCounts.parse(
                _object(payload["expected_counts"], f"{context}.expected_counts"),
                context=f"{context}.expected_counts",
            ),
            shard_count=shard_count,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "generator_version": self.generator_version,
            "root_seed": self.root_seed,
            "capability_profile": self.capability_profile,
            "toolchain": self.toolchain.to_payload(),
            "cases": [case.to_payload() for case in self.cases],
            "expected_counts": self.expected_counts.to_payload(),
            "shard_count": self.shard_count,
        }

    def load_cases(self, root: Path) -> tuple[tuple[CaseManifest, Path], ...]:
        root = Path(root).resolve()
        loaded: list[tuple[CaseManifest, Path]] = []
        dispositions: dict[ExpectedDisposition, int] = {
            disposition: 0 for disposition in ExpectedDisposition
        }
        for reference in self.cases:
            path = (root / reference.path).resolve()
            if root != path and root not in path.parents:
                raise StageAInputError(f"round-trip case {reference.id} escapes corpus root")
            if not path.is_file() or sha256_file(path) != reference.sha256:
                raise StageAInputError(
                    f"round-trip case {reference.id} manifest binding does not match"
                )
            case = load_case_manifest(path)
            if case.id != reference.id or case.shard != reference.shard:
                raise StageAInputError(
                    f"round-trip case {reference.id} identity does not match its reference"
                )
            case_root = path.parent
            case.verify_artifacts(case_root)
            dispositions[case.expectation.disposition] += 1
            loaded.append((case, case_root))
        expected = self.expected_counts
        observed = {
            ExpectedDisposition.QUALIFIED: expected.qualified_cases,
            ExpectedDisposition.VIOLATED: expected.violated_cases,
            ExpectedDisposition.INCOMPLETE: expected.incomplete_cases,
        }
        if dispositions != observed:
            raise StageAInputError(
                "round-trip corpus expected counts do not match case expectations"
            )
        return tuple(loaded)


def load_case_manifest(path: Path) -> CaseManifest:
    return CaseManifest.parse(_load_json_object(Path(path), "round-trip case manifest"))


def load_corpus_manifest(path: Path) -> CorpusManifest:
    return CorpusManifest.parse(
        _load_json_object(Path(path), "round-trip corpus manifest")
    )


def write_case_manifest(path: Path, manifest: CaseManifest) -> None:
    parsed = CaseManifest.parse(manifest.to_payload())
    write_json(Path(path), parsed.to_payload())


def write_corpus_manifest(path: Path, manifest: CorpusManifest) -> None:
    parsed = CorpusManifest.parse(manifest.to_payload())
    write_json(Path(path), parsed.to_payload())


def canonical_payload_sha256(payload: Mapping[str, Any]) -> str:
    from hashlib import sha256

    return sha256(json_dumps(dict(payload)).encode("utf-8")).hexdigest()


def _load_json_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    return _object(payload, context)


def artifact_refs(
    *, root: Path, artifacts: Sequence[tuple[str, Path]],
) -> tuple[ArtifactRef, ...]:
    return tuple(
        ArtifactRef.from_path(role=role, root=root, path=path)
        for role, path in artifacts
    )
