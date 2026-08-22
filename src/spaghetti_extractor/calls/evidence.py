"""Content-bound machine observations for physical call transport."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import MACHINE_CALL_EVIDENCE_V1_FORMAT
from ._canonical import CallProtocolError, canonical, content_id, digest, exact, identifier, object_
from .frame import CallSubjectV1, PhysicalCallFrameV2


TRANSPORT_FIELDS = frozenset(
    {
        "transfer_kind",
        "target",
        "abi_dialect",
        "calling_convention",
        "arguments",
        "results",
        "stack",
        "preserved_state",
        "clobbered_state",
        "outcomes",
    }
)


@dataclass(frozen=True)
class MachineCallEvidenceV1:
    evidence_id: str
    producer: str
    subject: CallSubjectV1
    binary_sha256: str
    observed_fields: Mapping[str, object]
    dependency_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        producer: str,
        subject: CallSubjectV1 | Mapping[str, object],
        binary_sha256: str,
        observed_fields: Mapping[str, object],
        dependency_ids: Sequence[str] = (),
    ) -> "MachineCallEvidenceV1":
        parsed_subject = subject if isinstance(subject, CallSubjectV1) else CallSubjectV1.parse(subject)
        fields = dict(sorted((str(key), canonical(value)) for key, value in observed_fields.items()))
        if not fields or not set(fields) <= TRANSPORT_FIELDS:
            raise CallProtocolError("machine call evidence fields are empty or unsupported")
        dependencies = tuple(sorted(set(identifier(item, "machine call evidence dependency") for item in dependency_ids)))
        core = {
            "format": MACHINE_CALL_EVIDENCE_V1_FORMAT,
            "producer": identifier(producer, "machine call evidence producer"),
            "subject": parsed_subject.to_payload(),
            "binary_sha256": digest(binary_sha256, "machine call evidence binary digest"),
            "observed_fields": fields,
            "dependency_ids": list(dependencies),
        }
        return cls(content_id("machine-call-evidence-v1", core), str(core["producer"]), parsed_subject, str(core["binary_sha256"]), fields, dependencies)

    @classmethod
    def from_frame(
        cls,
        frame: PhysicalCallFrameV2,
        *,
        producer: str,
        binary_sha256: str,
        dependency_ids: Sequence[str] = (),
    ) -> "MachineCallEvidenceV1":
        payload = frame.to_payload()
        return cls.create(producer=producer, subject=frame.subject, binary_sha256=binary_sha256, observed_fields={key: payload[key] for key in sorted(TRANSPORT_FIELDS)}, dependency_ids=dependency_ids)

    @classmethod
    def from_pe32_callback_authority(
        cls,
        frame: PhysicalCallFrameV2,
        *,
        authority: Mapping[str, object],
        binary_sha256: str,
        dependency_ids: Sequence[str] = (),
    ) -> "MachineCallEvidenceV1":
        """Translate exact legacy callback-entry authority into call evidence.

        This is a deliberately narrow migration bridge.  It accepts only the
        word-oriented PE32 callback facts that the old authority actually
        proves and refuses register arguments, split values, or other details
        that cannot be reconstructed losslessly.
        """

        callback_id = identifier(authority.get("id"), "callback authority id")
        if authority.get("status") != "complete" or authority.get("authorizing") is not True:
            raise CallProtocolError("callback authority is not complete and authorizing")
        protocol = object_(authority.get("protocol"), "callback authority protocol")
        protocol_id = identifier(protocol.get("id"), "callback protocol id")
        if frame.subject.kind != "callback" or frame.subject.identity != protocol_id:
            raise CallProtocolError("callback protocol and call subject disagree")
        if frame.transfer_kind != "callback":
            raise CallProtocolError("callback evidence requires callback transport")
        entry = object_(authority.get("entry_state"), "callback entry state")
        if entry.get("model") != "pe32-callback-entry-v1":
            raise CallProtocolError("callback authority has an unsupported entry model")
        signature = object_(protocol.get("signature"), "callback authority signature")
        abi_template = signature.get("abi_template")
        convention = {
            "pe32-cdecl-v1": "cdecl",
            "pe32-stdcall-v1": "stdcall",
            "pe32-fastcall-v1": "fastcall",
            "pe32-thiscall-v1": "thiscall",
        }.get(abi_template)
        if convention is None or frame.calling_convention != convention:
            raise CallProtocolError("callback calling convention contradicts authority")
        word_count = signature.get("argument_words")
        cleanup_bytes = signature.get("stack_cleanup_bytes")
        if not isinstance(word_count, int) or isinstance(word_count, bool) or word_count < 0:
            raise CallProtocolError("callback authority argument count is malformed")
        if not isinstance(cleanup_bytes, int) or isinstance(cleanup_bytes, bool):
            raise CallProtocolError("callback authority cleanup is malformed")
        stack = object_(entry.get("stack"), "callback authority stack")
        if stack.get("callee_cleanup_bytes") != cleanup_bytes:
            raise CallProtocolError("callback entry state and protocol cleanup disagree")
        arguments = stack.get("arguments")
        if not isinstance(arguments, list) or len(arguments) != word_count:
            raise CallProtocolError("callback entry state and protocol arity disagree")
        for index, item in enumerate(arguments):
            row = object_(item, f"callback authority argument {index}")
            if row.get("index") != index or row.get("offset") != 4 + 4 * index or row.get("width") != 4:
                raise CallProtocolError("callback authority has a noncanonical word frame")
        physical_words: set[int] = set()
        for slot in frame.arguments:
            for fragment in slot.fragments:
                location = fragment.location
                if (
                    not fragment.specified
                    or location.kind != "stack"
                    or location.phase != "callee_entry"
                    or location.stack_base != frame.stack.coordinate
                    or location.stack_offset_bytes is None
                    or fragment.location_offset_bits != 0
                    or fragment.width_bits % 32 != 0
                ):
                    raise CallProtocolError(
                        "legacy callback authority cannot prove this argument transport"
                    )
                first = (location.stack_offset_bytes - 4) // 4
                physical_words.update(range(first, first + fragment.width_bits // 32))
        if physical_words != set(range(word_count)):
            raise CallProtocolError("callback argument transport contradicts authority")
        if frame.stack.cleanup_bytes != cleanup_bytes:
            raise CallProtocolError("callback stack cleanup contradicts authority")
        result = object_(signature.get("result"), "callback authority result")
        if result.get("kind") == "void":
            if frame.results:
                raise CallProtocolError("void callback authority contradicts result transport")
        elif result.get("kind") == "word":
            if len(frame.results) != 1:
                raise CallProtocolError("word callback authority requires one result")
            fragments = frame.results[0].fragments
            register = result.get("register")
            if (
                len(fragments) != 1
                or fragments[0].width_bits != 32
                or fragments[0].location.kind != "register"
                or fragments[0].location.name != register
            ):
                raise CallProtocolError("callback result transport contradicts authority")
        else:
            raise CallProtocolError("callback authority result is unsupported")
        return cls.from_frame(
            frame,
            producer="callback-authority-v4",
            binary_sha256=binary_sha256,
            dependency_ids=(callback_id, protocol_id, *dependency_ids),
        )

    @classmethod
    def parse(cls, value: object) -> "MachineCallEvidenceV1":
        row = object_(value, "machine call evidence")
        exact(row, {"format", "id", "producer", "subject", "binary_sha256", "observed_fields", "dependency_ids"}, "machine call evidence")
        if row["format"] != MACHINE_CALL_EVIDENCE_V1_FORMAT:
            raise CallProtocolError("unsupported machine call evidence format")
        dependencies = row["dependency_ids"]
        if not isinstance(dependencies, list):
            raise CallProtocolError("machine call evidence dependencies must be an array")
        result = cls.create(producer=row["producer"], subject=CallSubjectV1.parse(row["subject"]), binary_sha256=row["binary_sha256"], observed_fields=object_(row["observed_fields"], "machine call observations"), dependency_ids=dependencies)
        if row["id"] != result.evidence_id:
            raise CallProtocolError("machine call evidence id does not bind its contents")
        return result

    @property
    def complete(self) -> bool:
        return set(self.observed_fields) == TRANSPORT_FIELDS

    def agrees_with(self, frame: PhysicalCallFrameV2) -> bool:
        payload = frame.to_payload()
        return all(payload[key] == value for key, value in self.observed_fields.items())

    def to_payload(self) -> dict[str, object]:
        return {
            "format": MACHINE_CALL_EVIDENCE_V1_FORMAT,
            "id": self.evidence_id,
            "producer": self.producer,
            "subject": self.subject.to_payload(),
            "binary_sha256": self.binary_sha256,
            "observed_fields": dict(self.observed_fields),
            "dependency_ids": list(self.dependency_ids),
        }


__all__ = ["MachineCallEvidenceV1", "TRANSPORT_FIELDS"]
