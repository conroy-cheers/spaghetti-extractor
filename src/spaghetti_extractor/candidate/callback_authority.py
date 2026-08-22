"""Candidate-side checked view of callback protocol authority V4."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..artifacts.io import open_artifact_reader_v3
from ..authority.callbacks import (
    CALLBACK_AUTHORITY_ARTIFACT_KIND_V4,
    CALLBACK_AUTHORITY_CODEC_V4,
    CallbackAuthorityV4,
)
from ..errors import ToolkitInputError


@dataclass(frozen=True)
class CallbackProtocolAuthorityIndexV1:
    artifact_id: str
    manifest_sha256: str
    callbacks: tuple[CallbackAuthorityV4, ...]

    def by_external_site(self) -> dict[str, tuple[CallbackAuthorityV4, ...]]:
        result: dict[str, list[CallbackAuthorityV4]] = {}
        for callback in self.callbacks:
            result.setdefault(callback.external_site_id, []).append(callback)
        return {
            key: tuple(sorted(value, key=lambda row: row.callback_id))
            for key, value in sorted(result.items())
        }


def load_callback_protocol_authority_v1(
    path: Path | str,
) -> CallbackProtocolAuthorityIndexV1:
    reader = open_artifact_reader_v3(Path(path))
    if reader.manifest.artifact_kind != CALLBACK_AUTHORITY_ARTIFACT_KIND_V4:
        raise ToolkitInputError(
            "candidate callback authority must be callback-authority-v4"
        )
    callbacks: list[CallbackAuthorityV4] = []
    for source in reader.iter_records():
        record = CALLBACK_AUTHORITY_CODEC_V4.read(source).value
        if record.status != "complete" or not record.authorizing:
            if record.callbacks:
                raise ToolkitInputError(
                    f"callback authority inventory {record.record_id!r} exposes "
                    "callbacks without authority"
                )
            continue
        for callback in record.callbacks:
            if (
                callback.status != "complete"
                or not callback.authorizing
                or callback.protocol is None
                or callback.entry_state is None
            ):
                raise ToolkitInputError(
                    f"callback authority {callback.callback_id!r} is incomplete"
                )
            callbacks.append(callback)
    ids = [row.callback_id for row in callbacks]
    if len(ids) != len(set(ids)):
        raise ToolkitInputError("callback authority repeats a callback ID")
    return CallbackProtocolAuthorityIndexV1(
        artifact_id=reader.manifest.artifact_id,
        manifest_sha256=reader.manifest_sha256,
        callbacks=tuple(sorted(callbacks, key=lambda row: row.callback_id)),
    )


__all__ = [
    "CallbackProtocolAuthorityIndexV1",
    "load_callback_protocol_authority_v1",
]
