"""Isolated portable-C invocation for component evidence production."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import select
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from .logical_abi import (
    LOGICAL_C_V1,
    LOGICAL_OBJECT_C_V1,
    NUL_TERMINATED_BYTES_V1,
    READ_ONLY_BYTES_V1,
    SCALAR_C_TYPES,
)


CANDIDATE_CASE_TIMEOUT_SECONDS = 1.0
_RUNNER_START_TIMEOUT_SECONDS = 5.0
_CTYPE_BY_NAME = {
    "uint8_t": ctypes.c_uint8,
    "uint16_t": ctypes.c_uint16,
    "uint32_t": ctypes.c_uint32,
    "uint64_t": ctypes.c_uint64,
    "int8_t": ctypes.c_int8,
    "int16_t": ctypes.c_int16,
    "int32_t": ctypes.c_int32,
    "int64_t": ctypes.c_int64,
}
_READ_U8 = ctypes.CFUNCTYPE(
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
)


class _StageBRoBytesV1(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("extent", ctypes.c_uint32),
        ("read_u8", _READ_U8),
    ]


class _StageBCStringV1(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("read_u8", _READ_U8),
    ]


class CandidateRunError(RuntimeError):
    """A candidate process failed without establishing a behavior mismatch."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class CandidateEvidenceRunner:
    """Invoke one compiled candidate in a disposable helper process."""

    def __init__(
        self,
        *,
        library: Path,
        abi: str,
        symbol: str,
        parameters: Sequence[Mapping[str, object]],
        result_type: str,
        timeout: float = CANDIDATE_CASE_TIMEOUT_SECONDS,
    ) -> None:
        self._configuration = {
            "library": str(library.resolve()),
            "abi": abi,
            "symbol": symbol,
            "parameters": [dict(parameter) for parameter in parameters],
            "result_type": result_type,
        }
        self._timeout = timeout
        self._process: subprocess.Popen[bytes] | None = None
        self._requests: TextIO | None = None
        self._responses: TextIO | None = None

    def run(self, arguments: Mapping[str, object]) -> dict[str, object]:
        if self._process is None:
            self._start()
        assert self._requests is not None
        try:
            self._send(self._requests, {"command": "run", "arguments": arguments})
        except OSError as exc:
            process = self._process
            returncode = None if process is None else process.poll()
            self._terminate()
            raise CandidateRunError(
                "component_candidate_process_crashed",
                "candidate process closed its request channel before the case "
                f"could run; status {returncode!r}",
            ) from exc
        response = self._receive(self._timeout, "candidate case")
        kind = response.get("kind")
        if kind == "result":
            return response
        if kind == "infrastructure_error":
            self._terminate()
            raise CandidateRunError(
                "component_candidate_runner_infrastructure_failed",
                str(response.get("detail", "candidate runner failed")),
            )
        self._terminate()
        raise CandidateRunError(
            "component_candidate_runner_infrastructure_failed",
            f"candidate runner returned an invalid response kind: {kind!r}",
        )

    def close(self) -> None:
        process = self._process
        if (
            process is not None
            and process.poll() is None
            and self._requests is not None
        ):
            try:
                self._send(self._requests, {"command": "close"})
                process.wait(timeout=0.5)
            except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                self._terminate()
        self._close_streams()
        self._process = None

    def _start(self) -> None:
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        command = [
            sys.executable,
            "-m",
            "spaghetti_extractor.components.evidence_runner",
            "--request-fd",
            str(request_read),
            "--response-fd",
            str(response_write),
        ]
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(request_read, response_write),
                start_new_session=True,
            )
        except OSError as exc:
            os.close(request_read)
            os.close(request_write)
            os.close(response_read)
            os.close(response_write)
            raise CandidateRunError(
                "component_candidate_runner_infrastructure_failed",
                f"cannot start candidate runner: {exc}",
            ) from exc
        os.close(request_read)
        os.close(response_write)
        self._requests = os.fdopen(request_write, "w", encoding="ascii", buffering=1)
        self._responses = os.fdopen(response_read, "r", encoding="ascii", buffering=1)
        try:
            self._send(
                self._requests,
                {"command": "initialize", **self._configuration},
            )
            response = self._receive(
                _RUNNER_START_TIMEOUT_SECONDS, "candidate runner startup"
            )
        except (CandidateRunError, OSError) as exc:
            self._terminate()
            if isinstance(exc, CandidateRunError):
                raise
            raise CandidateRunError(
                "component_candidate_runner_infrastructure_failed",
                f"cannot initialize candidate runner: {exc}",
            ) from exc
        if response.get("kind") == "ready":
            return
        if response.get("kind") == "infrastructure_error":
            detail = str(
                response.get("detail", "candidate runner initialization failed")
            )
        else:
            detail = f"candidate runner returned an invalid startup response: {response!r}"
        self._terminate()
        raise CandidateRunError(
            "component_candidate_runner_infrastructure_failed",
            detail,
        )

    def _receive(self, timeout: float, phase: str) -> dict[str, object]:
        assert self._responses is not None
        ready, _, _ = select.select([self._responses.fileno()], [], [], timeout)
        if not ready:
            self._terminate()
            raise CandidateRunError(
                "component_candidate_process_timed_out",
                f"{phase} exceeded the deterministic {timeout:.3f}s timeout",
            )
        line = self._responses.readline()
        if not line:
            process = self._process
            returncode = None if process is None else process.poll()
            if process is not None and returncode is None:
                try:
                    returncode = process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    returncode = None
            self._terminate()
            raise CandidateRunError(
                "component_candidate_process_crashed",
                f"{phase} ended the candidate process with status {returncode!r}",
            )
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            self._terminate()
            raise CandidateRunError(
                "component_candidate_runner_infrastructure_failed",
                f"candidate runner returned malformed JSON: {exc}",
            ) from exc
        if not isinstance(response, dict):
            self._terminate()
            raise CandidateRunError(
                "component_candidate_runner_infrastructure_failed",
                "candidate runner response is not an object",
            )
        return response

    def _terminate(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                process.kill()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
        self._close_streams()

    def _close_streams(self) -> None:
        for stream in (self._requests, self._responses):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        self._requests = None
        self._responses = None

    @staticmethod
    def _send(stream: TextIO, value: object) -> None:
        stream.write(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        )
        stream.flush()


def _configure_function(
    configuration: Mapping[str, object],
) -> tuple[Any, list[Mapping[str, object]]]:
    library = configuration.get("library")
    symbol = configuration.get("symbol")
    abi = configuration.get("abi")
    raw_parameters = configuration.get("parameters")
    result_type = configuration.get("result_type")
    if not isinstance(library, str) or not isinstance(symbol, str):
        raise ValueError("candidate library and symbol must be strings")
    if abi not in {LOGICAL_C_V1, LOGICAL_OBJECT_C_V1}:
        raise ValueError(f"unsupported candidate ABI {abi!r}")
    if not isinstance(raw_parameters, list) or not isinstance(result_type, str):
        raise ValueError("candidate signature is malformed")
    parameters = [
        dict(parameter)
        for parameter in raw_parameters
        if isinstance(parameter, Mapping)
    ]
    if len(parameters) != len(raw_parameters):
        raise ValueError("candidate parameters are malformed")
    function = getattr(ctypes.CDLL(library), symbol)
    function.argtypes = [
        _parameter_ctype(abi, str(parameter.get("type")))
        for parameter in parameters
    ]
    function.restype = _scalar_ctype(result_type)
    return function, parameters


def _parameter_ctype(abi: object, type_name: str) -> Any:
    if type_name == READ_ONLY_BYTES_V1 and abi == LOGICAL_OBJECT_C_V1:
        return ctypes.POINTER(_StageBRoBytesV1)
    if type_name == NUL_TERMINATED_BYTES_V1 and abi == LOGICAL_OBJECT_C_V1:
        return ctypes.POINTER(_StageBCStringV1)
    return _scalar_ctype(type_name)


def _scalar_ctype(type_name: str) -> Any:
    if type_name not in SCALAR_C_TYPES:
        raise ValueError(f"unsupported scalar C type {type_name!r}")
    return _CTYPE_BY_NAME[type_name]


def _invoke(
    function: Any,
    parameters: Sequence[Mapping[str, object]],
    arguments: Mapping[str, object],
) -> dict[str, object]:
    values: list[object] = []
    keepalive: list[object] = []
    violations: list[dict[str, object]] = []
    for parameter_index, parameter in enumerate(parameters):
        identity = parameter.get("id")
        type_name = parameter.get("type")
        if not isinstance(identity, str) or identity not in arguments:
            raise ValueError("candidate argument set does not match its signature")
        value = arguments[identity]
        if type_name in SCALAR_C_TYPES:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"candidate scalar argument {identity} is malformed")
            values.append(value)
            continue
        if type_name not in {
            READ_ONLY_BYTES_V1,
            NUL_TERMINATED_BYTES_V1,
        } or not isinstance(value, list):
            raise ValueError(f"candidate object argument {identity} is malformed")
        view = parameter.get("memory_view")
        if not isinstance(view, Mapping):
            raise ValueError(f"candidate object view {identity} is malformed")
        data = tuple(int(byte) for byte in value)
        if type_name == READ_ONLY_BYTES_V1:
            extent_id = view.get("extent_parameter_id")
            extent = arguments.get(extent_id) if isinstance(extent_id, str) else None
            if (
                not isinstance(extent, int)
                or isinstance(extent, bool)
                or extent < 0
                or extent > 0xFFFFFFFF
                or extent > len(value)
            ):
                raise ValueError(
                    f"candidate object view {identity} has an invalid extent"
                )
        else:
            if 0 not in data:
                raise ValueError(
                    f"candidate C-string view {identity} has no NUL terminator"
                )
            extent = len(data)
        token = ctypes.c_uint8((parameter_index + 1) & 0xFF)
        expected_context = ctypes.addressof(token)

        def read_u8(
            context: object,
            offset: int,
            output: ctypes.POINTER(ctypes.c_uint8),
            *,
            parameter_id: str = identity,
            expected: int = expected_context,
            declared_extent: int = extent,
            byte_values: tuple[int, ...] = data,
        ) -> int:
            actual_context = int(context) if context is not None else 0
            if actual_context != expected:
                violations.append(
                    {
                        "kind": "context_mismatch",
                        "parameter_id": parameter_id,
                    }
                )
                return 1
            if int(offset) >= declared_extent:
                violations.append(
                    {
                        "kind": "out_of_view_read",
                        "parameter_id": parameter_id,
                        "offset": int(offset),
                        "extent": declared_extent,
                    }
                )
                return 1
            if not bool(output):
                violations.append(
                    {
                        "kind": "null_output_pointer",
                        "parameter_id": parameter_id,
                        "offset": int(offset),
                        "extent": declared_extent,
                    }
                )
                return 1
            output[0] = byte_values[int(offset)]
            return 0

        callback = _READ_U8(read_u8)
        object_view = (
            _StageBRoBytesV1(
                ctypes.c_void_p(expected_context),
                extent,
                callback,
            )
            if type_name == READ_ONLY_BYTES_V1
            else _StageBCStringV1(
                ctypes.c_void_p(expected_context),
                callback,
            )
        )
        object_pointer = ctypes.pointer(object_view)
        keepalive.extend((token, callback, object_view, object_pointer))
        values.append(object_pointer)
    observed = int(function(*values))
    del keepalive
    return {
        "kind": "result",
        "observed": observed,
        "violations": violations,
    }


def _write_message(stream: TextIO, value: object) -> None:
    stream.write(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    )
    stream.flush()


def _child_main(request_fd: int, response_fd: int) -> int:
    with os.fdopen(request_fd, "r", encoding="ascii") as requests, os.fdopen(
        response_fd, "w", encoding="ascii", buffering=1
    ) as responses:
        line = requests.readline()
        try:
            configuration = json.loads(line)
            if (
                not isinstance(configuration, Mapping)
                or configuration.get("command") != "initialize"
            ):
                raise ValueError("candidate runner initialization is malformed")
            function, parameters = _configure_function(configuration)
        except Exception as exc:
            _write_message(
                responses,
                {
                    "kind": "infrastructure_error",
                    "detail": f"{type(exc).__name__}: {exc}",
                },
            )
            return 2
        _write_message(responses, {"kind": "ready"})
        for line in requests:
            try:
                request = json.loads(line)
                if not isinstance(request, Mapping):
                    raise ValueError("candidate runner request is not an object")
                if request.get("command") == "close":
                    return 0
                if request.get("command") != "run":
                    raise ValueError("candidate runner command is unsupported")
                arguments = request.get("arguments")
                if not isinstance(arguments, Mapping):
                    raise ValueError("candidate runner arguments are malformed")
                response = _invoke(function, parameters, arguments)
            except Exception as exc:
                response = {
                    "kind": "infrastructure_error",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            _write_message(responses, response)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-fd", type=int, required=True)
    parser.add_argument("--response-fd", type=int, required=True)
    arguments = parser.parse_args(argv)
    return _child_main(arguments.request_fd, arguments.response_fd)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CANDIDATE_CASE_TIMEOUT_SECONDS",
    "CandidateEvidenceRunner",
    "CandidateRunError",
]
