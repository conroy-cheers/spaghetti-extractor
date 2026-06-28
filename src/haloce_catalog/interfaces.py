from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from pathlib import Path
from typing import Any

from .labels import ensure_label, interface_test_case_label
from .util import utc_now


REQUIRED_INTERFACE_CASES = ("success", "failure", "error_path")
INTERFACE_TEST_STATUSES = ("planned", "pass", "fail")


@dataclass(frozen=True)
class MockEndpointSpec:
    dll: str
    symbol: str | None
    ordinal: int | None = None
    subsystem: str = "unknown"
    endpoint_kind: str = "import"
    test_id: str = ""
    evidence: str = ""

    @property
    def label(self) -> str:
        from .labels import platform_endpoint_label

        return platform_endpoint_label(self.dll, self.symbol, self.ordinal)

    @property
    def display_name(self) -> str:
        symbol = self.symbol if self.symbol is not None else f"#{self.ordinal}"
        return f"{self.dll}!{symbol}"


def _endpoint_identity(dll: str, symbol: str | None, ordinal: int | None) -> tuple[str, str, int | None]:
    return (dll.lower(), (symbol or "").lower(), ordinal)


MOCKED_ENDPOINTS: tuple[MockEndpointSpec, ...] = (
    MockEndpointSpec("kernel32.dll", "CreateFileA", subsystem="win32", test_id="kernel32-createfilea"),
    MockEndpointSpec("kernel32.dll", "ReadFile", subsystem="win32", test_id="kernel32-readfile"),
    MockEndpointSpec("kernel32.dll", "WriteFile", subsystem="win32", test_id="kernel32-writefile"),
    MockEndpointSpec("kernel32.dll", "CloseHandle", subsystem="win32", test_id="kernel32-closehandle"),
    MockEndpointSpec("kernel32.dll", "FindFirstFileA", subsystem="win32", test_id="kernel32-findfirstfilea"),
    MockEndpointSpec("kernel32.dll", "FindNextFileA", subsystem="win32", test_id="kernel32-findnextfilea"),
    MockEndpointSpec("kernel32.dll", "FindClose", subsystem="win32", test_id="kernel32-findclose"),
    MockEndpointSpec("kernel32.dll", "CreateDirectoryA", subsystem="win32", test_id="kernel32-createdirectorya"),
    MockEndpointSpec("kernel32.dll", "GetFileAttributesA", subsystem="win32", test_id="kernel32-getfileattributesa"),
    MockEndpointSpec("kernel32.dll", "SetFilePointer", subsystem="win32", test_id="kernel32-setfilepointer"),
    MockEndpointSpec("kernel32.dll", "GetFileSize", subsystem="win32", test_id="kernel32-getfilesize"),
    MockEndpointSpec("kernel32.dll", "GetLastError", subsystem="win32", test_id="kernel32-getlasterror"),
    MockEndpointSpec("kernel32.dll", "SetLastError", subsystem="win32", test_id="kernel32-setlasterror"),
    MockEndpointSpec("kernel32.dll", "GetTickCount", subsystem="win32", test_id="kernel32-gettickcount"),
    MockEndpointSpec("kernel32.dll", "QueryPerformanceCounter", subsystem="win32", test_id="kernel32-qpc"),
    MockEndpointSpec("kernel32.dll", "QueryPerformanceFrequency", subsystem="win32", test_id="kernel32-qpf"),
    MockEndpointSpec("kernel32.dll", "Sleep", subsystem="win32", test_id="kernel32-sleep"),
    MockEndpointSpec("kernel32.dll", "CreateThread", subsystem="win32", test_id="kernel32-createthread"),
    MockEndpointSpec("kernel32.dll", "ExitThread", subsystem="win32", test_id="kernel32-exitthread"),
    MockEndpointSpec("kernel32.dll", "WaitForSingleObject", subsystem="win32", test_id="kernel32-waitforsingleobject"),
    MockEndpointSpec("kernel32.dll", "CreateEventA", subsystem="win32", test_id="kernel32-createeventa"),
    MockEndpointSpec("kernel32.dll", "SetEvent", subsystem="win32", test_id="kernel32-setevent"),
    MockEndpointSpec("kernel32.dll", "ResetEvent", subsystem="win32", test_id="kernel32-resetevent"),
    MockEndpointSpec("kernel32.dll", "TlsAlloc", subsystem="win32", test_id="kernel32-tlsalloc"),
    MockEndpointSpec("kernel32.dll", "TlsGetValue", subsystem="win32", test_id="kernel32-tlsgetvalue"),
    MockEndpointSpec("kernel32.dll", "TlsSetValue", subsystem="win32", test_id="kernel32-tlssetvalue"),
    MockEndpointSpec("kernel32.dll", "TlsFree", subsystem="win32", test_id="kernel32-tlsfree"),
    MockEndpointSpec("kernel32.dll", "HeapAlloc", subsystem="win32", test_id="kernel32-heapalloc"),
    MockEndpointSpec("kernel32.dll", "HeapFree", subsystem="win32", test_id="kernel32-heapfree"),
    MockEndpointSpec("kernel32.dll", "GetProcessHeap", subsystem="win32", test_id="kernel32-getprocessheap"),
    MockEndpointSpec("advapi32.dll", "RegOpenKeyExA", subsystem="win32", test_id="advapi32-regopenkeyexa"),
    MockEndpointSpec("advapi32.dll", "RegQueryValueExA", subsystem="win32", test_id="advapi32-regqueryvalueexa"),
    MockEndpointSpec("advapi32.dll", "RegSetValueExA", subsystem="win32", test_id="advapi32-regsetvalueexa"),
    MockEndpointSpec("advapi32.dll", "RegDeleteValueA", subsystem="win32", test_id="advapi32-regdeletevaluea"),
    MockEndpointSpec("advapi32.dll", "RegCloseKey", subsystem="win32", test_id="advapi32-regclosekey"),
    MockEndpointSpec("user32.dll", "CreateWindowExA", subsystem="rendering/windowing", test_id="user32-createwindowexa"),
    MockEndpointSpec("user32.dll", "DestroyWindow", subsystem="rendering/windowing", test_id="user32-destroywindow"),
    MockEndpointSpec("user32.dll", "SetFocus", subsystem="rendering/windowing", test_id="user32-setfocus"),
    MockEndpointSpec("user32.dll", "PeekMessageA", subsystem="rendering/windowing", test_id="user32-peekmessagea"),
    MockEndpointSpec("user32.dll", "DispatchMessageA", subsystem="rendering/windowing", test_id="user32-dispatchmessagea"),
    MockEndpointSpec("gdi32.dll", "SetDeviceGammaRamp", subsystem="rendering/windowing", test_id="gdi32-setdevicegammaramp"),
    MockEndpointSpec("ddraw.dll", "DirectDrawCreate", subsystem="rendering/windowing", test_id="ddraw-directdrawcreate"),
    MockEndpointSpec("d3d8.dll", "Direct3DCreate8", subsystem="rendering/windowing", test_id="d3d8-direct3dcreate8"),
    MockEndpointSpec("dinput.dll", "DirectInputCreateA", subsystem="input", test_id="dinput-directinputcreatea"),
    MockEndpointSpec("dinput8.dll", "DirectInput8Create", subsystem="input", test_id="dinput8-directinput8create"),
    MockEndpointSpec("dsound.dll", "DirectSoundCreate", subsystem="audio/video", test_id="dsound-directsoundcreate"),
    MockEndpointSpec("winmm.dll", "timeGetTime", subsystem="audio/video", test_id="winmm-timegettime"),
    MockEndpointSpec("winmm.dll", "waveOutGetNumDevs", subsystem="audio/video", test_id="winmm-waveoutgetnumdevs"),
    MockEndpointSpec("ws2_32.dll", "WSAStartup", subsystem="networking/services", test_id="ws2-32-wsastartup"),
    MockEndpointSpec("ws2_32.dll", "WSACleanup", subsystem="networking/services", test_id="ws2-32-wsacleanup"),
    MockEndpointSpec("ws2_32.dll", "socket", subsystem="networking/services", test_id="ws2-32-socket"),
    MockEndpointSpec("ws2_32.dll", "closesocket", subsystem="networking/services", test_id="ws2-32-closesocket"),
    MockEndpointSpec("ws2_32.dll", "bind", subsystem="networking/services", test_id="ws2-32-bind"),
    MockEndpointSpec("ws2_32.dll", "sendto", subsystem="networking/services", test_id="ws2-32-sendto"),
    MockEndpointSpec("ws2_32.dll", "recvfrom", subsystem="networking/services", test_id="ws2-32-recvfrom"),
    MockEndpointSpec("ws2_32.dll", "select", subsystem="networking/services", test_id="ws2-32-select"),
    MockEndpointSpec("ws2_32.dll", "ioctlsocket", subsystem="networking/services", test_id="ws2-32-ioctlsocket"),
    MockEndpointSpec("ws2_32.dll", "gethostbyname", subsystem="networking/services", test_id="ws2-32-gethostbyname"),
    MockEndpointSpec("ws2_32.dll", "htons", subsystem="networking/services", test_id="ws2-32-htons"),
    MockEndpointSpec("ws2_32.dll", "ntohs", subsystem="networking/services", test_id="ws2-32-ntohs"),
    MockEndpointSpec("wsock32.dll", "sendto", subsystem="networking/services", test_id="wsock32-sendto"),
    MockEndpointSpec("wsock32.dll", "recvfrom", subsystem="networking/services", test_id="wsock32-recvfrom"),
    MockEndpointSpec("wsock32.dll", "gethostbyname", subsystem="networking/services", test_id="wsock32-gethostbyname"),
    MockEndpointSpec("binkw32.dll", "BinkOpen", subsystem="audio/video", test_id="bink-binkopen"),
    MockEndpointSpec("binkw32.dll", "BinkDoFrame", subsystem="audio/video", test_id="bink-binkdoframe"),
    MockEndpointSpec("binkw32.dll", "BinkNextFrame", subsystem="audio/video", test_id="bink-binknextframe"),
    MockEndpointSpec("binkw32.dll", "BinkClose", subsystem="audio/video", test_id="bink-binkclose"),
    MockEndpointSpec("msvcrt.dll", "malloc", subsystem="platform runtime", test_id="msvcrt-malloc"),
    MockEndpointSpec("msvcrt.dll", "free", subsystem="platform runtime", test_id="msvcrt-free"),
    MockEndpointSpec("msvcrt.dll", "atexit", subsystem="platform runtime", test_id="msvcrt-atexit"),
    MockEndpointSpec("msvcrt.dll", "setlocale", subsystem="platform runtime", test_id="msvcrt-setlocale"),
)

_MOCKED_ENDPOINTS_BY_IDENTITY = {
    _endpoint_identity(spec.dll, spec.symbol, spec.ordinal): spec for spec in MOCKED_ENDPOINTS
}

_DLL_SUBSYSTEMS = {
    "advapi32.dll": "win32",
    "binkw32.dll": "audio/video",
    "d3d8.dll": "rendering/windowing",
    "d3d9.dll": "rendering/windowing",
    "ddraw.dll": "rendering/windowing",
    "dinput.dll": "input",
    "dinput8.dll": "input",
    "dsound.dll": "audio/video",
    "gdi32.dll": "rendering/windowing",
    "kernel32.dll": "win32",
    "msvcrt.dll": "platform runtime",
    "ole32.dll": "win32",
    "oleaut32.dll": "win32",
    "user32.dll": "rendering/windowing",
    "wininet.dll": "networking/services",
    "winmm.dll": "audio/video",
    "ws2_32.dll": "networking/services",
    "wsock32.dll": "networking/services",
}

_MOCKED_SUBSYSTEMS = {
    "audio/video",
    "input",
    "networking/services",
    "platform runtime",
    "rendering/windowing",
    "win32",
}


def endpoint_subsystem(dll: str) -> str:
    return _DLL_SUBSYSTEMS.get(dll.lower(), "unknown")


def endpoint_mock_status(dll: str, symbol: str | None, ordinal: int | None) -> str:
    identity = _endpoint_identity(dll, symbol, ordinal)
    if identity in _MOCKED_ENDPOINTS_BY_IDENTITY:
        return "complete"
    subsystem = endpoint_subsystem(dll)
    return "partial" if subsystem in _MOCKED_SUBSYSTEMS else "missing"


def upsert_platform_endpoint(
    conn: sqlite3.Connection,
    *,
    dll: str,
    symbol: str | None,
    ordinal: int | None = None,
    endpoint_kind: str = "import",
    subsystem: str | None = None,
    mock_status: str | None = None,
    test_status: str = "untested",
    created_at: str | None = None,
) -> dict[str, Any]:
    from .labels import platform_endpoint_label

    resolved_subsystem = subsystem or endpoint_subsystem(dll)
    resolved_mock_status = mock_status or endpoint_mock_status(dll, symbol, ordinal)
    label = platform_endpoint_label(dll, symbol, ordinal)
    display = f"{dll}!{symbol}" if symbol else f"{dll}!#{ordinal}"
    ensure_label(
        conn,
        label,
        "platform_endpoint",
        display,
        "platform endpoint mock/spec target",
        created_at=created_at,
    )
    conn.execute(
        """
        INSERT INTO platform_endpoints(
          label, dll, symbol, ordinal, endpoint_kind, subsystem, mock_status, test_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(label) DO UPDATE SET
          endpoint_kind = excluded.endpoint_kind,
          subsystem = excluded.subsystem,
          mock_status = excluded.mock_status,
          test_status = excluded.test_status
        """,
        (
            label,
            dll,
            symbol,
            ordinal,
            endpoint_kind,
            resolved_subsystem,
            resolved_mock_status,
            test_status,
        ),
    )
    return {
        "label": label,
        "dll": dll,
        "symbol": symbol,
        "ordinal": ordinal,
        "subsystem": resolved_subsystem,
        "mock_status": resolved_mock_status,
        "test_status": test_status,
    }


def record_mock_interface_suite(
    conn: sqlite3.Connection,
    *,
    endpoint_specs: tuple[MockEndpointSpec, ...] = MOCKED_ENDPOINTS,
    status: str = "pass",
    evidence: str = "public mock behavior suite covers success, failure, and error-path behavior",
    created_at: str | None = None,
) -> dict[str, Any]:
    if status not in INTERFACE_TEST_STATUSES:
        raise ValueError(f"unknown interface test status: {status}")

    endpoints = 0
    cases = 0
    for spec in endpoint_specs:
        endpoint = upsert_platform_endpoint(
            conn,
            dll=spec.dll,
            symbol=spec.symbol,
            ordinal=spec.ordinal,
            endpoint_kind=spec.endpoint_kind,
            subsystem=spec.subsystem,
            mock_status="complete",
            test_status="tested" if status == "pass" else "untested",
            created_at=created_at,
        )
        endpoints += 1
        test_id = spec.test_id or endpoint["label"]
        case_evidence = spec.evidence or evidence
        for case_kind in REQUIRED_INTERFACE_CASES:
            record_interface_test_case(
                conn,
                endpoint_label=endpoint["label"],
                case_kind=case_kind,
                test_id=test_id,
                status=status,
                evidence=f"{case_evidence}; case={case_kind}",
                created_at=created_at,
            )
            cases += 1

    return {
        "endpoints": endpoints,
        "test_cases": cases,
        "case_kinds": list(REQUIRED_INTERFACE_CASES),
        "status": status,
    }


def record_observed_interface_suite(
    conn: sqlite3.Connection,
    *,
    scopes: tuple[str, ...] = ("included", "candidate"),
    status: str = "pass",
    evidence: str,
    test_id_prefix: str = "observed-interface",
    fixture_path: Path | str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    if status not in INTERFACE_TEST_STATUSES:
        raise ValueError(f"unknown interface test status: {status}")
    if not evidence.strip():
        raise ValueError("observed interface suite evidence is required")
    if not scopes:
        raise ValueError("at least one binary scope is required")

    placeholders = ",".join("?" for _ in scopes)
    endpoints = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT DISTINCT pe.label, pe.dll, pe.symbol, pe.ordinal, pe.subsystem
            FROM platform_endpoints pe
            JOIN binary_platform_endpoints bpe ON bpe.endpoint_id = pe.id
            JOIN binaries b ON b.id = bpe.binary_id
            WHERE b.scope IN ({placeholders})
            ORDER BY lower(pe.dll), COALESCE(pe.symbol, ''), COALESCE(pe.ordinal, -1)
            """,
            tuple(scopes),
        )
    ]
    created = created_at or utc_now()
    cases = 0
    for endpoint in endpoints:
        conn.execute(
            """
            UPDATE platform_endpoints
            SET mock_status = ?, test_status = ?
            WHERE label = ?
            """,
            ("complete", "tested" if status == "pass" else "untested", endpoint["label"]),
        )
        symbol = endpoint["symbol"] if endpoint["symbol"] is not None else f"#{endpoint['ordinal']}"
        test_id = _interface_test_id(test_id_prefix, endpoint["dll"], symbol)
        for case_kind in REQUIRED_INTERFACE_CASES:
            record_interface_test_case(
                conn,
                endpoint_label=endpoint["label"],
                case_kind=case_kind,
                test_id=test_id,
                status=status,
                evidence=f"{evidence}; endpoint={endpoint['dll']}!{symbol}; case={case_kind}",
                fixture_path=fixture_path,
                created_at=created,
            )
            cases += 1

    return {
        "endpoints": len(endpoints),
        "test_cases": cases,
        "case_kinds": list(REQUIRED_INTERFACE_CASES),
        "status": status,
        "scopes": list(scopes),
    }


def record_interface_test_case(
    conn: sqlite3.Connection,
    *,
    endpoint_label: str,
    case_kind: str,
    test_id: str,
    status: str = "pass",
    evidence: str = "",
    fixture_path: Path | str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    if case_kind not in REQUIRED_INTERFACE_CASES:
        raise ValueError(f"unknown interface case kind: {case_kind}")
    if status not in INTERFACE_TEST_STATUSES:
        raise ValueError(f"unknown interface test status: {status}")

    endpoint = conn.execute(
        "SELECT id, label, dll, symbol, ordinal FROM platform_endpoints WHERE label = ?",
        (endpoint_label,),
    ).fetchone()
    if endpoint is None:
        raise ValueError(f"unknown platform endpoint label: {endpoint_label}")

    label = interface_test_case_label(endpoint_label, case_kind, test_id)
    created = created_at or utc_now()
    ensure_label(
        conn,
        label,
        "interface_test_case",
        f"{endpoint_label}:{case_kind}:{test_id}",
        "interface mock behavior test case",
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO interface_test_cases(
          label, endpoint_id, case_kind, test_id, status, evidence, fixture_path, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(endpoint_id, case_kind, test_id) DO UPDATE SET
          status = excluded.status,
          evidence = excluded.evidence,
          fixture_path = excluded.fixture_path
        """,
        (
            label,
            int(endpoint["id"]),
            case_kind,
            test_id,
            status,
            evidence,
            str(fixture_path) if fixture_path is not None else None,
            created,
        ),
    )
    return {
        "label": label,
        "endpoint_label": endpoint_label,
        "case_kind": case_kind,
        "test_id": test_id,
        "status": status,
    }


def _interface_test_id(prefix: str, dll: str, symbol: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "-" for ch in f"{dll}-{symbol}")
    normalized = "-".join(part for part in normalized.split("-") if part)
    return f"{prefix}-{normalized}"
