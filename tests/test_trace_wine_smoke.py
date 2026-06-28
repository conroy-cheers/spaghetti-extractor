import os
import shutil
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.catalog import build_catalog
from haloce_catalog.coverage import prove_halo_trace


RUN_WINE_TRACE_SMOKE = os.environ.get("HALOCE_RUN_WINE_TRACE_SMOKE") == "1"
SMOKE_ROOT = Path(os.environ["HALOCE_WINE_SMOKE_ROOT"]) if "HALOCE_WINE_SMOKE_ROOT" in os.environ else None
SMOKE_EXE = Path(os.environ["HALOCE_WINE_SMOKE_EXE"]) if "HALOCE_WINE_SMOKE_EXE" in os.environ else None
WINE_COMMAND = os.environ.get("HALOCE_WINE_COMMAND", "wine")


def _resolve_smoke_exe() -> Path | None:
    if SMOKE_EXE is not None and SMOKE_EXE.exists():
        return SMOKE_EXE
    if SMOKE_ROOT is not None:
        candidate = SMOKE_ROOT / "bin" / "halo-trace-win32-smoke.exe"
        if candidate.exists():
            return candidate
    found = shutil.which("halo-trace-win32-smoke.exe")
    return Path(found) if found else None


def _resolve_smoke_root(exe: Path) -> Path:
    if SMOKE_ROOT is not None:
        return SMOKE_ROOT
    return exe.parent.parent


@unittest.skipUnless(RUN_WINE_TRACE_SMOKE, "set HALOCE_RUN_WINE_TRACE_SMOKE=1 to run 32-bit Wine trace smoke")
@unittest.skipUnless(shutil.which("halo-trace-run") is not None, "halo-trace-run is not on PATH")
class WineTraceSmokeTests(unittest.TestCase):
    def test_generated_win32_fixture_records_blocks_cfg_edges_and_call_edges(self):
        exe = _resolve_smoke_exe()
        self.assertIsNotNone(exe, "set HALOCE_WINE_SMOKE_ROOT or HALOCE_WINE_SMOKE_EXE")
        assert exe is not None
        wine_command = _resolve_command(WINE_COMMAND)
        self.assertIsNotNone(wine_command, f"{WINE_COMMAND} is not on PATH")
        assert wine_command is not None

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "win32-smoke.jsonl"
            build = build_catalog(_resolve_smoke_root(exe), db_path, static_depth="none")
            self.assertEqual(build["errors"], [])

            result = _with_default_winedebug(
                lambda: prove_halo_trace(
                    db_path,
                    log_path,
                    "win32-smoke-live-proof",
                    [wine_command, str(exe)],
                    expected_filename=exe.name,
                    arch=os.environ.get("HALOCE_WINE_TRACE_ARCH", "auto"),
                    timeout_seconds=int(os.environ.get("HALOCE_WINE_TRACE_TIMEOUT", "30")),
                    allow_timeout=False,
                )
            )

        self.assertTrue(result["ok"], _failure_message(result))
        self.assertGreater(result["mapped"]["blocks"], 0)
        self.assertGreater(result["mapped"]["cfg_edges"], 0)
        self.assertGreater(result["mapped"]["call_edges"], 0)


def _resolve_command(command: str) -> str | None:
    path = Path(command)
    if path.is_file():
        return str(path)
    return shutil.which(command)


def _with_default_winedebug(callback):
    previous = os.environ.get("WINEDEBUG")
    if previous is None:
        os.environ["WINEDEBUG"] = "-all"
    try:
        return callback()
    finally:
        if previous is None:
            os.environ.pop("WINEDEBUG", None)


def _failure_message(result: dict) -> str:
    return "\n".join(
        [
            "Wine/DynamoRIO smoke proof failed",
            f"command: {result['command']}",
            f"failures: {result['failures']}",
            f"returncode: {result['returncode']}",
            f"timed_out: {result['timed_out']}",
            f"stderr: {result['stderr']}",
            f"raw_trace: {result['raw_trace']}",
            f"mapped: {result['mapped']}",
            f"trace_log: {result['trace_log']}",
        ]
    )


if __name__ == "__main__":
    unittest.main()
