from __future__ import annotations

from tests.unit.candidate.native_build._support import *


class InterpreterNativeBuildValidationTests(unittest.TestCase):
    def test_rejects_v1_receipt_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            packages.candidate_authority.write_bytes(
                canonical_json_bytes_v3(
                    {
                        "format": "spaghetti-extractor-static-hybrid-closure-receipt-v1",
                        "status": "complete",
                        "authorizes": True,
                    }
                )
            )

            with self.assertRaisesRegex(
                CandidateNativeBuildError, "candidate receipt"
            ):
                build_spx_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )

    def test_rejects_stale_fallback_receipt_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            fallback = json.loads(
                packages.fallback_receipt.read_text(encoding="utf-8")
            )
            fallback["authority"] = "stale-after-candidate-authorization"
            fallback_body = {
                key: value
                for key, value in fallback.items()
                if key != "receipt_sha256"
            }
            fallback["receipt_sha256"] = _canonical_sha256(fallback_body)
            _write_json(packages.fallback_receipt, fallback)

            with self.assertRaisesRegex(
                CandidateNativeBuildError, "stale|different inputs"
            ):
                build_spx_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )

    def test_rejects_stale_runtime_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            source = packages.runtime / "native-runtime.c"
            source.write_text(
                source.read_text(encoding="ascii") + "\n", encoding="ascii"
            )

            with self.assertRaisesRegex(
                CandidateNativeBuildError,
                "native_runtime .* SHA-256 mismatch",
            ):
                build_spx_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    anchor_manifest=packages.anchors,
                    out_dir=Path(temporary) / "candidate",
                )

    def test_rejects_incomplete_package_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            manifest_path = packages.interpreter / "state-machine-interpreter-package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["status"] = "incomplete"
            _write_json(manifest_path, manifest)

            with self.assertRaisesRegex(
                CandidateNativeBuildError, "interpreter package is not ready"
            ):
                build_spx_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    anchor_manifest=packages.anchors,
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )


if __name__ == "__main__":
    unittest.main()
