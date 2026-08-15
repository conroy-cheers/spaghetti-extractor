from __future__ import annotations

from tests.unit.candidate.native_build._support import *


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"), "i686 MinGW compiler unavailable"
)
class InterpreterNativeBuildIntegrationTests(unittest.TestCase):
    def test_compile_keys_track_only_transitive_source_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            baseline = prepare_spx_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=root / "baseline-graph",
            )
            runtime_source = packages.runtime / "native-runtime.c"
            runtime_source.write_text(
                runtime_source.read_text(encoding="ascii") + "\n",
                encoding="ascii",
            )
            _refresh_source_binding(
                packages.runtime / "native-runtime-package.json", runtime_source
            )
            changed = prepare_spx_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=root / "changed-graph",
            )

            baseline_keys = {
                row["id"]: row["compile_key_sha256"] for row in baseline["units"]
            }
            changed_keys = {
                row["id"]: row["compile_key_sha256"] for row in changed["units"]
            }
            changed_ids = {
                unit_id
                for unit_id in baseline_keys
                if baseline_keys[unit_id] != changed_keys[unit_id]
            }
            self.assertEqual(changed_ids, {"native_runtime-native_runtime_source"})
            baseline_bundles = {
                row["unit_id"]: row["bundle_sha256"]
                for row in baseline["bundles"]
            }
            changed_bundles = {
                row["unit_id"]: row["bundle_sha256"]
                for row in changed["bundles"]
            }
            self.assertEqual(
                {
                    unit_id
                    for unit_id in baseline_bundles
                    if baseline_bundles[unit_id] != changed_bundles[unit_id]
                },
                {"native_runtime-native_runtime_source"},
            )

    def test_normalized_source_bundle_compiles_the_same_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            graph_root = root / "graph"
            graph = prepare_spx_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=graph_root,
            )
            bundle_index = json.loads(
                (graph_root / "native-object-bundles.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(bundle_index["bundles"], graph["bundles"])
            self.assertNotIn("/nix/store/", json.dumps(bundle_index))
            binding = graph["bundles"][0]
            direct = compile_spx_interpreter_native_object(
                graph=graph_root,
                unit_id=binding["unit_id"],
                out_dir=root / "direct",
            )
            bundled = compile_spx_interpreter_native_source_bundle(
                source_bundle=graph_root / binding["path"],
                compiler="i686-w64-mingw32-gcc",
                out_dir=root / "bundled",
            )
            self.assertEqual(
                direct["compile_key_sha256"], bundled["compile_key_sha256"]
            )
            self.assertEqual(
                (root / "direct" / "object.o").read_bytes(),
                (root / "bundled" / "object.o").read_bytes(),
            )

    def test_normalized_source_bundle_fails_closed_on_changed_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            graph_root = root / "graph"
            graph = prepare_spx_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=graph_root,
            )
            binding = graph["bundles"][0]
            bundle = graph_root / binding["path"]
            payload = json.loads(
                (bundle / "native-source-bundle.json").read_text(encoding="utf-8")
            )
            source = bundle / payload["source"]["bundle_path"]
            source.write_text(source.read_text(encoding="ascii") + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                CandidateNativeBuildError, "source.*binding is stale"
            ):
                compile_spx_interpreter_native_source_bundle(
                    source_bundle=bundle,
                    compiler="i686-w64-mingw32-gcc",
                    out_dir=root / "object",
                )

    def test_compile_graph_records_exact_quoted_include_closures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            graph = prepare_spx_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=root / "graph",
            )
            rows = {row["id"]: row for row in graph["units"]}
            interpreter_headers = {
                item["path"]
                for item in rows["interpreter-interpreter_source"]["dependencies"]
            }
            self.assertEqual(
                interpreter_headers,
                {
                    "state-machine-interpreter-internal.h",
                    "state-machine-interpreter.h",
                    "state-machine-runtime.h",
                },
            )
            runtime_headers = {
                (item["owner"], item["path"])
                for item in rows["native_runtime-native_runtime_source"][
                    "dependencies"
                ]
            }
            self.assertEqual(
                runtime_headers,
                {
                    ("native_runtime", "native-runtime.h"),
                    ("interpreter", "state-machine-interpreter.h"),
                    ("interpreter", "state-machine-runtime.h"),
                },
            )

    def test_builds_content_bound_relocatable_candidate_and_linker_map(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            manifest = build_spx_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                **packages.release_inputs(),
                out_dir=root / "candidate",
            )
            repeated = build_spx_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                **packages.release_inputs(),
                out_dir=root / "candidate-repeated",
            )
            graph_dir = root / "object-graph"
            graph = prepare_spx_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=graph_dir,
            )
            object_packages = []
            for unit in graph["units"]:
                object_dir = root / "cached-objects" / unit["id"]
                compile_spx_interpreter_native_object(
                    graph=graph_dir, unit_id=unit["id"], out_dir=object_dir
                )
                object_packages.append(object_dir)
            object_package = root / "object-package"
            assemble_spx_interpreter_native_objects(
                graph=graph_dir,
                object_packages=object_packages,
                out_dir=object_package,
            )
            cached = build_spx_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                **packages.release_inputs(),
                precompiled_objects=object_package,
                out_dir=root / "candidate-cached",
            )

            output = root / "candidate"
            repeated_output = root / "candidate-repeated"
            self.assertEqual(manifest, repeated)
            self.assertEqual(
                (output / "candidate.exe").read_bytes(),
                (repeated_output / "candidate.exe").read_bytes(),
            )
            self.assertEqual(
                (output / "payload.map").read_bytes(),
                (repeated_output / "payload.map").read_bytes(),
            )
            self.assertEqual(
                (output / "candidate.exe").read_bytes(),
                (root / "candidate-cached" / "candidate.exe").read_bytes(),
            )
            self.assertEqual(
                cached["policy"]["object_compilation"],
                "content-addressed-per-source",
            )
            self.assertEqual(manifest["format"], INTERPRETER_NATIVE_BUILD_FORMAT)
            self.assertEqual(manifest["status"], "candidate-generated")
            self.assertEqual(manifest["acceptance_authority"], "none")
            self.assertEqual(
                manifest["inputs"]["candidate_authority"]["format"],
                "spaghetti-extractor-candidate-authority-receipt-v3",
            )
            self.assertTrue(
                manifest["inputs"]["candidate_authority"]["authorizes"]
            )
            self.assertEqual(
                manifest["inputs"]["candidate_authority"][
                    "machine_ir_sha256"
                ],
                sha256_file(packages.machine_ir),
            )
            self.assertEqual(
                manifest["inputs"]["candidate_authority"][
                    "fallback_coverage_receipt_sha256"
                ],
                sha256_file(packages.fallback_receipt),
            )
            self.assertEqual(manifest["qualification"]["payload_imports"], 0)
            self.assertFalse(manifest["qualification"]["dynamic_base"])
            self.assertTrue(manifest["qualification"]["relocations_stripped"])
            self.assertTrue(
                manifest["qualification"]["relocation_inventory_complete"]
            )
            self.assertEqual(manifest["qualification"]["base_relocations"], 0)
            self.assertTrue((output / "candidate.exe").is_file())
            self.assertTrue((output / "payload.map").is_file())
            self.assertTrue(
                (output / "executable-anchor-manifest.json").is_file()
            )
            self.assertTrue(
                (output / INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME).is_file()
            )
            self.assertEqual(
                manifest["outputs"]["linker_map"]["sha256"],
                sha256_file(output / "payload.map"),
            )
            for name in (
                "interpreter_package",
                "native_engine_package",
                "native_runtime_package",
            ):
                binding = manifest["inputs"][name]
                self.assertRegex(binding["manifest_sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(binding["artifacts"])

            payload = pefile.PE(str(output / "payload.exe"))
            file_header: Any = payload.FILE_HEADER
            optional: Any = payload.OPTIONAL_HEADER
            self.assertEqual(int(file_header.Machine), 0x14C)
            self.assertEqual(int(optional.Magic), 0x10B)
            self.assertFalse(int(file_header.Characteristics) & 0x0001)
            self.assertTrue(int(optional.DllCharacteristics) & 0x0040)
            self.assertGreater(int(optional.DATA_DIRECTORY[5].Size), 0)
            for index in (1, 9, 12, 13):
                directory = optional.DATA_DIRECTORY[index]
                self.assertEqual(
                    (int(directory.VirtualAddress), int(directory.Size)), (0, 0)
                )
            payload.close()

            candidate: Any = pefile.PE(str(output / "candidate.exe"))
            self.assertTrue(int(candidate.FILE_HEADER.Characteristics) & 0x0001)
            self.assertFalse(int(candidate.OPTIONAL_HEADER.DllCharacteristics) & 0x0040)
            self.assertEqual(int(candidate.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size), 0)
            candidate.close()

            cached_manifest = json.loads(
                (object_package / "native-object-package.json").read_text(
                    encoding="utf-8"
                )
            )
            cached_object = object_package / cached_manifest["objects"][0]["path"]
            cached_object.write_bytes(cached_object.read_bytes() + b"\x00")
            with self.assertRaisesRegex(
                CandidateNativeBuildError,
                "native object package artifact is stale",
            ):
                build_spx_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    precompiled_objects=object_package,
                    out_dir=root / "candidate-tampered-cache",
                )


if __name__ == "__main__":
    unittest.main()
