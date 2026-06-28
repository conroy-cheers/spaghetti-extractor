import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.cli import main
from haloce_catalog.db import connect, initialize
from haloce_catalog.labels import ensure_label, function_label, module_label
from haloce_catalog.routines import classify_functions, upsert_internal_routine_contract
from haloce_catalog.spec_generation import specs_json
from haloce_catalog.util import utc_now


class RoutineClassificationTests(unittest.TestCase):
    def test_classify_functions_updates_unknown_taxonomy_and_label_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            fn_label = self._seed_function(conn)

            with conn:
                result = classify_functions(
                    conn,
                    scopes=("included",),
                    filename="game.exe",
                    subsystem="stateful engine logic",
                    purity="stateful",
                    side_effects="platform calls and deterministic state updates",
                    calling_convention="cdecl",
                    signature="int mainCRTStartup(void)",
                    confidence="high",
                    test_status="specified",
                    clean_room_status="ready",
                    evidence="public behavior contract and oracle fixtures classify the entrypoint",
                )
            function = dict(conn.execute("SELECT * FROM functions WHERE label = ?", (fn_label,)).fetchone())
            label = dict(conn.execute("SELECT description, private FROM labels WHERE label = ?", (fn_label,)).fetchone())
            conn.close()

        self.assertEqual(result["functions"], 1)
        self.assertEqual(function["subsystem"], "stateful engine logic")
        self.assertEqual(function["purity"], "stateful")
        self.assertEqual(function["side_effects"], "platform calls and deterministic state updates")
        self.assertEqual(function["calling_convention"], "cdecl")
        self.assertEqual(function["signature"], "int mainCRTStartup(void)")
        self.assertEqual(function["clean_room_status"], "ready")
        self.assertEqual(label["description"], "public behavior contract and oracle fixtures classify the entrypoint")
        self.assertEqual(label["private"], 0)

    def test_classify_functions_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            self._seed_function(conn)
            conn.close()
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "classify-functions",
                        "--db",
                        str(db_path),
                        "--scope",
                        "included",
                        "--filename",
                        "game.exe",
                        "--subsystem",
                        "stateful engine logic",
                        "--purity",
                        "stateful",
                        "--side-effects",
                        "platform calls and deterministic state updates",
                        "--evidence",
                        "public behavior contract and oracle fixtures classify the entrypoint",
                        "--report-dir",
                        str(root / "reports"),
                    ]
                )

            payload = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(payload["function_classification"]["functions"], 1)

    def test_upsert_internal_routine_contract_records_sanitized_public_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            fn_label = self._seed_function(conn)

            with conn:
                result = upsert_internal_routine_contract(
                    conn,
                    label="routine_entrypoint_transcript_v1",
                    function_label=fn_label,
                    public_name="reference_transcript_entrypoint_v1",
                    purpose_summary="Runs the deterministic transcript mode and writes JSON observations.",
                    calling_convention="cdecl",
                    signature="int mainCRTStartup(void)",
                    input_shape={"argv": ["--json", "--scenario", "name", "--frames", "n", "--seed", "n"]},
                    output_shape={"stdout": "JSON transcript", "exit_code": 0},
                    preconditions=["process command line is readable"],
                    postconditions=["stdout contains one transcript JSON object"],
                    side_effects=["reads process command line", "writes stdout"],
                    state_transitions=["advances fixed-step simulation for requested frames"],
                    fixtures=["expected/orbit-seed7-180.json"],
                    evidence_labels=["behavior_wincr_reference_3d_game"],
                    evidence_source="human_review",
                    confidence="high",
                    taint_level="behavioral_public",
                    review_status="reviewed",
                )
            contract = dict(conn.execute("SELECT * FROM internal_routine_contracts WHERE label = ?", (result["label"],)).fetchone())
            mapping = dict(conn.execute("SELECT * FROM oracle_mappings WHERE label = ?", (result["label"],)).fetchone())
            label = dict(conn.execute("SELECT private FROM labels WHERE label = ?", (result["label"],)).fetchone())
            spec = specs_json(conn)
            conn.close()

        self.assertEqual(result["function_label"], fn_label)
        self.assertEqual(contract["public_name"], "reference_transcript_entrypoint_v1")
        self.assertEqual(mapping["entity_type"], "internal_routine_contract")
        self.assertEqual(mapping["module_sha256"], "c" * 64)
        self.assertEqual(mapping["rva_start"], 0x1000)
        self.assertEqual(label["private"], 0)
        self.assertEqual(len(spec["internal_routine_contracts"]), 1)
        public = spec["internal_routine_contracts"][0]
        self.assertEqual(public["function_label"], fn_label)
        self.assertEqual(public["input_shape"]["argv"][0], "--json")
        self.assertNotIn("module_sha256", json.dumps(public))
        self.assertNotIn("rva_start", public)
        self.assertNotIn("rva_end", public)
        self.assertNotIn("rva", public)

    def test_internal_routine_contract_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            fn_label = self._seed_function(conn)
            conn.close()
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "upsert-internal-routine-contract",
                        "--db",
                        str(db_path),
                        "--label",
                        "routine_entrypoint_transcript_v1",
                        "--function-label",
                        fn_label,
                        "--public-name",
                        "reference_transcript_entrypoint_v1",
                        "--purpose-summary",
                        "Runs deterministic transcript mode.",
                        "--calling-convention",
                        "cdecl",
                        "--signature",
                        "int mainCRTStartup(void)",
                        "--input-shape-json",
                        '{"argv":["--json"]}',
                        "--output-shape-json",
                        '{"stdout":"JSON transcript"}',
                        "--precondition",
                        "process command line is readable",
                        "--postcondition",
                        "stdout contains transcript JSON",
                        "--side-effect",
                        "writes stdout",
                        "--state-transition",
                        "advances fixed-step simulation",
                        "--fixture",
                        "expected/orbit-seed7-180.json",
                        "--evidence-label",
                        "behavior_wincr_reference_3d_game",
                        "--evidence-source",
                        "human_review",
                        "--confidence",
                        "high",
                        "--taint-level",
                        "behavioral_public",
                        "--review-status",
                        "reviewed",
                        "--report-dir",
                        str(root / "reports"),
                    ]
                )

            payload = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(payload["internal_routine_contract"]["label"], "routine_entrypoint_transcript_v1")
            self.assertTrue((root / "reports" / "specs.json").exists())

    def _seed_function(self, conn) -> str:
        created = utc_now()
        binary_label = module_label("bin/game.exe", "c" * 64)
        fn_label = function_label(binary_label, 0x1000, "seed", "entrypoint")
        with conn:
            ensure_label(conn, binary_label, "module", "bin/game.exe", created_at=created)
            cursor = conn.execute(
                """
                INSERT INTO binaries(
                  label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                  entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                  role, scope, role_reason, source_root, catalog_version, discovered_at
                )
                VALUES (?, 'bin/game.exe', 'game.exe', ?, 1, 'exe', 'i386', 0,
                        4194304, 4096, 8192, 'windows_cui', '0.0', 0,
                        'closed_runtime', 'included', 'test binary', '/tmp/ref', 'test', ?)
                """,
                (binary_label, "c" * 64, created),
            )
            binary_id = int(cursor.lastrowid)
            ensure_label(conn, fn_label, "function", "entrypoint", created_at=created)
            conn.execute(
                """
                INSERT INTO functions(label, binary_id, rva, name, source)
                VALUES (?, ?, 4096, 'entrypoint', 'seed')
                """,
                (fn_label, binary_id),
            )
        return fn_label


if __name__ == "__main__":
    unittest.main()
