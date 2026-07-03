from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .behavior import (
    BEHAVIOR_OBSERVATION_STATUSES,
    compare_json_behavior,
    compare_json_spec_observations,
    compare_process_spec_observations,
    load_json_file,
    record_behavior_observation,
    record_process_behavior_observation,
    run_clean_spec_suite,
    run_json_behavior_observation,
    run_process_behavior_observation,
    upsert_behavior_contract,
)
from .block_suite import gate_block_suite, generate_block_suite
from .byteclasses import rebuild_executable_byte_classes
from .catalog import build_catalog, resolve_install_root
from .clean_derivation import derive_clean_specs, promote_clean_templates, validate_clean_specs
from .coverage import (
    doctor_drcov,
    ingest_drcov,
    ingest_halo_trace,
    ingest_trace,
    prove_halo_trace,
    prove_halo_trace_log,
    prove_trace,
    prove_trace_log,
    run_drcov,
)
from .data_state import (
    DATA_STATE_TEST_STATUSES,
    ROUND_TRIP_KINDS,
    TRANSITION_KINDS,
    record_data_state_test_case,
    upsert_data_structure,
)
from .db import connect, initialize
from .ghidra import import_ghidra_json, run_ghidra_export
from .harness import (
    INTERNAL_HARNESS_KINDS,
    INTERNAL_HARNESS_STATUSES,
    record_internal_harness_run,
    run_internal_harness,
    upsert_internal_harness,
)
from .input_trace import list_input_devices, record_input_trace, replay_input_trace, summarize_input_trace
from .interfaces import (
    INTERFACE_TEST_STATUSES,
    REQUIRED_INTERFACE_CASES,
    record_interface_test_case,
    record_mock_interface_suite,
    record_observed_interface_suite,
)
from .labels import ensure_label, ensure_oracle_mapping, waiver_label
from .mutation import MUTATION_TEST_STATUSES, REQUIRED_MUTATION_KINDS, record_mutation_test_case
from .mutation import run_json_mutation_test
from .oracle import (
    ORACLE_CASE_KINDS,
    ORACLE_TEST_STATUSES,
    REQUIRED_ORACLE_PROCESS_SUITES,
    record_oracle_test_case,
    run_oracle_process_test,
)
from .private_artifacts import export_private_artifacts, validate_dirty_corpus
from .reports import gates_json, generate_reports
from .routines import (
    ROUTINE_CONTRACT_CONFIDENCE,
    ROUTINE_CONTRACT_EVIDENCE_SOURCES,
    ROUTINE_CONTRACT_REVIEW_STATUSES,
    ROUTINE_CONTRACT_TAINT_LEVELS,
    classify_functions,
    parse_contract_json,
    upsert_internal_routine_contract,
)
from .static_crosscheck import DEFAULT_STATIC_CROSS_CHECK_TOOLS, run_static_cross_checks
from .target import TargetConfig, load_target_config, target_lists_from_metadata
from .util import utc_now
from .wine_probe import probe_wine_trace_matrix
from .workbench import (
    refresh_content_manifest,
    render_dirty_corpus,
    review_dirty_corpus,
    write_cli_index,
    write_reimplementation_plan,
)
from .windows_vm import (
    WindowsVmConfig,
    check_vfio_host,
    generate_windows_vm_bundle,
    run_windows_guest_trace,
    replay_qmp_input_events,
    write_qmp_input_events,
)


def main(argv: list[str] | None = None, *, prog: str | None = None) -> int:
    parser = argparse.ArgumentParser(prog=prog or (Path(sys.argv[0]).name if argv is None else "wincr"))
    subcommands = parser.add_subparsers(dest="command", required=True)

    build = subcommands.add_parser("build", help="build SQLite catalog and generated reports")
    _add_target_config(build)
    build.add_argument("--install-root", help="target install root; defaults to the manifest install-root environment variable")
    build.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    build.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    build.add_argument("--static-depth", choices=["none", "included", "candidate", "all"], default="none")
    build.add_argument(
        "--max-disassembly-bytes",
        type=int,
        default=6 * 1024 * 1024,
        help="per-binary Capstone byte cap for optional block discovery; 0 means unlimited",
    )
    build.set_defaults(func=_cmd_build)

    analyze = subcommands.add_parser(
        "analyze-reference",
        help="build the reference catalog, import Ghidra metadata, run static cross-checks, and regenerate reports",
    )
    _add_target_config(analyze)
    analyze.add_argument("--install-root", help="target install root; defaults to the manifest install-root environment variable")
    analyze.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    analyze.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    analyze.add_argument("--static-depth", choices=["none", "included", "candidate", "all"], default="none")
    analyze.add_argument(
        "--max-disassembly-bytes",
        type=int,
        default=6 * 1024 * 1024,
        help="per-binary Capstone byte cap for optional block discovery; 0 means unlimited",
    )
    analyze.add_argument(
        "--ghidra-filename",
        dest="ghidra_filenames",
        action="append",
        help=(
            "PE filename to export through Ghidra; repeatable. "
            "When omitted, all included and candidate runtime PEs are exported."
        ),
    )
    analyze.add_argument("--skip-ghidra", action="store_true", help="skip Ghidra export/import")
    analyze.add_argument("--ghidra-out-dir", type=Path, default=Path("build/ghidra/exports"))
    analyze.add_argument("--ghidra-project-dir", type=Path, default=Path("build/ghidra/projects"))
    analyze.add_argument("--ghidra-project-name", default="halo-catalog")
    analyze.add_argument("--analyze-headless", help="path to analyzeHeadless; defaults to HALOCE_GHIDRA_HEADLESS/PATH")
    analyze.add_argument("--script-path", type=Path, help="directory containing HaloCatalogExport.java")
    analyze.add_argument("--ghidra-timeout-seconds", type=int, help="per-binary Ghidra timeout")
    analyze.add_argument("--skip-static-cross-check", action="store_true", help="skip LLVM/rizin static cross-checks")
    analyze.add_argument(
        "--static-tool",
        dest="static_tools",
        action="append",
        choices=["llvm-readobj", "rizin", "r2", "radare2"],
        help="static cross-check tool; repeatable, defaults to llvm-readobj and rizin",
    )
    analyze.add_argument(
        "--static-scope",
        dest="static_scopes",
        action="append",
        choices=["included", "candidate", "excluded"],
        help="catalog scope to cross-check; repeatable, defaults to included and candidate",
    )
    analyze.add_argument("--static-timeout-seconds", type=int, default=60)
    analyze.set_defaults(func=_cmd_analyze_reference)

    report = subcommands.add_parser("report", help="regenerate JSON/Markdown reports from a catalog database")
    report.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    report.add_argument("--out-dir", type=Path, default=Path("build/reports"))
    report.set_defaults(func=_cmd_report)

    private_artifacts = subcommands.add_parser(
        "export-private-artifacts",
        aliases=["export-dirty-corpus"],
        help="export private dirty evidence packets for human/LLM clean-spec derivation",
    )
    private_artifacts.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    private_artifacts.add_argument("--out-dir", type=Path, default=Path("private/wincr-artifacts"))
    private_artifacts.add_argument("--artifact-set-id")
    private_artifacts.add_argument(
        "--scope",
        dest="scopes",
        action="append",
        choices=["included", "candidate", "excluded"],
        help="binary scope to include; repeatable, defaults to included and candidate",
    )
    private_artifacts.add_argument("--skip-disassembly", action="store_true")
    private_artifacts.add_argument("--objdump", default="llvm-objdump")
    private_artifacts.add_argument("--objdump-timeout-seconds", type=int, default=60)
    private_artifacts.add_argument(
        "--no-copy-raw-evidence",
        dest="copy_raw_evidence",
        action="store_false",
        help="record raw evidence paths/hashes but do not copy small text-like sidecars into review packets",
    )
    private_artifacts.add_argument(
        "--max-raw-evidence-bytes",
        type=int,
        default=4 * 1024 * 1024,
        help="maximum size for copying allowlisted raw evidence sidecars into review packets",
    )
    private_artifacts.add_argument(
        "--no-clean",
        dest="clean",
        action="store_false",
        help="do not remove existing generated files under the private artifact root before export",
    )
    private_artifacts.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    private_artifacts.set_defaults(func=_cmd_export_private_artifacts)

    validate_dirty = subcommands.add_parser(
        "validate-dirty-corpus",
        help="validate a private dirty corpus for review packet, dossier, and evidence completeness",
    )
    validate_dirty.add_argument("--corpus-dir", type=Path, default=Path("private/wincr-artifacts"))
    validate_dirty.add_argument("--report-json", type=Path)
    validate_dirty.add_argument("--report-md", type=Path)
    validate_dirty.set_defaults(func=_cmd_validate_dirty_corpus)

    render_dirty = subcommands.add_parser(
        "render-dirty-corpus",
        help="render an offline HTML reimplementation workbench for a private dirty corpus",
    )
    render_dirty.add_argument("--corpus-dir", type=Path, default=Path("private/wincr-artifacts"))
    render_dirty.add_argument("--out-dir", type=Path, required=True)
    render_dirty.set_defaults(func=_cmd_render_dirty_corpus)

    review_dirty = subcommands.add_parser(
        "review-dirty-corpus",
        help="query or interactively review a private dirty corpus label/task index",
    )
    review_dirty.add_argument("--corpus-dir", type=Path, default=Path("private/wincr-artifacts"))
    review_dirty.add_argument("--search")
    review_dirty.add_argument("--label")
    review_dirty.add_argument("--todos", action="store_true")
    review_dirty.add_argument("--summary", action="store_true")
    review_dirty.add_argument("--interactive", action="store_true")
    review_dirty.set_defaults(func=_cmd_review_dirty_corpus)

    clean_specs = subcommands.add_parser(
        "derive-clean-specs",
        help="derive public clean specs/tests from reviewed clean templates in a private dirty corpus",
    )
    clean_specs.add_argument("--corpus-dir", type=Path, default=Path("private/wincr-artifacts"))
    clean_specs.add_argument("--out-dir", type=Path, default=Path("build/clean-specs"))
    clean_specs.set_defaults(func=_cmd_derive_clean_specs)

    promote_templates = subcommands.add_parser(
        "promote-clean-templates",
        help="mark reviewed clean templates publishable after validating public fields",
    )
    promote_templates.add_argument("--corpus-dir", type=Path, default=Path("private/wincr-artifacts"))
    promote_templates.add_argument("--reviewer", required=True)
    promote_templates.add_argument("--entity-type", dest="entity_types", action="append")
    promote_templates.add_argument("--category", dest="categories", action="append")
    promote_templates.add_argument(
        "--publication-decision",
        choices=["publish", "public", "approved", "reviewed_public"],
        default="publish",
    )
    promote_templates.add_argument("--note")
    promote_templates.add_argument("--dry-run", action="store_true")
    promote_templates.set_defaults(func=_cmd_promote_clean_templates)

    validate_clean = subcommands.add_parser(
        "validate-clean-specs",
        help="validate derived clean specs/tests for public leakage and structural completeness",
    )
    validate_clean.add_argument("--spec-json", type=Path, required=True)
    validate_clean.add_argument("--tests-json", type=Path)
    validate_clean.set_defaults(func=_cmd_validate_clean_specs)

    byte_classes = subcommands.add_parser(
        "rebuild-byte-classes",
        help="rebuild executable-byte classifications from ranges, blocks, coverage, and waivers",
    )
    byte_classes.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    byte_classes.add_argument("--binary-id", type=int)
    byte_classes.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    byte_classes.set_defaults(func=_cmd_rebuild_byte_classes)

    static_check = subcommands.add_parser(
        "cross-check-static",
        help="cross-check cataloged PE sections with LLVM and rizin/radare2 metadata",
    )
    static_check.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    static_check.add_argument(
        "--tool",
        dest="tools",
        action="append",
        choices=["llvm-readobj", "rizin", "r2", "radare2"],
        help="tool to run; repeatable, defaults to llvm-readobj and rizin",
    )
    static_check.add_argument(
        "--scope",
        dest="scopes",
        action="append",
        choices=["included", "candidate", "excluded"],
        help="catalog scope to cross-check; repeatable, defaults to included and candidate",
    )
    static_check.add_argument("--filename", dest="filenames", action="append", help="PE filename filter; repeatable")
    static_check.add_argument("--timeout-seconds", type=int, default=30)
    static_check.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    static_check.set_defaults(func=_cmd_cross_check_static)

    ingest = subcommands.add_parser("ingest-drcov", help="ingest a DynamoRIO drcov log")
    ingest.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    ingest.add_argument("--log", type=Path, required=True)
    ingest.add_argument("--test-id", required=True)
    ingest.add_argument("--suite", default="drcov")
    ingest.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    ingest.set_defaults(func=_cmd_ingest_drcov)

    halo_trace = subcommands.add_parser("ingest-halo-trace", help="ingest JSONL from the custom DynamoRIO tracer")
    halo_trace.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    halo_trace.add_argument("--log", type=Path, required=True)
    halo_trace.add_argument("--suite", default="halo-trace")
    halo_trace.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    halo_trace.set_defaults(func=_cmd_ingest_halo_trace)

    trace = subcommands.add_parser("ingest-trace", help="ingest JSONL from the custom DynamoRIO tracer")
    trace.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    trace.add_argument("--log", type=Path, required=True)
    trace.add_argument("--suite", default="trace")
    trace.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    trace.set_defaults(func=_cmd_ingest_trace)

    prove_trace = subcommands.add_parser(
        "prove-halo-trace",
        help="run and ingest the custom DynamoRIO tracer, then assert mapped block/edge/call evidence",
    )
    prove_trace.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    prove_trace.add_argument("--out", type=Path, required=True, help="JSONL trace output path")
    prove_trace.add_argument("--test-id", required=True)
    prove_trace.add_argument("--expected-filename", help="cataloged PE filename expected to produce mapped trace events")
    prove_trace.add_argument("--expected-sha256", help="cataloged module SHA256 expected to produce mapped trace events")
    prove_trace.add_argument("--arch", choices=["auto", "32", "64"], default="auto")
    prove_trace.add_argument("--trace-runner", help="path to trace runner; defaults to WINCR_TRACE_RUNNER/HALOCE_TRACE_RUNNER/PATH")
    prove_trace.add_argument("--timeout-seconds", type=int, default=45)
    prove_trace.add_argument("--fail-on-timeout", action="store_true", help="treat a traced process timeout as a failure")
    prove_trace.add_argument("--expected-returncode", type=int, default=0, help="expected traced process exit code")
    prove_trace.add_argument("--semantic-profile", action="store_true", help="capture bounded private semantic values")
    prove_trace.add_argument("--semantic-max-records", type=int, default=128)
    prove_trace.add_argument("--block-state-trace", action="store_true", help="capture block-local pre/post state and side effects")
    prove_trace.add_argument("--block-state-max-records", type=int, default=8192)
    prove_trace.add_argument("--pretraced", action="store_true", help="run app directly; it must write HALOCE_TRACE_OUT")
    prove_trace.add_argument("--suite", default="halo-trace")
    prove_trace.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    prove_trace.add_argument("app", nargs=argparse.REMAINDER)
    prove_trace.set_defaults(func=_cmd_prove_halo_trace)

    prove_trace_generic = subcommands.add_parser(
        "prove-trace",
        help="run and ingest the custom DynamoRIO tracer, then assert mapped block/edge/call evidence",
    )
    prove_trace_generic.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    prove_trace_generic.add_argument("--out", type=Path, required=True, help="JSONL trace output path")
    prove_trace_generic.add_argument("--test-id", required=True)
    prove_trace_generic.add_argument("--expected-filename", help="cataloged PE filename expected to produce mapped trace events")
    prove_trace_generic.add_argument("--expected-sha256", help="cataloged module SHA256 expected to produce mapped trace events")
    prove_trace_generic.add_argument("--arch", choices=["auto", "32", "64"], default="auto")
    prove_trace_generic.add_argument("--trace-runner", help="path to trace runner; defaults to WINCR_TRACE_RUNNER/HALOCE_TRACE_RUNNER/PATH")
    prove_trace_generic.add_argument("--timeout-seconds", type=int, default=45)
    prove_trace_generic.add_argument("--fail-on-timeout", action="store_true", help="treat a traced process timeout as a failure")
    prove_trace_generic.add_argument("--expected-returncode", type=int, default=0, help="expected traced process exit code")
    prove_trace_generic.add_argument("--semantic-profile", action="store_true", help="capture bounded private semantic values")
    prove_trace_generic.add_argument("--semantic-max-records", type=int, default=128)
    prove_trace_generic.add_argument("--block-state-trace", action="store_true", help="capture block-local pre/post state and side effects")
    prove_trace_generic.add_argument("--block-state-max-records", type=int, default=8192)
    prove_trace_generic.add_argument("--pretraced", action="store_true", help="run app directly; it must write WINCR_TRACE_OUT")
    prove_trace_generic.add_argument("--suite", default="trace")
    prove_trace_generic.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    prove_trace_generic.add_argument("app", nargs=argparse.REMAINDER)
    prove_trace_generic.set_defaults(func=_cmd_prove_trace)

    block_suite = subcommands.add_parser(
        "generate-block-suite",
        help="generate a private full-coverage block conformance suite from included binaries and captured traces",
    )
    _add_target_config(block_suite)
    block_suite.add_argument("--binary-root", type=Path, required=True, help="runtime root used to resolve included manifest binaries")
    block_suite.add_argument("--binary", dest="binaries", type=Path, action="append", help="included binary path; repeatable")
    block_suite.add_argument("--trace-dir", type=Path, help="directory containing captured trace JSONL files")
    block_suite.add_argument("--trace", dest="traces", type=Path, action="append", help="trace JSONL file; repeatable")
    block_suite.add_argument("--out-dir", type=Path, required=True)
    block_suite.add_argument("--wincr-block", default="wincr-block", help="wincr-block executable")
    block_suite.add_argument("--max-cases-per-block", type=int)
    block_suite.add_argument("--no-clean", dest="clean", action="store_false", help="do not remove existing suite output before generation")
    block_suite.set_defaults(func=_cmd_generate_block_suite, clean=True)

    block_suite_gate = subcommands.add_parser(
        "block-suite-gate",
        help="fail unless a generated block conformance suite has no unresolved gaps",
    )
    block_suite_gate.add_argument("--suite", type=Path, required=True)
    block_suite_gate.set_defaults(func=_cmd_block_suite_gate)

    wine_probe = subcommands.add_parser(
        "probe-wine-trace",
        help="run the public 32-bit PE trace proof across candidate Wine commands",
    )
    wine_probe.add_argument("--smoke-root", type=Path, help="result root from halo-trace-win32-smoke-root")
    wine_probe.add_argument("--smoke-exe", type=Path, help="explicit halo-trace-win32-smoke.exe path")
    wine_probe.add_argument("--out-dir", type=Path, default=Path("build/wine-trace-probes"))
    wine_probe.add_argument(
        "--wine-command",
        action="append",
        default=[],
        help="Wine command to test; repeatable, defaults to 'wine'. Quote arguments as one shell-style value.",
    )
    wine_probe.add_argument("--trace-runner", help="path to halo-trace-run; defaults to HALOCE_TRACE_RUNNER/PATH")
    wine_probe.add_argument("--arch", choices=["auto", "32", "64"], default="auto")
    wine_probe.add_argument("--timeout-seconds", type=int, default=30)
    wine_probe.add_argument("--wine-debug", default="-all", help="WINEDEBUG value when not already set; use empty string to leave unset")
    wine_probe.add_argument("--wait-wineserver", action="store_true", help="run wineserver -w after the direct launch warm-up")
    wine_probe.add_argument(
        "--isolate-catalog-build",
        action="store_true",
        help="build the smoke catalog in a helper process before tracing Wine",
    )
    wine_probe.add_argument(
        "--isolate-trace-proof",
        action="store_true",
        help="run the DynamoRIO trace proof in a helper process after the direct Wine warm-up",
    )
    wine_probe.set_defaults(func=_cmd_probe_wine_trace)

    windows_vm = subcommands.add_parser(
        "generate-windows-vm",
        help="generate private Windows VM XML, unattended install, and guest trace scripts",
    )
    _add_target_config(windows_vm)
    windows_vm.add_argument("--out-dir", type=Path, default=Path("build/windows-vm"))
    windows_vm.add_argument("--name")
    windows_vm.add_argument("--memory-mib", type=int, default=8192)
    windows_vm.add_argument("--vcpus", type=int, default=4)
    windows_vm.add_argument("--disk", type=Path)
    windows_vm.add_argument("--windows-iso", type=Path)
    windows_vm.add_argument("--autounattend-iso", type=Path, default=Path("build/windows-vm/autounattend.iso"))
    windows_vm.add_argument("--virtio-iso", type=Path)
    windows_vm.add_argument("--spice-tools-iso", type=Path)
    windows_vm.add_argument("--shared-dir", type=Path, default=Path("private/windows-vm/share"))
    windows_vm.add_argument("--ovmf-code", type=Path, default=Path("/run/libvirt/nix-ovmf/edk2-x86_64-code.fd"))
    windows_vm.add_argument("--ovmf-vars", type=Path, default=Path("private/windows-vm/OVMF_VARS.fd"))
    windows_vm.add_argument("--ovmf-vars-template", type=Path, default=Path("/run/libvirt/nix-ovmf/edk2-x86_64-vars.fd"))
    windows_vm.add_argument("--qmp-socket", type=Path, default=Path("build/windows-vm/qmp.sock"))
    windows_vm.add_argument("--admin-user")
    windows_vm.add_argument("--admin-password")
    windows_vm.add_argument("--dynamorio-root", type=Path)
    windows_vm.add_argument("--trace-client-dll", type=Path)
    windows_vm.add_argument("--halo-runtime-root", type=Path, help="legacy alias for --runtime-root")
    windows_vm.add_argument("--runtime-root", type=Path, help="target runtime directory staged into the Windows guest")
    windows_vm.add_argument("--virtio-tools-root", type=Path)
    windows_vm.add_argument("--spice-tools-root", type=Path)
    windows_vm.add_argument("--install-image-index", type=int, default=1)
    windows_vm.add_argument("--gpu-pci-address", action="append", default=[])
    windows_vm.add_argument("--usb-vendor-product", action="append", default=[])
    windows_vm.add_argument(
        "--display-mode",
        choices=["spice-qxl", "gpu-only"],
        default="spice-qxl",
        help="guest display profile: SPICE/QXL for provisioning, or GPU-only for passthrough client traces",
    )
    windows_vm.add_argument("--network", default="default")
    windows_vm.add_argument("--libvirt-uri", default="qemu:///system")
    windows_vm.add_argument("--xorriso", default="xorriso")
    windows_vm.set_defaults(func=_cmd_generate_windows_vm)

    qmp_input = subcommands.add_parser(
        "emit-qmp-input",
        help="convert a private evdev input trace to QMP input-send-event JSONL",
    )
    qmp_input.add_argument("--log", type=Path, required=True)
    qmp_input.add_argument("--out", type=Path, required=True)
    qmp_input.set_defaults(func=_cmd_emit_qmp_input)

    qmp_replay = subcommands.add_parser(
        "replay-qmp-input",
        help="replay QMP input-send-event JSONL into a running Windows VM",
    )
    qmp_replay.add_argument("--log", type=Path, required=True, help="QMP JSONL generated by emit-qmp-input")
    qmp_replay.add_argument("--socket", type=Path, help="raw QMP UNIX socket path")
    qmp_replay.add_argument("--domain", help="libvirt domain name for virsh qemu-monitor-command")
    qmp_replay.add_argument("--virsh", default="virsh")
    qmp_replay.add_argument("--virsh-uri", default="qemu:///system")
    qmp_replay.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    qmp_replay.add_argument("--dry-run", action="store_true")
    qmp_replay.set_defaults(func=_cmd_replay_qmp_input)

    windows_guest_trace = subcommands.add_parser(
        "run-windows-guest-trace",
        help="run the generated Windows guest trace script over OpenSSH and copy logs back",
    )
    _add_target_config(windows_guest_trace)
    windows_guest_trace.add_argument("--host", required=True)
    windows_guest_trace.add_argument("--user")
    windows_guest_trace.add_argument("--out-dir", type=Path, default=Path("private/windows-vm/logs"))
    windows_guest_trace.add_argument("--target")
    windows_guest_trace.add_argument("--run-seconds", type=int, default=45)
    windows_guest_trace.add_argument("--test-id-prefix", default="windows-vm")
    windows_guest_trace.add_argument("--block-state-trace", action="store_true", help="capture per-block pre/post state and side-effect records in the guest")
    windows_guest_trace.add_argument("--block-state-max-records", type=int, default=8192)
    windows_guest_trace.add_argument("--password", default="", help="password for generated password-only Windows trace VMs")
    windows_guest_trace.add_argument("--sshpass", default="sshpass", help="sshpass executable used when --password is set")
    windows_guest_trace.add_argument("--ssh", default="ssh")
    windows_guest_trace.add_argument("--scp", default="scp")
    windows_guest_trace.add_argument("--copy-all-logs", action="store_true", help="copy the whole guest log directory instead of only this test's files")
    windows_guest_trace.set_defaults(func=_cmd_run_windows_guest_trace)

    prove_windows_guest_trace = subcommands.add_parser(
        "prove-windows-guest-trace",
        help="run a Windows guest trace, copy logs back, ingest them, and require mapped PE coverage",
    )
    _add_target_config(prove_windows_guest_trace)
    prove_windows_guest_trace.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    prove_windows_guest_trace.add_argument("--host", required=True)
    prove_windows_guest_trace.add_argument("--user")
    prove_windows_guest_trace.add_argument("--out-dir", type=Path, default=Path("private/windows-vm/logs"))
    prove_windows_guest_trace.add_argument("--target")
    prove_windows_guest_trace.add_argument("--run-seconds", type=int, default=45)
    prove_windows_guest_trace.add_argument("--test-id-prefix", default="windows-vm")
    prove_windows_guest_trace.add_argument("--block-state-trace", action="store_true", help="capture per-block pre/post state and side-effect records in the guest")
    prove_windows_guest_trace.add_argument("--block-state-max-records", type=int, default=8192)
    prove_windows_guest_trace.add_argument("--expected-filename")
    prove_windows_guest_trace.add_argument("--expected-sha256")
    prove_windows_guest_trace.add_argument("--trace-log", type=Path, help="copied JSONL trace path; defaults to <out-dir>/<test-id>.jsonl")
    prove_windows_guest_trace.add_argument("--suite", default="windows-vm")
    prove_windows_guest_trace.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    prove_windows_guest_trace.add_argument("--skip-reports", action="store_true", help="skip heavyweight report regeneration after proof ingestion")
    prove_windows_guest_trace.add_argument("--fail-on-timeout", action="store_true", help="treat guest target timeout as a proof failure")
    prove_windows_guest_trace.add_argument("--password", default="", help="password for generated password-only Windows trace VMs")
    prove_windows_guest_trace.add_argument("--sshpass", default="sshpass", help="sshpass executable used when --password is set")
    prove_windows_guest_trace.add_argument("--ssh", default="ssh")
    prove_windows_guest_trace.add_argument("--scp", default="scp")
    prove_windows_guest_trace.add_argument("--copy-all-logs", action="store_true", help="copy the whole guest log directory instead of only this test's files")
    prove_windows_guest_trace.set_defaults(func=_cmd_prove_windows_guest_trace)

    vfio_check = subcommands.add_parser(
        "check-vfio-host",
        help="check whether host PCI devices are ready for VFIO/libvirt passthrough",
    )
    vfio_check.add_argument("--pci-address", action="append", required=True, help="PCI address to check, e.g. 0000:12:00.0")
    vfio_check.add_argument("--required-kernel-param", action="append", default=[], help="kernel command-line token that must be present")
    vfio_check.add_argument("--expected-driver", default="vfio-pci")
    vfio_check.set_defaults(func=_cmd_check_vfio_host)

    run = subcommands.add_parser("run-drcov", help="run an application under DynamoRIO drcov")
    run.add_argument("--log-dir", type=Path, default=Path("build/drcov"))
    run.add_argument("--timeout-seconds", type=int)
    run.add_argument("app", nargs=argparse.REMAINDER)
    run.set_defaults(func=_cmd_run_drcov)

    interface_test = subcommands.add_parser(
        "record-interface-test",
        help="record success/failure/error-path coverage for a platform endpoint mock",
    )
    interface_test.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    interface_test.add_argument("--endpoint-label", required=True)
    interface_test.add_argument("--case-kind", choices=REQUIRED_INTERFACE_CASES, required=True)
    interface_test.add_argument("--test-id", required=True)
    interface_test.add_argument("--status", choices=INTERFACE_TEST_STATUSES, default="pass")
    interface_test.add_argument("--evidence", default="")
    interface_test.add_argument("--fixture-path", type=Path)
    interface_test.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    interface_test.set_defaults(func=_cmd_record_interface_test)

    interface_suite = subcommands.add_parser(
        "record-mock-interface-suite",
        help="record the built-in public mock suite for known platform endpoints",
    )
    interface_suite.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    interface_suite.add_argument("--status", choices=INTERFACE_TEST_STATUSES, default="pass")
    interface_suite.add_argument(
        "--evidence",
        default="public mock behavior suite covers success, failure, and error-path behavior",
    )
    interface_suite.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    interface_suite.set_defaults(func=_cmd_record_mock_interface_suite)

    observed_interface_suite = subcommands.add_parser(
        "record-observed-interface-suite",
        help="mark catalog-observed platform endpoints as covered by a target-owned mock/shim suite",
    )
    observed_interface_suite.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    observed_interface_suite.add_argument(
        "--scope",
        action="append",
        choices=["included", "candidate"],
        help="binary scope to cover; repeatable, defaults to included and candidate",
    )
    observed_interface_suite.add_argument("--status", choices=INTERFACE_TEST_STATUSES, default="pass")
    observed_interface_suite.add_argument("--test-id-prefix", default="observed-interface")
    observed_interface_suite.add_argument("--evidence", required=True)
    observed_interface_suite.add_argument("--fixture-path", type=Path)
    observed_interface_suite.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    observed_interface_suite.set_defaults(func=_cmd_record_observed_interface_suite)

    data_structure = subcommands.add_parser(
        "upsert-data-structure",
        help="add or update a map/profile/save/packet/config/state-machine spec target",
    )
    data_structure.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    data_structure.add_argument("--name", required=True)
    data_structure.add_argument("--structure-kind", required=True)
    data_structure.add_argument("--spec-status", default="unknown")
    data_structure.add_argument("--fixture-status", default="missing")
    data_structure.add_argument("--description", default="")
    data_structure.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    data_structure.set_defaults(func=_cmd_upsert_data_structure)

    data_state_test = subcommands.add_parser(
        "record-data-state-test",
        help="record fixture/malformed/transition/round-trip evidence for a data structure",
    )
    data_state_test.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    data_state_test.add_argument("--data-structure-label", required=True)
    data_state_test.add_argument("--case-kind", required=True)
    data_state_test.add_argument("--test-id", required=True)
    data_state_test.add_argument("--status", choices=DATA_STATE_TEST_STATUSES, default="pass")
    data_state_test.add_argument("--evidence", default="")
    data_state_test.add_argument("--fixture-path", type=Path)
    data_state_test.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    data_state_test.set_defaults(func=_cmd_record_data_state_test)

    classify = subcommands.add_parser(
        "classify-functions",
        help="apply target-owned taxonomy/spec status to cataloged functions",
    )
    classify.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    classify.add_argument("--scope", action="append", choices=["included", "candidate"], help="binary scope to classify; repeatable")
    classify.add_argument("--filename")
    classify.add_argument("--function-label")
    classify.add_argument("--name")
    classify.add_argument("--source")
    classify.add_argument("--subsystem", required=True)
    classify.add_argument("--purity", required=True)
    classify.add_argument("--side-effects", required=True)
    classify.add_argument("--calling-convention")
    classify.add_argument("--signature")
    classify.add_argument("--confidence", default="medium")
    classify.add_argument("--test-status", default="specified")
    classify.add_argument("--clean-room-status", default="ready")
    classify.add_argument("--evidence", required=True)
    classify.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    classify.set_defaults(func=_cmd_classify_functions)

    routine_contract = subcommands.add_parser(
        "upsert-internal-routine-contract",
        help="add or update a sanitized label-first internal routine behavior contract",
    )
    routine_contract.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    routine_contract.add_argument("--label", required=True, help="stable public routine-contract label")
    routine_contract.add_argument("--function-label", required=True, help="catalog function label with private hash/RVA mapping")
    routine_contract.add_argument("--public-name", required=True)
    routine_contract.add_argument("--purpose-summary", required=True)
    routine_contract.add_argument("--calling-convention", required=True)
    routine_contract.add_argument("--signature", required=True)
    routine_contract.add_argument("--input-shape-json", default="{}")
    routine_contract.add_argument("--output-shape-json", default="{}")
    routine_contract.add_argument("--precondition", action="append", default=[])
    routine_contract.add_argument("--postcondition", action="append", default=[])
    routine_contract.add_argument("--side-effect", action="append", default=[])
    routine_contract.add_argument("--state-transition", action="append", default=[])
    routine_contract.add_argument("--fixture", action="append", default=[])
    routine_contract.add_argument("--evidence-label", action="append", default=[])
    routine_contract.add_argument("--evidence-source", choices=sorted(ROUTINE_CONTRACT_EVIDENCE_SOURCES), required=True)
    routine_contract.add_argument("--confidence", choices=sorted(ROUTINE_CONTRACT_CONFIDENCE), required=True)
    routine_contract.add_argument("--taint-level", choices=sorted(ROUTINE_CONTRACT_TAINT_LEVELS), required=True)
    routine_contract.add_argument("--review-status", choices=sorted(ROUTINE_CONTRACT_REVIEW_STATUSES), required=True)
    routine_contract.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    routine_contract.set_defaults(func=_cmd_upsert_internal_routine_contract)

    oracle_test = subcommands.add_parser(
        "record-oracle-test",
        help="record original-binary process or private harness oracle evidence",
    )
    oracle_test.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    oracle_test.add_argument("--suite-id", required=True)
    oracle_test.add_argument("--test-id", required=True)
    oracle_test.add_argument("--case-kind", choices=ORACLE_CASE_KINDS, required=True)
    oracle_test.add_argument("--status", choices=ORACLE_TEST_STATUSES, default="pass")
    oracle_test.add_argument("--evidence", default="")
    oracle_test.add_argument("--command")
    oracle_test.add_argument("--fixture-path", type=Path)
    oracle_test.add_argument("--trace-log", type=Path)
    oracle_test.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    oracle_test.set_defaults(func=_cmd_record_oracle_test)

    oracle_process = subcommands.add_parser(
        "run-oracle-process-test",
        help="run a black-box original-binary process test and record oracle evidence",
    )
    oracle_process.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    oracle_process.add_argument("--suite-id", required=True)
    oracle_process.add_argument("--test-id", required=True)
    oracle_process.add_argument("--artifact-dir", type=Path, default=Path("build/oracle"))
    oracle_process.add_argument("--timeout-seconds", type=float, default=60.0)
    oracle_process.add_argument("--cwd", type=Path)
    oracle_process.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    oracle_process.add_argument("--stdin-file", type=Path)
    oracle_process.add_argument("--stdin-text")
    oracle_process.add_argument("--expect-exit-code", type=int, action="append", dest="expected_exit_codes")
    oracle_process.add_argument("--stdout-contains", action="append", default=[])
    oracle_process.add_argument("--stderr-contains", action="append", default=[])
    oracle_process.add_argument("--trace-log", type=Path)
    oracle_process.add_argument(
        "--offscreen-display",
        choices=["none", "auto", "x11"],
        default="none",
        help="run the process under an offscreen X11 display; auto starts Xvfb only when no display is set",
    )
    oracle_process.add_argument(
        "--offscreen-screen",
        default="1280x720x24",
        help="Xvfb screen geometry/depth used with --offscreen-display auto or x11",
    )
    oracle_process.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    oracle_process.add_argument("command", nargs=argparse.REMAINDER)
    oracle_process.set_defaults(func=_cmd_run_oracle_process_test)

    behavior_contract = subcommands.add_parser(
        "upsert-behavior-contract",
        help="add or update a label-first public behavior contract",
    )
    behavior_contract.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    behavior_contract.add_argument("--contract-id", required=True)
    behavior_contract.add_argument("--title", required=True)
    behavior_contract.add_argument("--scope", required=True)
    behavior_contract.add_argument("--version", default="1")
    behavior_contract.add_argument("--contract-json", type=Path, required=True)
    behavior_contract.add_argument("--evidence", default="")
    behavior_contract.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    behavior_contract.set_defaults(func=_cmd_upsert_behavior_contract)

    behavior_observation = subcommands.add_parser(
        "record-behavior-observation",
        help="record an externally captured JSON behavior observation",
    )
    behavior_observation.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    behavior_observation.add_argument("--behavior-contract-label", required=True)
    behavior_observation.add_argument("--test-id", required=True)
    behavior_observation.add_argument("--observed-json", type=Path, required=True)
    behavior_observation.add_argument("--input-json", type=Path)
    behavior_observation.add_argument("--status", choices=BEHAVIOR_OBSERVATION_STATUSES, default="pass")
    behavior_observation.add_argument("--command")
    behavior_observation.add_argument("--evidence", default="")
    behavior_observation.add_argument("--fixture-path", type=Path)
    behavior_observation.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    behavior_observation.set_defaults(func=_cmd_record_behavior_observation)

    process_observation = subcommands.add_parser(
        "record-process-behavior-observation",
        help="record a public process stdout/stderr/exit-code behavior observation",
    )
    process_observation.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    process_observation.add_argument("--behavior-contract-label", required=True)
    process_observation.add_argument("--test-id", required=True)
    process_observation.add_argument("--observed-json", type=Path, required=True)
    process_observation.add_argument("--input-json", type=Path)
    process_observation.add_argument("--status", choices=BEHAVIOR_OBSERVATION_STATUSES, default="pass")
    process_observation.add_argument("--command")
    process_observation.add_argument("--evidence", default="")
    process_observation.add_argument("--fixture-path", type=Path)
    process_observation.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    process_observation.set_defaults(func=_cmd_record_process_behavior_observation)

    json_behavior = subcommands.add_parser(
        "run-json-behavior-test",
        help="run a command that emits a JSON object and record it as behavior evidence",
    )
    json_behavior.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    json_behavior.add_argument("--behavior-contract-label", required=True)
    json_behavior.add_argument("--test-id", required=True)
    json_behavior.add_argument("--artifact-dir", type=Path, default=Path("build/behavior"))
    json_behavior.add_argument("--timeout-seconds", type=float, default=60.0)
    json_behavior.add_argument("--cwd", type=Path)
    json_behavior.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    json_behavior.add_argument("--input-json", type=Path)
    json_behavior.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    json_behavior.add_argument("command", nargs=argparse.REMAINDER)
    json_behavior.set_defaults(func=_cmd_run_json_behavior_test)

    process_behavior = subcommands.add_parser(
        "run-process-behavior-test",
        help="run a command and record stdout, stderr, and exit code as public behavior evidence",
    )
    process_behavior.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    process_behavior.add_argument("--behavior-contract-label", required=True)
    process_behavior.add_argument("--test-id", required=True)
    process_behavior.add_argument("--artifact-dir", type=Path, default=Path("build/process-behavior"))
    process_behavior.add_argument("--timeout-seconds", type=float, default=60.0)
    process_behavior.add_argument("--cwd", type=Path)
    process_behavior.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    process_behavior.add_argument("--input-json", type=Path)
    process_behavior.add_argument("--stdin-file", type=Path)
    process_behavior.add_argument("--stdin-text")
    process_behavior.add_argument("--expect-exit-code", type=int, action="append", dest="expected_exit_codes")
    process_behavior.add_argument("--stdout-contains", action="append", default=[])
    process_behavior.add_argument("--stderr-contains", action="append", default=[])
    process_behavior.add_argument("--strip-stdout-line-regex", action="append", default=[])
    process_behavior.add_argument("--strip-stderr-line-regex", action="append", default=[])
    process_behavior.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    process_behavior.add_argument("command", nargs=argparse.REMAINDER)
    process_behavior.set_defaults(func=_cmd_run_process_behavior_test)

    compare_behavior = subcommands.add_parser(
        "compare-json-behavior",
        help="run a command that emits JSON and compare it with an expected behavior fixture",
    )
    compare_behavior.add_argument("--expected-json", type=Path, required=True)
    compare_behavior.add_argument("--test-id", required=True)
    compare_behavior.add_argument("--artifact-dir", type=Path, default=Path("build/behavior-compare"))
    compare_behavior.add_argument("--timeout-seconds", type=float, default=60.0)
    compare_behavior.add_argument("--cwd", type=Path)
    compare_behavior.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    compare_behavior.add_argument("command", nargs=argparse.REMAINDER)
    compare_behavior.set_defaults(func=_cmd_compare_json_behavior)

    compare_spec_behavior = subcommands.add_parser(
        "compare-json-spec-observations",
        help="validate a JSON-emitting implementation against public behavior observations in specs.json",
    )
    compare_spec_behavior.add_argument("--spec-json", type=Path, required=True)
    compare_spec_behavior.add_argument("--contract-id")
    compare_spec_behavior.add_argument("--contract-label")
    compare_spec_behavior.add_argument("--artifact-dir", type=Path, default=Path("build/spec-observation-compare"))
    compare_spec_behavior.add_argument("--timeout-seconds", type=float, default=60.0)
    compare_spec_behavior.add_argument("--cwd", type=Path)
    compare_spec_behavior.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    compare_spec_behavior.add_argument("command", nargs=argparse.REMAINDER)
    compare_spec_behavior.set_defaults(func=_cmd_compare_json_spec_observations)

    compare_process_spec = subcommands.add_parser(
        "compare-process-spec-observations",
        help="validate a process implementation against public stdout/stderr/exit-code observations in specs.json",
    )
    compare_process_spec.add_argument("--spec-json", type=Path, required=True)
    compare_process_spec.add_argument("--contract-id")
    compare_process_spec.add_argument("--contract-label")
    compare_process_spec.add_argument("--artifact-dir", type=Path, default=Path("build/process-spec-observation-compare"))
    compare_process_spec.add_argument("--timeout-seconds", type=float, default=60.0)
    compare_process_spec.add_argument("--cwd", type=Path)
    compare_process_spec.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    compare_process_spec.add_argument("command", nargs=argparse.REMAINDER)
    compare_process_spec.set_defaults(func=_cmd_compare_process_spec_observations)

    run_clean_suite = subcommands.add_parser(
        "run-clean-spec-suite",
        help="run all supported public clean-spec observations against an implementation",
    )
    run_clean_suite.add_argument("--spec-json", type=Path, required=True)
    run_clean_suite.add_argument("--contract-id")
    run_clean_suite.add_argument("--contract-label")
    run_clean_suite.add_argument("--artifact-dir", type=Path, default=Path("build/clean-spec-suite"))
    run_clean_suite.add_argument(
        "--json-command-template-json",
        help="JSON array command template for behavior_observation records",
    )
    run_clean_suite.add_argument(
        "--process-command-template-json",
        help="JSON array command template for process_behavior_observation records",
    )
    run_clean_suite.add_argument("--timeout-seconds", type=float, default=60.0)
    run_clean_suite.add_argument("--cwd", type=Path)
    run_clean_suite.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    run_clean_suite.set_defaults(func=_cmd_run_clean_spec_suite)

    internal_harness = subcommands.add_parser(
        "upsert-internal-harness",
        help="add or update a private original-code internal-call harness target",
    )
    internal_harness.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    internal_harness.add_argument("--target-label", required=True)
    internal_harness.add_argument("--harness-id", required=True)
    internal_harness.add_argument("--harness-kind", choices=INTERNAL_HARNESS_KINDS, required=True)
    internal_harness.add_argument("--command-template", default="")
    internal_harness.add_argument("--input-contract", default="")
    internal_harness.add_argument("--expected-observation", default="")
    internal_harness.add_argument("--risk", default="")
    internal_harness.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    internal_harness.set_defaults(func=_cmd_upsert_internal_harness)

    internal_harness_run = subcommands.add_parser(
        "record-internal-harness-run",
        help="record externally produced private internal-call harness evidence",
    )
    internal_harness_run.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    internal_harness_run.add_argument("--harness-label", required=True)
    internal_harness_run.add_argument("--test-id", required=True)
    internal_harness_run.add_argument("--status", choices=INTERNAL_HARNESS_STATUSES, default="pass")
    internal_harness_run.add_argument("--evidence", required=True)
    internal_harness_run.add_argument("--command")
    internal_harness_run.add_argument("--fixture-path", type=Path)
    internal_harness_run.add_argument("--trace-log", type=Path)
    internal_harness_run.add_argument("--returncode", type=int)
    internal_harness_run.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    internal_harness_run.set_defaults(func=_cmd_record_internal_harness_run)

    internal_harness_process = subcommands.add_parser(
        "run-internal-harness",
        help="run a private original-code internal-call harness and record oracle evidence",
    )
    internal_harness_process.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    internal_harness_process.add_argument("--harness-label", required=True)
    internal_harness_process.add_argument("--test-id", required=True)
    internal_harness_process.add_argument("--artifact-dir", type=Path, default=Path("build/internal-harness"))
    internal_harness_process.add_argument("--timeout-seconds", type=float, default=60.0)
    internal_harness_process.add_argument("--cwd", type=Path)
    internal_harness_process.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    internal_harness_process.add_argument("--stdin-file", type=Path)
    internal_harness_process.add_argument("--stdin-text")
    internal_harness_process.add_argument("--expect-exit-code", type=int, action="append", dest="expected_exit_codes")
    internal_harness_process.add_argument("--stdout-contains", action="append", default=[])
    internal_harness_process.add_argument("--stderr-contains", action="append", default=[])
    internal_harness_process.add_argument("--trace-log", type=Path)
    internal_harness_process.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    internal_harness_process.add_argument("command", nargs=argparse.REMAINDER)
    internal_harness_process.set_defaults(func=_cmd_run_internal_harness)

    mutation_test = subcommands.add_parser(
        "record-mutation-test",
        help="record that a representative wrong implementation was killed by tests",
    )
    mutation_test.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    mutation_test.add_argument("--mutation-kind", required=True)
    mutation_test.add_argument("--target-label")
    mutation_test.add_argument("--test-id", required=True)
    mutation_test.add_argument("--status", choices=MUTATION_TEST_STATUSES, default="killed")
    mutation_test.add_argument("--evidence", default="")
    mutation_test.add_argument("--command")
    mutation_test.add_argument("--fixture-path", type=Path)
    mutation_test.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    mutation_test.set_defaults(func=_cmd_record_mutation_test)

    json_mutation_test = subcommands.add_parser(
        "run-json-mutation-test",
        help="run a JSON-emitting mutant and record it killed when it differs from the expected fixture",
    )
    json_mutation_test.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    json_mutation_test.add_argument("--mutation-kind", required=True)
    json_mutation_test.add_argument("--target-label")
    json_mutation_test.add_argument("--test-id", required=True)
    json_mutation_test.add_argument("--expected-json", type=Path, required=True)
    json_mutation_test.add_argument("--artifact-dir", type=Path, default=Path("build/mutation"))
    json_mutation_test.add_argument("--timeout-seconds", type=float, default=60.0)
    json_mutation_test.add_argument("--cwd", type=Path)
    json_mutation_test.add_argument("--env", action="append", default=[], help="extra process environment KEY=VALUE; repeatable")
    json_mutation_test.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    json_mutation_test.add_argument("command", nargs=argparse.REMAINDER)
    json_mutation_test.set_defaults(func=_cmd_run_json_mutation_test)

    list_inputs = subcommands.add_parser("list-input-devices", help="list Linux evdev devices usable for input traces")
    list_inputs.set_defaults(func=_cmd_list_input_devices)

    record_input = subcommands.add_parser("record-input", help="record selected evdev keyboard/mouse devices to JSONL")
    record_input.add_argument("--out", type=Path, required=True, help="JSONL fixture path to write")
    record_input.add_argument(
        "--device",
        type=Path,
        action="append",
        required=True,
        help="evdev device path such as /dev/input/event7; repeat for keyboard and mouse",
    )
    record_input.add_argument("--duration-seconds", type=float, help="stop automatically after this many seconds")
    record_input.add_argument("--test-id", help="identifier for the gameplay/process-test sequence being captured")
    record_input.add_argument("--scenario", help="short human-readable gameplay scenario label")
    record_input.add_argument("--note", help="private operator note written into the input trace session header")
    record_input.set_defaults(func=_cmd_record_input)

    replay_input = subcommands.add_parser("replay-input", help="validate or replay a recorded input JSONL fixture")
    replay_input.add_argument("--log", type=Path, required=True)
    replay_input.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    replay_input.add_argument("--uinput", type=Path, default=Path("/dev/uinput"))
    replay_input.add_argument("--force", action="store_true", help="actually write events to /dev/uinput")
    replay_input.set_defaults(func=_cmd_replay_input)

    summarize_input = subcommands.add_parser("summarize-input", help="summarize an input JSONL fixture")
    summarize_input.add_argument("--log", type=Path, required=True)
    summarize_input.set_defaults(func=_cmd_summarize_input)

    doctor = subcommands.add_parser("doctor-drcov", help="smoke-test the local drrun/drcov installation")
    doctor.set_defaults(func=_cmd_doctor_drcov)

    ghidra = subcommands.add_parser("import-ghidra", help="import metadata JSON exported by tools/ghidra")
    ghidra.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    ghidra.add_argument("--json", type=Path, required=True)
    ghidra.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    ghidra.set_defaults(func=_cmd_import_ghidra)

    export_ghidra = subcommands.add_parser(
        "export-ghidra",
        help="run Ghidra headless metadata export for cataloged binaries",
    )
    export_ghidra.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    export_ghidra.add_argument("--out-dir", type=Path, default=Path("build/ghidra/exports"))
    export_ghidra.add_argument("--project-dir", type=Path, default=Path("build/ghidra/projects"))
    export_ghidra.add_argument("--project-name", default="halo-catalog")
    export_ghidra.add_argument("--analyze-headless", help="path to analyzeHeadless; defaults to HALOCE_GHIDRA_HEADLESS/PATH")
    export_ghidra.add_argument("--script-path", type=Path, help="directory containing HaloCatalogExport.java")
    export_ghidra.add_argument(
        "--scope",
        dest="scopes",
        action="append",
        choices=["included", "candidate", "excluded"],
        help="catalog scope to export; repeatable, defaults to included and candidate",
    )
    export_ghidra.add_argument("--filename", dest="filenames", action="append", help="PE filename filter; repeatable")
    export_ghidra.add_argument("--no-import", action="store_true", help="write Ghidra JSON without importing it")
    export_ghidra.add_argument("--timeout-seconds", type=int, help="per-binary Ghidra timeout")
    export_ghidra.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    export_ghidra.set_defaults(func=_cmd_export_ghidra)

    check = subcommands.add_parser("check-gates", help="evaluate objective gates from a catalog database")
    check.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    check.add_argument("--allow-open", action="store_true", help="print gates but return success even when gates are open")
    check.set_defaults(func=_cmd_check_gates)

    waiver = subcommands.add_parser("add-waiver", help="add an auditable coverage/catalog waiver")
    waiver.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    waiver.add_argument("--binary-sha256", required=True)
    waiver.add_argument("--rva-start", required=True, type=_parse_int)
    waiver.add_argument("--rva-end", required=True, type=_parse_int)
    waiver.add_argument("--category", required=True)
    waiver.add_argument("--reason", required=True)
    waiver.add_argument("--evidence", required=True)
    waiver.add_argument("--reviewer", required=True)
    waiver.add_argument("--revalidation-trigger", required=True)
    waiver.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    waiver.set_defaults(func=_cmd_add_waiver)

    args = parser.parse_args(argv)
    return int(args.func(args))


def _cmd_build(args: Any) -> int:
    target_config = _target_config_from_args(args)
    root = resolve_install_root(args.install_root, target_config)
    result = build_catalog(
        root,
        args.db,
        static_depth=args.static_depth,
        max_disassembly_bytes=args.max_disassembly_bytes,
        target_config=target_config,
    )
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"catalog": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if not result["errors"] else 1


def _cmd_analyze_reference(args: Any) -> int:
    target_config = _target_config_from_args(args)
    root = resolve_install_root(args.install_root, target_config)
    catalog = build_catalog(
        root,
        args.db,
        static_depth=args.static_depth,
        max_disassembly_bytes=args.max_disassembly_bytes,
        target_config=target_config,
    )

    ghidra_result: dict[str, Any] | None = None
    if not args.skip_ghidra:
        ghidra_result = run_ghidra_export(
            args.db,
            out_dir=args.ghidra_out_dir,
            project_dir=args.ghidra_project_dir,
            project_name=args.ghidra_project_name,
            analyze_headless=args.analyze_headless,
            script_path=args.script_path,
            scopes=("included", "candidate"),
            filenames=args.ghidra_filenames,
            timeout_seconds=args.ghidra_timeout_seconds,
        )

    static_result: dict[str, Any] | None = None
    if not args.skip_static_cross_check:
        static_result = run_static_cross_checks(
            args.db,
            tools=tuple(args.static_tools or DEFAULT_STATIC_CROSS_CHECK_TOOLS),
            scopes=tuple(args.static_scopes or ("included", "candidate")),
            timeout_seconds=args.static_timeout_seconds,
        )

    reports = generate_reports(args.db, args.report_dir)
    ok = not catalog["errors"]
    if ghidra_result is not None:
        ok = ok and not ghidra_result["failures"]
    if static_result is not None:
        ok = ok and int(static_result["failed"]) == 0
    _print_json(
        {
            "ok": ok,
            "catalog": catalog,
            "ghidra": ghidra_result,
            "static_cross_checks": static_result,
            "reports": {key: str(value) for key, value in reports.items()},
        }
    )
    return 0 if ok else 1


def _cmd_report(args: Any) -> int:
    reports = generate_reports(args.db, args.out_dir)
    _print_json({key: str(value) for key, value in reports.items()})
    return 0


def _cmd_export_private_artifacts(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = export_private_artifacts(
            conn,
            args.out_dir,
            artifact_set_id=args.artifact_set_id,
            scopes=tuple(args.scopes or ("included", "candidate")),
            include_disassembly=not args.skip_disassembly,
            objdump=args.objdump,
            objdump_timeout_seconds=args.objdump_timeout_seconds,
            copy_raw_evidence=args.copy_raw_evidence,
            max_raw_evidence_bytes=args.max_raw_evidence_bytes,
            clean=args.clean,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"private_artifacts": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_validate_dirty_corpus(args: Any) -> int:
    result = validate_dirty_corpus(args.corpus_dir, report_json=args.report_json, report_md=args.report_md)
    _print_json({"dirty_corpus_validation": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_render_dirty_corpus(args: Any) -> int:
    plan = write_reimplementation_plan(args.corpus_dir)
    cli_index = write_cli_index(args.corpus_dir, plan=plan)
    result = render_dirty_corpus(args.corpus_dir, args.out_dir, plan=plan, cli_index=cli_index)
    result["content_manifest"] = refresh_content_manifest(args.corpus_dir)
    _print_json({"dirty_corpus_html": result})
    return 0


def _cmd_review_dirty_corpus(args: Any) -> int:
    result = review_dirty_corpus(
        args.corpus_dir,
        search=args.search,
        label=args.label,
        todos=args.todos,
        summary=args.summary,
        interactive=args.interactive,
    )
    _print_json({"dirty_corpus_review": result})
    return 0


def _cmd_derive_clean_specs(args: Any) -> int:
    result = derive_clean_specs(args.corpus_dir, args.out_dir)
    _print_json({"clean_derivation": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_promote_clean_templates(args: Any) -> int:
    result = promote_clean_templates(
        args.corpus_dir,
        reviewer=args.reviewer,
        entity_types=tuple(args.entity_types or ()),
        categories=tuple(args.categories or ()),
        publication_decision=args.publication_decision,
        note=args.note,
        dry_run=bool(args.dry_run),
    )
    _print_json({"clean_template_promotion": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_validate_clean_specs(args: Any) -> int:
    result = validate_clean_specs(args.spec_json, args.tests_json)
    _print_json({"clean_spec_validation": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_rebuild_byte_classes(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = rebuild_executable_byte_classes(conn, args.binary_id)
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"executable_byte_classes": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_cross_check_static(args: Any) -> int:
    result = run_static_cross_checks(
        args.db,
        tools=tuple(args.tools or DEFAULT_STATIC_CROSS_CHECK_TOOLS),
        scopes=tuple(args.scopes or ("included", "candidate")),
        filenames=args.filenames,
        timeout_seconds=args.timeout_seconds,
    )
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"static_cross_checks": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["failed"] == 0 else 1


def _cmd_ingest_drcov(args: Any) -> int:
    result = ingest_drcov(args.db, args.log, args.test_id, suite=args.suite)
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"coverage": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_ingest_halo_trace(args: Any) -> int:
    result = ingest_halo_trace(args.db, args.log, suite=args.suite)
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"coverage": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_ingest_trace(args: Any) -> int:
    result = ingest_trace(args.db, args.log, suite=args.suite)
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"coverage": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_prove_halo_trace(args: Any) -> int:
    result = prove_halo_trace(
        args.db,
        args.out,
        args.test_id,
        args.app,
        expected_filename=args.expected_filename,
        expected_sha256=args.expected_sha256,
        arch=args.arch,
        trace_runner=args.trace_runner,
        timeout_seconds=args.timeout_seconds,
        suite=args.suite,
        allow_timeout=not args.fail_on_timeout,
        pretraced=args.pretraced,
        expected_returncode=args.expected_returncode,
        semantic_profile=args.semantic_profile,
        semantic_max_records=args.semantic_max_records,
        block_state_trace=args.block_state_trace,
        block_state_max_records=args.block_state_max_records,
    )
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"trace_proof": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["ok"] else 1


def _cmd_prove_trace(args: Any) -> int:
    result = prove_trace(
        args.db,
        args.out,
        args.test_id,
        args.app,
        expected_filename=args.expected_filename,
        expected_sha256=args.expected_sha256,
        arch=args.arch,
        trace_runner=args.trace_runner,
        timeout_seconds=args.timeout_seconds,
        suite=args.suite,
        allow_timeout=not args.fail_on_timeout,
        pretraced=args.pretraced,
        expected_returncode=args.expected_returncode,
        semantic_profile=args.semantic_profile,
        semantic_max_records=args.semantic_max_records,
        block_state_trace=args.block_state_trace,
        block_state_max_records=args.block_state_max_records,
    )
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"trace_proof": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["ok"] else 1


def _cmd_generate_block_suite(args: Any) -> int:
    target_config = _target_config_from_args(args)
    result = generate_block_suite(
        target_config=target_config,
        binary_root=args.binary_root,
        binaries=list(args.binaries or []),
        trace_dir=args.trace_dir,
        traces=list(args.traces or []),
        out_dir=args.out_dir,
        wincr_block=args.wincr_block,
        max_cases_per_block=args.max_cases_per_block,
        clean=args.clean,
    )
    _print_json(
        {
            "block_suite": {
                "ok": result["ok"],
                "manifest": str(args.out_dir / "manifest.json"),
                "gaps": str(args.out_dir / "gaps.json"),
                "next_traces": str(args.out_dir / "next-traces.json"),
                "external_modules": str(args.out_dir / "external-modules.json"),
                "gap_count": result["gaps"]["gap_count"],
            }
        }
    )
    return 0 if result["ok"] else 1


def _cmd_block_suite_gate(args: Any) -> int:
    result = gate_block_suite(args.suite)
    _print_json({"block_suite_gate": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_probe_wine_trace(args: Any) -> int:
    result = probe_wine_trace_matrix(
        smoke_root=args.smoke_root,
        smoke_exe=args.smoke_exe,
        out_dir=args.out_dir,
        wine_commands=args.wine_command,
        trace_runner=args.trace_runner,
        arch=args.arch,
        timeout_seconds=args.timeout_seconds,
        wine_debug=args.wine_debug if args.wine_debug != "" else None,
        wait_wineserver=args.wait_wineserver,
        isolate_catalog_build=args.isolate_catalog_build,
        isolate_trace_proof=args.isolate_trace_proof,
    )
    reports = generate_reports(Path(result["db"]), args.out_dir / "reports")
    _print_json({"wine_trace_probe": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["ok"] else 1


def _cmd_generate_windows_vm(args: Any) -> int:
    target_config = _target_config_from_args(args)
    runtime_root = args.runtime_root or args.halo_runtime_root
    config = WindowsVmConfig(
        name=args.name or f"{target_config.project_id}-wintrace",
        memory_mib=args.memory_mib,
        vcpus=args.vcpus,
        disk_path=args.disk or Path(f"private/windows-vm/{target_config.project_id}-wintrace.qcow2"),
        windows_iso=args.windows_iso,
        autounattend_iso=args.autounattend_iso,
        virtio_iso=args.virtio_iso,
        spice_tools_iso=args.spice_tools_iso,
        shared_dir=args.shared_dir,
        ovmf_code=args.ovmf_code,
        ovmf_vars=args.ovmf_vars,
        ovmf_vars_template=args.ovmf_vars_template,
        qmp_socket=args.qmp_socket,
        admin_user=args.admin_user or _default_vm_user(target_config),
        admin_password=args.admin_password or _default_vm_password(target_config),
        dynamorio_root=args.dynamorio_root,
        trace_client_dll=args.trace_client_dll,
        runtime_root=runtime_root,
        virtio_tools_root=args.virtio_tools_root,
        spice_tools_root=args.spice_tools_root,
        install_image_index=args.install_image_index,
        gpu_pci_addresses=tuple(args.gpu_pci_address),
        usb_vendor_products=tuple(args.usb_vendor_product),
        display_mode=args.display_mode,
        network=args.network,
        libvirt_uri=args.libvirt_uri,
        xorriso=args.xorriso,
        target_config=target_config,
    )
    result = generate_windows_vm_bundle(config, args.out_dir)
    _print_json({"windows_vm": result})
    return 0


def _cmd_emit_qmp_input(args: Any) -> int:
    result = write_qmp_input_events(args.log, args.out)
    _print_json({"qmp_input": result})
    return 0


def _cmd_replay_qmp_input(args: Any) -> int:
    result = replay_qmp_input_events(
        args.log,
        qmp_socket=args.socket,
        domain=args.domain,
        virsh=args.virsh,
        virsh_uri=args.virsh_uri,
        speed=args.speed,
        dry_run=args.dry_run,
    )
    _print_json({"qmp_replay": result})
    return 0 if result.get("ok", True) else 1


def _cmd_run_windows_guest_trace(args: Any) -> int:
    target_config = _target_config_from_args(args)
    result = run_windows_guest_trace(
        host=args.host,
        user=args.user or _default_vm_user(target_config),
        out_dir=args.out_dir,
        target=args.target or _default_trace_target(target_config),
        run_seconds=args.run_seconds,
        test_id_prefix=args.test_id_prefix,
        block_state_trace=args.block_state_trace,
        block_state_max_records=args.block_state_max_records,
        password=args.password or None,
        sshpass=args.sshpass,
        ssh=args.ssh,
        scp=args.scp,
        copy_all_logs=args.copy_all_logs,
        target_config=target_config,
    )
    _print_json({"windows_guest_trace": result})
    return 0 if result["ok"] else 1


def _cmd_prove_windows_guest_trace(args: Any) -> int:
    target_config = _target_config_from_args(args)
    selected_target = args.target or _default_trace_target(target_config)
    target_suffix = _target_suffix(selected_target, target_config)
    test_id = f"{args.test_id_prefix}-{target_suffix}"
    expected_filename = args.expected_filename or _default_windows_target_filename(selected_target, target_config)
    run_result = run_windows_guest_trace(
        host=args.host,
        user=args.user or _default_vm_user(target_config),
        out_dir=args.out_dir,
        target=selected_target,
        run_seconds=args.run_seconds,
        test_id_prefix=args.test_id_prefix,
        block_state_trace=args.block_state_trace,
        block_state_max_records=args.block_state_max_records,
        password=args.password or None,
        sshpass=args.sshpass,
        ssh=args.ssh,
        scp=args.scp,
        copy_all_logs=args.copy_all_logs,
        target_config=target_config,
    )
    trace_log = args.trace_log or args.out_dir / f"{test_id}.jsonl"
    guest_result_path = args.out_dir / f"{test_id}.result.json"
    guest_result = _read_json_file(guest_result_path)
    guest_timed_out = bool(guest_result.get("timed_out", False))
    proof = prove_halo_trace_log(
        args.db,
        trace_log,
        test_id,
        expected_filename=expected_filename,
        expected_sha256=args.expected_sha256,
        suite=args.suite,
        command=run_result["ssh_command"],
        returncode=0 if run_result["ok"] else run_result["trace_returncode"],
        timed_out=guest_timed_out,
        timeout_seconds=args.run_seconds,
        allow_timeout=not args.fail_on_timeout,
        stdout=run_result.get("stdout", ""),
        stderr=run_result.get("stderr", ""),
        block_state_trace=args.block_state_trace,
    )
    if not run_result["ok"]:
        proof["failures"].append("Windows guest trace command or log copy failed")
        proof["ok"] = False
    proof["windows_guest_trace"] = run_result
    proof["guest_result"] = guest_result
    proof["guest_result_path"] = str(guest_result_path)
    reports = {} if args.skip_reports else generate_reports(args.db, args.report_dir)
    _print_json({"windows_guest_trace_proof": proof, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if proof["ok"] else 1


def _cmd_check_vfio_host(args: Any) -> int:
    result = check_vfio_host(
        pci_addresses=args.pci_address,
        required_kernel_params=args.required_kernel_param,
        expected_driver=args.expected_driver,
    )
    _print_json({"vfio_host": result})
    return 0 if result["ok"] else 1


def _default_windows_target_filename(target: str, target_config: TargetConfig) -> str:
    trace_target = _trace_target_for_cli(target, target_config)
    if trace_target.expected_filename:
        return trace_target.expected_filename
    return Path(trace_target.executable).name


def _read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _cmd_run_drcov(args: Any) -> int:
    app = args.app
    if app and app[0] == "--":
        app = app[1:]
    if not app:
        raise SystemExit("run-drcov requires an application after --")
    proc = run_drcov(args.log_dir, app, timeout_seconds=args.timeout_seconds)
    _print_json(
        {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "log_dir": str(args.log_dir),
        }
    )
    return proc.returncode


def _cmd_record_interface_test(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = record_interface_test_case(
            conn,
            endpoint_label=args.endpoint_label,
            case_kind=args.case_kind,
            test_id=args.test_id,
            status=args.status,
            evidence=args.evidence,
            fixture_path=args.fixture_path,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"interface_test_case": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_record_mock_interface_suite(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = record_mock_interface_suite(conn, status=args.status, evidence=args.evidence)
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"interface_mock_suite": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_record_observed_interface_suite(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = record_observed_interface_suite(
            conn,
            scopes=tuple(args.scope or ("included", "candidate")),
            status=args.status,
            evidence=args.evidence,
            test_id_prefix=args.test_id_prefix,
            fixture_path=args.fixture_path,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"observed_interface_suite": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_upsert_data_structure(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = upsert_data_structure(
            conn,
            name=args.name,
            structure_kind=args.structure_kind,
            spec_status=args.spec_status,
            fixture_status=args.fixture_status,
            description=args.description,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"data_structure": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_record_data_state_test(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    gate_metadata = _gate_metadata(conn)
    with conn:
        result = record_data_state_test_case(
            conn,
            data_structure_label_value=args.data_structure_label,
            case_kind=args.case_kind,
            test_id=args.test_id,
            status=args.status,
            evidence=args.evidence,
            fixture_path=args.fixture_path,
            round_trip_kinds=set(_target_list(gate_metadata, "data_state_round_trip_kinds_json", tuple(ROUND_TRIP_KINDS))),
            transition_kinds=set(_target_list(gate_metadata, "data_state_transition_kinds_json", tuple(TRANSITION_KINDS))),
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"data_state_test_case": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_classify_functions(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = classify_functions(
            conn,
            scopes=tuple(args.scope or ("included", "candidate")),
            subsystem=args.subsystem,
            purity=args.purity,
            side_effects=args.side_effects,
            calling_convention=args.calling_convention,
            signature=args.signature,
            confidence=args.confidence,
            test_status=args.test_status,
            clean_room_status=args.clean_room_status,
            evidence=args.evidence,
            filename=args.filename,
            function_label=args.function_label,
            name=args.name,
            source=args.source,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"function_classification": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_upsert_internal_routine_contract(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = upsert_internal_routine_contract(
            conn,
            label=args.label,
            function_label=args.function_label,
            public_name=args.public_name,
            purpose_summary=args.purpose_summary,
            calling_convention=args.calling_convention,
            signature=args.signature,
            input_shape=parse_contract_json(args.input_shape_json, {}),
            output_shape=parse_contract_json(args.output_shape_json, {}),
            preconditions=list(args.precondition),
            postconditions=list(args.postcondition),
            side_effects=list(args.side_effect),
            state_transitions=list(args.state_transition),
            fixtures=list(args.fixture),
            evidence_labels=list(args.evidence_label),
            evidence_source=args.evidence_source,
            confidence=args.confidence,
            taint_level=args.taint_level,
            review_status=args.review_status,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"internal_routine_contract": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_record_oracle_test(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    gate_metadata = _gate_metadata(conn)
    with conn:
        result = record_oracle_test_case(
            conn,
            suite_id=args.suite_id,
            test_id=args.test_id,
            case_kind=args.case_kind,
            status=args.status,
            evidence=args.evidence,
            command=args.command,
            fixture_path=args.fixture_path,
            trace_log=args.trace_log,
            required_process_suites=_target_list(
                gate_metadata,
                "required_oracle_process_suites_json",
                REQUIRED_ORACLE_PROCESS_SUITES,
            ),
            required_private_suites=_target_list(
                gate_metadata,
                "required_oracle_private_suites_json",
                REQUIRED_ORACLE_PRIVATE_SUITES,
            ),
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"oracle_test_case": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_run_oracle_process_test(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("run-oracle-process-test requires a command after --")
    if args.stdin_file is not None and args.stdin_text is not None:
        raise SystemExit("--stdin-file and --stdin-text are mutually exclusive")
    stdin_text = args.stdin_text
    if args.stdin_file is not None:
        stdin_text = args.stdin_file.read_text(encoding="utf-8")
    extra_env = dict(_parse_env_pair(item) for item in args.env)

    conn = connect(args.db)
    initialize(conn)
    gate_metadata = _gate_metadata(conn)
    result = run_oracle_process_test(
        conn,
        suite_id=args.suite_id,
        test_id=args.test_id,
        command=command,
        artifact_dir=args.artifact_dir,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env,
        stdin_text=stdin_text,
        expected_exit_codes=args.expected_exit_codes or (0,),
        stdout_contains=args.stdout_contains,
        stderr_contains=args.stderr_contains,
        trace_log=args.trace_log,
        offscreen_display=args.offscreen_display,
        offscreen_screen=args.offscreen_screen,
        required_process_suites=_target_list(
            gate_metadata,
            "required_oracle_process_suites_json",
            REQUIRED_ORACLE_PROCESS_SUITES,
        ),
    )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"oracle_process_test": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_upsert_behavior_contract(args: Any) -> int:
    contract = load_json_file(args.contract_json)
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = upsert_behavior_contract(
            conn,
            contract_id=args.contract_id,
            title=args.title,
            scope=args.scope,
            version=args.version,
            contract=contract,
            evidence=args.evidence,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"behavior_contract": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_record_behavior_observation(args: Any) -> int:
    observed = load_json_file(args.observed_json)
    input_data = load_json_file(args.input_json) if args.input_json is not None else None
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = record_behavior_observation(
            conn,
            behavior_contract_label_value=args.behavior_contract_label,
            test_id=args.test_id,
            observed=observed,
            status=args.status,
            command=args.command,
            input_data=input_data,
            evidence=args.evidence,
            fixture_path=args.fixture_path,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"behavior_observation": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_record_process_behavior_observation(args: Any) -> int:
    observed = load_json_file(args.observed_json)
    input_data = load_json_file(args.input_json) if args.input_json is not None else None
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = record_process_behavior_observation(
            conn,
            behavior_contract_label_value=args.behavior_contract_label,
            test_id=args.test_id,
            observed=observed,
            status=args.status,
            command=args.command,
            input_data=input_data,
            evidence=args.evidence,
            fixture_path=args.fixture_path,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"process_behavior_observation": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_run_json_behavior_test(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("run-json-behavior-test requires a command after --")
    input_data = load_json_file(args.input_json) if args.input_json is not None else None
    extra_env = dict(_parse_env_pair(item) for item in args.env)
    conn = connect(args.db)
    initialize(conn)
    result = run_json_behavior_observation(
        conn,
        behavior_contract_label_value=args.behavior_contract_label,
        test_id=args.test_id,
        command=command,
        artifact_dir=args.artifact_dir,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env or None,
        input_data=input_data,
    )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"behavior_observation": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_run_process_behavior_test(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("run-process-behavior-test requires a command after --")
    if args.stdin_file is not None and args.stdin_text is not None:
        raise SystemExit("--stdin-file and --stdin-text are mutually exclusive")
    stdin_text = args.stdin_text
    if args.stdin_file is not None:
        stdin_text = args.stdin_file.read_text(encoding="utf-8")
    input_data = load_json_file(args.input_json) if args.input_json is not None else None
    extra_env = dict(_parse_env_pair(item) for item in args.env)
    conn = connect(args.db)
    initialize(conn)
    result = run_process_behavior_observation(
        conn,
        behavior_contract_label_value=args.behavior_contract_label,
        test_id=args.test_id,
        command=command,
        artifact_dir=args.artifact_dir,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env or None,
        input_data=input_data,
        stdin_text=stdin_text,
        expected_exit_codes=args.expected_exit_codes,
        stdout_contains=args.stdout_contains,
        stderr_contains=args.stderr_contains,
        strip_stdout_line_regexes=args.strip_stdout_line_regex,
        strip_stderr_line_regexes=args.strip_stderr_line_regex,
    )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"process_behavior_observation": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_compare_json_behavior(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("compare-json-behavior requires a command after --")
    expected = load_json_file(args.expected_json)
    extra_env = dict(_parse_env_pair(item) for item in args.env)
    result = compare_json_behavior(
        expected=expected,
        expected_path=args.expected_json,
        command=command,
        artifact_dir=args.artifact_dir,
        test_id=args.test_id,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env or None,
    )
    _print_json({"behavior_comparison": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_compare_json_spec_observations(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("compare-json-spec-observations requires a command template after --")
    spec = load_json_file(args.spec_json)
    extra_env = dict(_parse_env_pair(item) for item in args.env)
    result = compare_json_spec_observations(
        spec=spec,
        command_template=command,
        artifact_dir=args.artifact_dir,
        contract_id=args.contract_id,
        contract_label=args.contract_label,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env or None,
    )
    _print_json({"spec_observation_comparison": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_compare_process_spec_observations(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("compare-process-spec-observations requires a command template after --")
    spec = load_json_file(args.spec_json)
    extra_env = dict(_parse_env_pair(item) for item in args.env)
    result = compare_process_spec_observations(
        spec=spec,
        command_template=command,
        artifact_dir=args.artifact_dir,
        contract_id=args.contract_id,
        contract_label=args.contract_label,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env or None,
    )
    _print_json({"process_spec_observation_comparison": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_run_clean_spec_suite(args: Any) -> int:
    spec = load_json_file(args.spec_json)
    extra_env = dict(_parse_env_pair(item) for item in args.env)
    result = run_clean_spec_suite(
        spec=spec,
        artifact_dir=args.artifact_dir,
        json_command_template=_parse_command_template_json(
            args.json_command_template_json,
            "--json-command-template-json",
        ),
        process_command_template=_parse_command_template_json(
            args.process_command_template_json,
            "--process-command-template-json",
        ),
        contract_id=args.contract_id,
        contract_label=args.contract_label,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env or None,
    )
    _print_json({"clean_spec_suite": result})
    return 0 if result["status"] == "pass" else 1


def _cmd_upsert_internal_harness(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = upsert_internal_harness(
            conn,
            target_label=args.target_label,
            harness_id=args.harness_id,
            harness_kind=args.harness_kind,
            command_template=args.command_template,
            input_contract=args.input_contract,
            expected_observation=args.expected_observation,
            risk=args.risk,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"internal_harness": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_record_internal_harness_run(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    with conn:
        result = record_internal_harness_run(
            conn,
            harness_label=args.harness_label,
            test_id=args.test_id,
            status=args.status,
            evidence=args.evidence,
            command=args.command,
            fixture_path=args.fixture_path,
            trace_log=args.trace_log,
            returncode=args.returncode,
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"internal_harness_run": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_run_internal_harness(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("run-internal-harness requires a command after --")
    if args.stdin_file is not None and args.stdin_text is not None:
        raise SystemExit("--stdin-file and --stdin-text are mutually exclusive")
    stdin_text = args.stdin_text
    if args.stdin_file is not None:
        stdin_text = args.stdin_file.read_text(encoding="utf-8")
    extra_env = dict(_parse_env_pair(item) for item in args.env)

    conn = connect(args.db)
    initialize(conn)
    result = run_internal_harness(
        conn,
        harness_label=args.harness_label,
        test_id=args.test_id,
        command=command,
        artifact_dir=args.artifact_dir,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env,
        stdin_text=stdin_text,
        expected_exit_codes=args.expected_exit_codes or (0,),
        stdout_contains=args.stdout_contains,
        stderr_contains=args.stderr_contains,
        trace_log=args.trace_log,
    )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"internal_harness_run": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "pass" else 1


def _cmd_record_mutation_test(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    gate_metadata = _gate_metadata(conn)
    with conn:
        result = record_mutation_test_case(
            conn,
            mutation_kind=args.mutation_kind,
            target_label=args.target_label,
            test_id=args.test_id,
            status=args.status,
            evidence=args.evidence,
            command=args.command,
            fixture_path=args.fixture_path,
            required_mutation_kinds=_target_list(
                gate_metadata,
                "required_mutation_kinds_json",
                REQUIRED_MUTATION_KINDS,
            ),
        )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"mutation_test_case": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_run_json_mutation_test(args: Any) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("run-json-mutation-test requires a command after --")
    expected = load_json_file(args.expected_json)
    extra_env = dict(_parse_env_pair(item) for item in args.env)
    conn = connect(args.db)
    initialize(conn)
    gate_metadata = _gate_metadata(conn)
    result = run_json_mutation_test(
        conn,
        mutation_kind=args.mutation_kind,
        target_label=args.target_label,
        test_id=args.test_id,
        expected=expected,
        expected_path=args.expected_json,
        command=command,
        artifact_dir=args.artifact_dir,
        timeout_seconds=args.timeout_seconds,
        cwd=args.cwd,
        env=extra_env or None,
        required_mutation_kinds=_target_list(
            gate_metadata,
            "required_mutation_kinds_json",
            REQUIRED_MUTATION_KINDS,
        ),
    )
    conn.close()
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"mutation_test_case": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if result["status"] == "killed" else 1


def _cmd_list_input_devices(args: Any) -> int:
    _print_json({"devices": list_input_devices()})
    return 0


def _cmd_record_input(args: Any) -> int:
    try:
        result = record_input_trace(
            args.out,
            args.device,
            duration_seconds=args.duration_seconds,
            test_id=args.test_id,
            scenario=args.scenario,
            note=args.note,
        )
    except KeyboardInterrupt:
        raise SystemExit(130)
    _print_json({"input_trace": result})
    return 0


def _cmd_replay_input(args: Any) -> int:
    result = replay_input_trace(args.log, dry_run=not args.force, force=args.force, speed=args.speed, uinput_path=args.uinput)
    _print_json({"input_replay": result})
    return 0


def _cmd_summarize_input(args: Any) -> int:
    _print_json({"input_trace": summarize_input_trace(args.log)})
    return 0


def _cmd_doctor_drcov(args: Any) -> int:
    result = doctor_drcov()
    _print_json(result)
    return 0 if result["ok"] else 1


def _cmd_import_ghidra(args: Any) -> int:
    result = import_ghidra_json(args.db, args.json)
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"ghidra": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_export_ghidra(args: Any) -> int:
    result = run_ghidra_export(
        args.db,
        out_dir=args.out_dir,
        project_dir=args.project_dir,
        project_name=args.project_name,
        analyze_headless=args.analyze_headless,
        script_path=args.script_path,
        scopes=args.scopes or ("included", "candidate"),
        filenames=args.filenames,
        import_results=not args.no_import,
        timeout_seconds=args.timeout_seconds,
    )
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"ghidra": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if not result["failures"] else 1


def _cmd_check_gates(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    gates = gates_json(conn)
    _print_json(gates)
    if args.allow_open:
        return 0
    return 0 if all(item["status"] == "pass" for item in gates.values()) else 1


def _cmd_add_waiver(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    binary = conn.execute("SELECT id, label FROM binaries WHERE sha256 = ?", (args.binary_sha256,)).fetchone()
    if binary is None:
        raise SystemExit(f"unknown binary sha256: {args.binary_sha256}")
    label = waiver_label(str(binary["label"]), args.rva_start, args.rva_end, args.category, args.reason)
    with conn:
        ensure_label(conn, label, "waiver", f"{binary['label']}:waiver", args.reason)
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="waiver",
            binary_id=int(binary["id"]),
            module_sha256=args.binary_sha256,
            rva_start=args.rva_start,
            rva_end=args.rva_end,
            private={"category": args.category, "reason": args.reason, "evidence": args.evidence},
        )
        conn.execute(
            """
            INSERT INTO waivers(
              label, binary_id, rva_start, rva_end, category, reason, evidence,
              reviewer, revalidation_trigger, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                label,
                int(binary["id"]),
                args.rva_start,
                args.rva_end,
                args.category,
                args.reason,
                args.evidence,
                args.reviewer,
                args.revalidation_trigger,
                utc_now(),
            ),
        )
        rebuild_executable_byte_classes(conn, int(binary["id"]))
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"waiver": "added", "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _add_target_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target-config",
        type=Path,
        help="TOML target manifest; defaults to the packaged Halo CE preset for compatibility",
    )


def _target_config_from_args(args: Any) -> TargetConfig:
    return load_target_config(getattr(args, "target_config", None))


def _trace_target_for_cli(target: str, target_config: TargetConfig):
    normalized = target.strip().lower()
    aliases = {
        "client": "client",
        "dedicated": "dedicated",
        "both": "both",
    }
    normalized = aliases.get(normalized, normalized)
    trace_target = target_config.trace_target(normalized)
    if trace_target is None:
        available = ", ".join(item.id for item in target_config.trace_targets)
        raise SystemExit(f"unknown trace target {target!r}; expected one of: {available}")
    return trace_target


def _target_suffix(target: str, target_config: TargetConfig) -> str:
    return _trace_target_for_cli(target, target_config).id


def _default_trace_target(target_config: TargetConfig) -> str:
    configured = target_config.windows_vm.default_trace_target
    if configured:
        return configured
    if target_config.trace_targets:
        return target_config.trace_targets[0].id
    raise SystemExit(f"target config {target_config.project_id!r} declares no trace targets")


def _default_vm_user(target_config: TargetConfig) -> str:
    return target_config.windows_vm.admin_user


def _default_vm_password(target_config: TargetConfig) -> str:
    return target_config.windows_vm.admin_password


def _gate_metadata(conn: Any) -> dict[str, str]:
    return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM metadata ORDER BY key")}


def _target_list(metadata: dict[str, str], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    return target_lists_from_metadata(metadata, key, default)


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def _parse_command_template_json(value: str | None, option_name: str) -> list[str] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{option_name} must be a JSON array: {exc}") from exc
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise SystemExit(f"{option_name} must be a JSON array of strings")
    if not parsed:
        raise SystemExit(f"{option_name} cannot be empty")
    return parsed


def _parse_env_pair(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise SystemExit(f"--env must be KEY=VALUE, got {value!r}")
    key, env_value = value.split("=", 1)
    if not key:
        raise SystemExit("--env key cannot be empty")
    return key, env_value
