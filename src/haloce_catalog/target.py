from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from .util import json_dumps


DEFAULT_TARGET_ID = "halo-ce"


@dataclass(frozen=True)
class BinaryRule:
    role: str
    scope: str
    reason: str
    names: tuple[str, ...] = ()
    path_contains: tuple[str, ...] = ()


@dataclass(frozen=True)
class TraceTarget:
    id: str
    executable: str
    expected_filename: str | None = None
    cwd: str = "."
    args: tuple[str, ...] = ()
    display_required: bool = False
    semantic_profile: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WindowsVmTargetConfig:
    trace_root: str = r"C:\WinCR"
    runtime_dir: str = "TargetRuntime"
    runtime_stage_dir: str = "TargetRuntime"
    runtime_stage_aliases: tuple[str, ...] = ()
    guest_trace_script: str = "Run-WinCRTrace.ps1"
    trace_client_name: str = "wincr_trace.dll"
    iso_volume_id: str = "WINCRTRACE"
    computer_name: str = "WINCRTRACE"
    operator_display_name: str = "WinCR Trace Operator"
    firewall_rule_name: str = "OpenSSH-Server-In-TCP-WinCR"
    firewall_rule_display_name: str = "OpenSSH Server WinCR"
    admin_user: str = "wincr"
    admin_password: str = "ChangeMe-WinCR-LocalOnly!"
    password_env: str = "WINCR_WINDOWS_VM_PASSWORD"
    skip_reports_env: str = "WINCR_WINDOWS_VM_SKIP_REPORTS"
    default_trace_target: str | None = None


@dataclass(frozen=True)
class TargetConfig:
    project_id: str
    project_name: str
    install_root_env: str = "WINCR_INSTALL_ROOT"
    reference_package_env: str = "WINCR_REFERENCE_PACKAGE"
    source_info_env: str = "WINCR_SOURCE_INFO"
    ghidra_headless_env: str = "WINCR_GHIDRA_HEADLESS"
    flake_lock_node: str | None = None
    reference_package_metadata_key: str = "reference_package"
    source_info_metadata_key: str = "source_info"
    binary_rules: tuple[BinaryRule, ...] = ()
    unknown_directory_markers: tuple[str, ...] = ()
    trace_targets: tuple[TraceTarget, ...] = ()
    required_oracle_process_suites: tuple[str, ...] = ()
    required_oracle_private_suites: tuple[str, ...] = ()
    required_mutation_kinds: tuple[str, ...] = ()
    data_state_round_trip_kinds: tuple[str, ...] = ()
    data_state_transition_kinds: tuple[str, ...] = ()
    windows_vm: WindowsVmTargetConfig = field(default_factory=WindowsVmTargetConfig)
    source_path: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "project": {
                "id": self.project_id,
                "name": self.project_name,
            },
            "install_root_env": self.install_root_env,
            "reference_package_env": self.reference_package_env,
            "source_info_env": self.source_info_env,
            "ghidra_headless_env": self.ghidra_headless_env,
            "flake_lock_node": self.flake_lock_node,
            "reference_package_metadata_key": self.reference_package_metadata_key,
            "source_info_metadata_key": self.source_info_metadata_key,
            "unknown_directory_markers": list(self.unknown_directory_markers),
            "trace_targets": [
                {
                    "id": target.id,
                    "executable": target.executable,
                    "expected_filename": target.expected_filename,
                    "cwd": target.cwd,
                    "args": list(target.args),
                    "display_required": target.display_required,
                    "semantic_profile": target.semantic_profile,
                }
                for target in self.trace_targets
            ],
            "required_oracle_process_suites": list(self.required_oracle_process_suites),
            "required_oracle_private_suites": list(self.required_oracle_private_suites),
            "required_mutation_kinds": list(self.required_mutation_kinds),
            "data_state_round_trip_kinds": list(self.data_state_round_trip_kinds),
            "data_state_transition_kinds": list(self.data_state_transition_kinds),
            "windows_vm": self.windows_vm.__dict__,
            "source_path": self.source_path,
        }

    def metadata_rows(self) -> dict[str, str]:
        return {
            "target_project_id": self.project_id,
            "target_project_name": self.project_name,
            "target_config_json": json_dumps(self.to_public_dict()),
            "required_oracle_process_suites_json": json_dumps(list(self.required_oracle_process_suites)),
            "required_oracle_private_suites_json": json_dumps(list(self.required_oracle_private_suites)),
            "required_mutation_kinds_json": json_dumps(list(self.required_mutation_kinds)),
            "data_state_round_trip_kinds_json": json_dumps(list(self.data_state_round_trip_kinds)),
            "data_state_transition_kinds_json": json_dumps(list(self.data_state_transition_kinds)),
        }

    def trace_target(self, target_id: str) -> TraceTarget | None:
        normalized = target_id.lower()
        for target in self.trace_targets:
            if target.id.lower() == normalized:
                return target
        return None


def load_target_config(path: Path | str | None = None) -> TargetConfig:
    if path is None:
        return _load_packaged_target(DEFAULT_TARGET_ID)
    resolved = Path(path)
    data = tomllib.loads(resolved.read_text(encoding="utf-8"))
    return target_config_from_mapping(data, source_path=str(resolved))


def _load_packaged_target(target_id: str) -> TargetConfig:
    resource = resources.files("haloce_catalog").joinpath("presets", f"{target_id}.toml")
    data = tomllib.loads(resource.read_text(encoding="utf-8"))
    return target_config_from_mapping(data, source_path=f"package:{target_id}")


def target_config_from_mapping(data: dict[str, Any], *, source_path: str | None = None) -> TargetConfig:
    project = _table(data, "project")
    env = _table(data, "env")
    provenance = _table(data, "provenance")
    gates = _table(data, "gates")
    data_state = _table(data, "data_state")
    windows_vm = _table(data, "windows_vm")
    return TargetConfig(
        project_id=str(project.get("id") or DEFAULT_TARGET_ID),
        project_name=str(project.get("name") or project.get("id") or "Windows target"),
        install_root_env=str(env.get("install_root") or "WINCR_INSTALL_ROOT"),
        reference_package_env=str(env.get("reference_package") or "WINCR_REFERENCE_PACKAGE"),
        source_info_env=str(env.get("source_info") or "WINCR_SOURCE_INFO"),
        ghidra_headless_env=str(env.get("ghidra_headless") or "WINCR_GHIDRA_HEADLESS"),
        flake_lock_node=_optional_str(provenance.get("flake_lock_node")),
        reference_package_metadata_key=str(provenance.get("reference_package_metadata_key") or "reference_package"),
        source_info_metadata_key=str(provenance.get("source_info_metadata_key") or "source_info"),
        binary_rules=tuple(_binary_rule(item) for item in data.get("binary_rules", [])),
        unknown_directory_markers=_tuple_str(data.get("unknown_directory_markers")),
        trace_targets=tuple(_trace_target(item) for item in data.get("trace_targets", [])),
        required_oracle_process_suites=_tuple_str(gates.get("oracle_process_suites")),
        required_oracle_private_suites=_tuple_str(gates.get("oracle_private_suites")),
        required_mutation_kinds=_tuple_str(gates.get("mutation_kinds")),
        data_state_round_trip_kinds=_tuple_str(data_state.get("round_trip_kinds")),
        data_state_transition_kinds=_tuple_str(data_state.get("transition_kinds")),
        windows_vm=WindowsVmTargetConfig(
            trace_root=str(windows_vm.get("trace_root") or r"C:\WinCR"),
            runtime_dir=str(windows_vm.get("runtime_dir") or "TargetRuntime"),
            runtime_stage_dir=str(windows_vm.get("runtime_stage_dir") or "TargetRuntime"),
            runtime_stage_aliases=_tuple_str(windows_vm.get("runtime_stage_aliases")),
            guest_trace_script=str(windows_vm.get("guest_trace_script") or "Run-WinCRTrace.ps1"),
            trace_client_name=str(windows_vm.get("trace_client_name") or "wincr_trace.dll"),
            iso_volume_id=str(windows_vm.get("iso_volume_id") or "WINCRTRACE"),
            computer_name=str(windows_vm.get("computer_name") or "WINCRTRACE"),
            operator_display_name=str(windows_vm.get("operator_display_name") or "WinCR Trace Operator"),
            firewall_rule_name=str(windows_vm.get("firewall_rule_name") or "OpenSSH-Server-In-TCP-WinCR"),
            firewall_rule_display_name=str(windows_vm.get("firewall_rule_display_name") or "OpenSSH Server WinCR"),
            admin_user=str(windows_vm.get("admin_user") or "wincr"),
            admin_password=str(windows_vm.get("admin_password") or "ChangeMe-WinCR-LocalOnly!"),
            password_env=str(windows_vm.get("password_env") or "WINCR_WINDOWS_VM_PASSWORD"),
            skip_reports_env=str(windows_vm.get("skip_reports_env") or "WINCR_WINDOWS_VM_SKIP_REPORTS"),
            default_trace_target=_optional_str(windows_vm.get("default_trace_target")),
        ),
        source_path=source_path,
    )


def target_lists_from_metadata(metadata: dict[str, str], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = metadata.get(key)
    if not value:
        return default
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return default
    if not isinstance(parsed, list):
        return default
    return tuple(str(item) for item in parsed if str(item).strip())


def _binary_rule(data: dict[str, Any]) -> BinaryRule:
    return BinaryRule(
        role=str(data["role"]),
        scope=str(data["scope"]),
        reason=str(data.get("reason") or ""),
        names=_tuple_str(data.get("names")),
        path_contains=_tuple_str(data.get("path_contains")),
    )


def _trace_target(data: dict[str, Any]) -> TraceTarget:
    return TraceTarget(
        id=str(data["id"]),
        executable=str(data["executable"]),
        expected_filename=_optional_str(data.get("expected_filename")),
        cwd=str(data.get("cwd") or "."),
        args=_tuple_str(data.get("args")),
        display_required=bool(data.get("display_required", False)),
        semantic_profile=dict(data.get("semantic_profile") or {}),
    )


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"target config [{key}] must be a table")
    return value


def _tuple_str(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    raise ValueError(f"expected string or list of strings, got {type(value).__name__}")


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None
