from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlencode

from ..stage_binary import StageABinary, StageAInputError
from ..util import sha256_bytes, sha256_file, write_json
from .analysis_artifact import validate_relational_analysis
from .artifacts import read_json_object as _read_json
from .checked_artifacts import (
    CHECKED_ARTIFACT_CHECKER_VERSION,
    CheckedArtifactManifest,
    write_checked_artifact_manifest,
)
from .contract import _load_contract
from .report_schema import RELATIONAL_PREPARED_REPORT_FILES
from .schema import (
    RELATIONAL_ACCEPTANCE_THEOREMS,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
    RELATIONAL_KERNEL_MODULES,
    LEAN_MODULE_GRAPH_FORMATS,
    LEAN_MODULE_GRAPH_V2_FORMAT,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
    ModuleGraph,
    PreparedProofDigests,
    SchemaError,
    StageAInterfaceManifest,
    selected_relational_acceptance_theorem,
)
from .ir import CompositionProgressIR, RelationalProofIR, WholeProgramAcceptanceIR
from .lean.compiler import _relational_cache_dir


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parent.parent / "lean" / "StageA"
_NIX_PUBLIC_KEY_RE = re.compile(r"^[^:\s]+:[A-Za-z0-9+/]+={0,2}$")
_LEAN_IMPORT_PATTERN = re.compile(
    r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE
)
_NIX_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?")
_NIX_BUILD_TRACE_V3_VERSION = (2, 35)
_NIXOS_SYSTEM_NIX = Path("/run/current-system/sw/bin/nix")
_LEAN_SEMANTIC_NODE_ID_FORMAT = "stage-a-lean-semantic-node-id-v1"
_LEAN_SEMANTIC_RECIPE_VERSION = "stage-a-lean-semantic-recipe-v1"
_NIX_EVALUATION_CACHE_FORMAT = "stage-a-nix-evaluation-cache-v1"
_NIX_SEMANTIC_BOUNDARY_FORMAT = "stage-a-nix-semantic-boundary-v1"


def _nix_executable() -> str:
    """Select one Nix client for every proof-build subprocess.

    Development shells may carry an older Nix than the active daemon. Prefer an
    explicit override, then the active NixOS system client, and only then PATH.
    This keeps content-addressed build-trace negotiation and realization on the
    same client version.
    """

    override = os.environ.get("SPAGHETTI_EXTRACTOR_NIX")
    if override:
        resolved = (
            override
            if os.path.sep in override
            else shutil.which(override)
        )
        if resolved is None or not os.path.isfile(resolved) or not os.access(
            resolved, os.X_OK
        ):
            raise StageAInputError(
                "SPAGHETTI_EXTRACTOR_NIX does not identify an executable Nix client"
            )
        return str(Path(resolved).resolve())
    if _NIXOS_SYSTEM_NIX.is_file() and os.access(_NIXOS_SYSTEM_NIX, os.X_OK):
        return str(_NIXOS_SYSTEM_NIX)
    ambient = shutil.which("nix")
    if ambient is None:
        raise StageAInputError("cannot find an executable Nix client")
    return ambient


def _content_addressed_derivations_requested() -> bool:
    value = os.environ.get(
        "SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED", "true"
    ).lower()
    if value not in {"true", "false"}:
        raise StageAInputError(
            "SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED must be true or false"
        )
    return value == "true"


def _nix_store_version(*, store: str | None = None) -> tuple[int, int, str]:
    command = [_nix_executable(), "store", "info", "--json"]
    environment = None
    if store is not None:
        command.extend(["--store", store])
        ssh_cache = Path(
            os.environ.get(
                "XDG_CACHE_HOME",
                str(Path.home() / ".cache"),
            )
        ) / "spaghetti-extractor" / "ssh"
        ssh_cache.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        ssh_options = (
            "-o IdentitiesOnly=yes "
            "-o ControlMaster=auto "
            f"-o ControlPath={ssh_cache}/%C "
            "-o ControlPersist=4h"
        )
        existing_ssh_options = environment.get("NIX_SSHOPTS", "").strip()
        environment["NIX_SSHOPTS"] = " ".join(
            option
            for option in (existing_ssh_options, ssh_options)
            if option
        )
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )
    if process.returncode != 0:
        location = store or "the local Nix daemon"
        raise StageAInputError(
            f"cannot query Nix store version for {location}:\n"
            + process.stderr[-4000:]
        )
    try:
        payload = json.loads(process.stdout)
        version = payload["version"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise StageAInputError("Nix returned malformed store-version metadata") from exc
    if not isinstance(version, str):
        raise StageAInputError("Nix store-version metadata omits a string version")
    match = _NIX_VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise StageAInputError(f"unsupported Nix store version {version!r}")
    return int(match.group(1)), int(match.group(2)), version


def _nix_client_version() -> tuple[int, int, str]:
    process = subprocess.run(
        [_nix_executable(), "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise StageAInputError(
            "cannot query the Nix client version:\n" + process.stderr[-4000:]
        )
    version_text = process.stdout.strip()
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)\s*$", version_text)
    if match is None:
        raise StageAInputError(
            f"Nix returned malformed client-version metadata {version_text!r}"
        )
    version = match.group(1)
    parsed = _NIX_VERSION_PATTERN.fullmatch(version)
    if parsed is None:
        raise StageAInputError(f"unsupported Nix client version {version!r}")
    return int(parsed.group(1)), int(parsed.group(2)), version


def _ca_builder_stores(builders_file: Path) -> list[str]:
    stores: list[str] = []
    for line_number, raw_line in enumerate(
        builders_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 6:
            raise StageAInputError(
                f"malformed Nix builder entry at {builders_file}:{line_number}"
            )
        features = set(fields[5].split(","))
        if "ca-derivations" not in features:
            continue
        uri = fields[0]
        ssh_key = fields[2]
        if ssh_key != "-":
            separator = "&" if "?" in uri else "?"
            uri += separator + urlencode({"ssh-key": ssh_key})
        stores.append(uri)
    return list(dict.fromkeys(stores))


def _nix_builders_spec(builders_file: Path) -> str:
    entries = [
        line.strip()
        for line in builders_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not entries:
        raise StageAInputError(f"Nix builders file is empty: {builders_file}")
    return "\n".join(entries)


def _check_remote_ca_build_trace_compatibility(
    builders_file: Path | None,
) -> None:
    """Reject the incompatible Nix 2.35 build-trace protocol boundary.

    Nix 2.35 replaced realisations with build-trace-v3 identities. A pre-2.35
    coordinating daemon can copy a 2.35 CA output from an ssh-ng builder, but
    cannot register that output as the realization of its derivation.
    """

    client_major, client_minor, client_version = _nix_client_version()
    local_major, local_minor, local_version = _nix_store_version()
    client_v3 = (client_major, client_minor) >= _NIX_BUILD_TRACE_V3_VERSION
    local_v3 = (local_major, local_minor) >= _NIX_BUILD_TRACE_V3_VERSION
    if client_v3 != local_v3:
        raise StageAInputError(
            "content-addressed proof builds cross the incompatible Nix 2.35 "
            f"build-trace boundary: client uses Nix {client_version}; local "
            f"daemon uses Nix {local_version}. Use a Nix client on the same "
            "side of the 2.35 boundary as the daemon."
        )
    incompatible: list[str] = []
    for store in (
        _ca_builder_stores(builders_file)
        if builders_file is not None
        else []
    ):
        remote_major, remote_minor, remote_version = _nix_store_version(store=store)
        remote_v3 = (remote_major, remote_minor) >= _NIX_BUILD_TRACE_V3_VERSION
        if local_v3 != remote_v3:
            incompatible.append(f"{store} uses Nix {remote_version}")
    if incompatible:
        raise StageAInputError(
            "content-addressed remote proof builds cross the incompatible Nix "
            f"2.35 build-trace boundary: local daemon uses Nix {local_version}; "
            + "; ".join(incompatible)
            + ". Upgrade the coordinating local Nix daemon to 2.35 or newer, "
            "or temporarily set "
            "SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED=false."
        )


def _remove_relational_build_output(path: Path) -> None:
    if not path.exists():
        return
    directories = [
        child for child in path.rglob("*")
        if child.is_dir() and not child.is_symlink()
    ]
    for directory in directories:
        directory.chmod(directory.stat().st_mode | 0o700)
    path.chmod(path.stat().st_mode | 0o700)
    shutil.rmtree(path)


def _trusted_builder_public_keys(
    trusted_public_keys_file: Path | None,
) -> list[str]:
    inline = os.environ.get(
        "SPAGHETTI_EXTRACTOR_NIX_TRUSTED_PUBLIC_KEYS", ""
    ).split()
    file_keys: list[str] = []
    if trusted_public_keys_file is not None:
        key_path = Path(trusted_public_keys_file).resolve()
        if not key_path.is_file():
            raise StageAInputError(
                f"Nix builder public-key file does not exist: {key_path}"
            )
        file_keys = [
            line.strip()
            for line in key_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    keys = list(dict.fromkeys([*file_keys, *inline]))
    invalid = [key for key in keys if _NIX_PUBLIC_KEY_RE.fullmatch(key) is None]
    if invalid:
        raise StageAInputError(
            "invalid Nix builder public key(s): " + ", ".join(repr(key) for key in invalid)
        )
    return keys


def _append_relational_remote_options(
    command: list[str],
    *,
    builders_file: Path | None,
    trusted_public_keys_file: Path | None,
) -> list[str]:
    if builders_file is not None:
        command.extend([
            "--option",
            "builders-use-substitutes",
            os.environ.get(
                "SPAGHETTI_EXTRACTOR_NIX_BUILDERS_USE_SUBSTITUTES", "true"
            ),
        ])
    substituters = os.environ.get("SPAGHETTI_EXTRACTOR_NIX_SUBSTITUTERS")
    if substituters:
        command.extend(["--option", "substituters", substituters])
    trusted_keys = _trusted_builder_public_keys(trusted_public_keys_file)
    if trusted_keys:
        command.extend([
            "--option", "extra-trusted-public-keys", " ".join(trusted_keys)
        ])
    return command


def _relational_nix_build_command(
    expression: str,
    builders_file: Path | None,
    trusted_public_keys_file: Path | None = None,
) -> list[str]:
    command = _relational_nix_build_prefix(
        builders_file, trusted_public_keys_file
    )
    command.extend(["--impure", "--expr", expression])
    return command


def _relational_nix_build_prefix(
    builders_file: Path | None,
    trusted_public_keys_file: Path | None = None,
) -> list[str]:
    command = [_nix_executable(), "build"]
    if builders_file is not None:
        command.extend([
            "--max-jobs", "0", "--cores", "2",
            "--builders", _nix_builders_spec(builders_file),
        ])
    command.extend(["--no-link", "--json"])
    _append_relational_remote_options(
        command,
        builders_file=builders_file,
        trusted_public_keys_file=trusted_public_keys_file,
    )
    return command


def _relational_nix_installable_build_command(
    installables: list[str],
    builders_file: Path | None,
    trusted_public_keys_file: Path | None = None,
) -> list[str]:
    command = _relational_nix_build_prefix(
        builders_file, trusted_public_keys_file
    )
    command.extend(installables)
    return command


def _relational_nix_evaluation_cache_key(
    *,
    prepared: Path,
    evaluator: Path,
    flake_root: Path,
    requested_target_nodes: list[str],
) -> str:
    inputs = {
        "format": _NIX_EVALUATION_CACHE_FORMAT,
        "module_graph_sha256": sha256_file(prepared / "module-graph.json"),
        "prepared_manifest_sha256": (
            None
            if requested_target_nodes
            else sha256_file(prepared / "prepared-proof.json")
        ),
        "artifact_manifest_sha256": (
            sha256_file(prepared / "artifact-manifest.json")
            if (prepared / "artifact-manifest.json").is_file()
            else None
        ),
        "evaluator_sha256": sha256_file(evaluator),
        "flake_lock_sha256": sha256_file(flake_root / "flake.lock"),
        "target_nodes": requested_target_nodes,
        "content_addressed": _content_addressed_derivations_requested(),
        "system": {
            "sysname": os.uname().sysname,
            "machine": os.uname().machine,
        },
    }
    return sha256_bytes(
        json.dumps(inputs, separators=(",", ":"), sort_keys=True).encode("ascii")
    )


def _relational_nix_evaluation_cache_path(cache_key: str) -> Path | None:
    cache_root = _relational_cache_dir()
    if cache_root is None:
        return None
    return cache_root / "nix-evaluations-v1" / f"{cache_key}.json"


def _cached_relational_nix_installables(
    cache_path: Path | None,
    *,
    cache_key: str,
) -> list[str] | None:
    if cache_path is None or not cache_path.is_file():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("format") != _NIX_EVALUATION_CACHE_FORMAT
        or payload.get("cache_key") != cache_key
    ):
        return None
    installables = payload.get("installables")
    if (
        not isinstance(installables, list)
        or not installables
        or not all(
            isinstance(installable, str)
            and re.fullmatch(r"/nix/store/[a-z0-9]+-[^\s^]+\.drv\^out", installable)
            and Path(installable.removesuffix("^out")).is_file()
            for installable in installables
        )
    ):
        return None
    return installables


def _publish_relational_nix_evaluation(
    cache_path: Path | None,
    *,
    cache_key: str,
    build_outputs: list[dict[str, Any]],
) -> None:
    if cache_path is None:
        return
    installables = [
        f"{output['drvPath']}^out"
        for output in build_outputs
        if isinstance(output, dict)
        and isinstance(output.get("drvPath"), str)
        and output["drvPath"].endswith(".drv")
    ]
    if len(installables) != len(build_outputs) or not installables:
        return
    write_json(
        cache_path,
        {
            "format": _NIX_EVALUATION_CACHE_FORMAT,
            "cache_key": cache_key,
            "installables": installables,
        },
    )


def _relational_semantic_boundary_cache_path(
    semantic_id: str,
) -> Path | None:
    cache_root = _relational_cache_dir()
    if cache_root is None:
        return None
    return cache_root / "nix-semantic-boundaries-v1" / f"{semantic_id}.json"


def _cached_relational_semantic_boundary(
    node: Mapping[str, Any],
) -> Path | None:
    semantic_id = node.get("semantic_id")
    if not isinstance(semantic_id, str):
        return None
    cache_path = _relational_semantic_boundary_cache_path(semantic_id)
    if cache_path is None or not cache_path.is_file():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        semantic_path = Path(payload["semantic_path"])
        interface = _read_json(semantic_path / "interface.json")
    except (KeyError, OSError, TypeError, json.JSONDecodeError, StageAInputError):
        return None
    try:
        resolved = semantic_path.resolve(strict=True)
        resolved.relative_to("/nix/store")
    except (OSError, ValueError):
        return None
    if (
        payload.get("format") != _NIX_SEMANTIC_BOUNDARY_FORMAT
        or payload.get("semantic_id") != semantic_id
        or payload.get("node_id") != node.get("id")
        or interface.get("format") != "stage-a-lean-semantic-interface-v1"
        or interface.get("id") != node.get("id")
        or interface.get("modules") != node.get("modules")
        or interface.get("dependencies") != node.get("dependencies")
        or interface.get("source_sha256") != node.get("source_sha256")
        or interface.get("semantic_id") != semantic_id
        or interface.get("dependency_semantic_ids")
            != node.get("dependency_semantic_ids")
        or interface.get("semantic_recipe_version")
            != node.get("semantic_recipe_version")
    ):
        return None
    outputs = interface.get("outputs")
    if (
        not isinstance(outputs, list)
        or {output.get("module") for output in outputs if isinstance(output, dict)}
            != set(node.get("modules", []))
        or not all(
            isinstance(output, dict)
            and isinstance(output.get("olean_sha256"), str)
            and (resolved / "StageA" / f"{output.get('module')}.olean").is_file()
            for output in outputs
        )
    ):
        return None
    return resolved


def _relational_incremental_evaluation(
    graph: Mapping[str, Any],
    requested_target_nodes: list[str],
) -> tuple[list[str], dict[str, dict[str, str]]]:
    roots = requested_target_nodes or [graph["final_node"]]
    closure = _relational_node_closure(dict(graph), roots)
    nodes = {
        node["id"]: node
        for node in graph["nodes"]
        if node["id"] in closure
    }
    cached = {
        node_id: semantic_path
        for node_id, node in nodes.items()
        if (semantic_path := _cached_relational_semantic_boundary(node)) is not None
    }
    active = set(nodes) - set(cached)
    # The requested roots must be instantiated so the evaluator can produce
    # their detached result or final audit output. Their semantic dependencies
    # may still enter through cached boundaries.
    active.update(roots)
    boundary_ids = {
        dependency
        for node_id in active
        for dependency in nodes[node_id]["dependencies"]
        if dependency not in active
    }
    missing_boundaries = boundary_ids - set(cached)
    if missing_boundaries:
        raise StageAInputError(
            "incremental Nix evaluation omitted uncached dependency nodes "
            + repr(sorted(missing_boundaries))
        )
    boundaries = {
        node_id: {
            "node_id": node_id,
            "semantic_id": nodes[node_id]["semantic_id"],
            "semantic_path": str(cached[node_id]),
        }
        for node_id in sorted(boundary_ids)
    }
    return sorted(active), boundaries


def _publish_relational_semantic_boundaries(
    result_paths: list[Path],
    graph: Mapping[str, Any],
) -> int:
    expected = {node["id"]: node for node in graph["nodes"]}
    pending: list[Path] = []
    for result_path in result_paths:
        root = result_path / "proof-node-root"
        if root.exists():
            pending.append(root)
        roots = result_path / "proof-node-roots"
        if roots.is_dir():
            pending.extend(sorted(roots.iterdir()))
    visited: set[Path] = set()
    published = 0
    while pending:
        semantic_path = pending.pop().resolve()
        if semantic_path in visited:
            continue
        visited.add(semantic_path)
        try:
            semantic_path.relative_to("/nix/store")
            interface = _read_json(semantic_path / "interface.json")
        except (OSError, ValueError, StageAInputError):
            continue
        node_id = interface.get("id")
        node = expected.get(node_id)
        if (
            node is not None
            and interface.get("semantic_id") == node.get("semantic_id")
            and interface.get("source_sha256") == node.get("source_sha256")
            and interface.get("dependency_semantic_ids")
                == node.get("dependency_semantic_ids")
        ):
            cache_path = _relational_semantic_boundary_cache_path(
                node["semantic_id"]
            )
            if cache_path is not None:
                write_json(
                    cache_path,
                    {
                        "format": _NIX_SEMANTIC_BOUNDARY_FORMAT,
                        "node_id": node_id,
                        "semantic_id": node["semantic_id"],
                        "semantic_path": str(semantic_path),
                    },
                )
                published += 1
        direct = (
            semantic_path
            / "nix-support"
            / "stage-a-direct-dependencies"
        )
        if direct.is_file():
            pending.extend(
                Path(path)
                for path in direct.read_text(encoding="utf-8").splitlines()
                if path
            )
    return published


def _relational_nix_work_reused(stderr: str, *, succeeded: bool) -> bool:
    """Classify reuse from the real build without evaluating the graph twice.

    This is diagnostic only. The typed Lean audit remains authoritative. Nix
    reports every realization, substitution, and remote copy on stderr; an
    otherwise successful quiet invocation therefore reused the complete graph.
    """

    if not succeeded:
        return False
    events = stderr.lower()
    realization_reported = any(marker in events for marker in (
        "building '",
        "building derivation",
    )) or re.search(r"copying (?:path|\d+ paths?)", events) is not None
    return not realization_reported


def _relational_nix_realize_command(
    flake_ref: str,
    builders_file: Path | None,
    trusted_public_keys_file: Path | None = None,
) -> list[str]:
    command = _relational_nix_build_prefix(
        builders_file, trusted_public_keys_file
    )
    command.append(flake_ref)
    return command


def _nix_single_output_path(stdout: str, *, operation: str) -> Path:
    try:
        build_outputs = json.loads(stdout)
        output_paths = [
            Path(path)
            for build in build_outputs
            for path in build["outputs"].values()
        ]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise StageAInputError(f"Nix returned malformed {operation} provenance") from exc
    if len(build_outputs) != 1 or len(output_paths) != 1:
        raise StageAInputError(
            f"Nix {operation} must produce exactly one derivation output"
        )
    return output_paths[0]


def stage_a_build_relational_from_nix(
    *,
    prepared_nix_ref: str,
    prepared_subpath: Path,
    out: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
    builder_trusted_public_keys_file: Path | None = None,
    target_nodes: list[str] | None = None,
) -> dict[str, Any]:
    """Realize a prepared proof first, then build its dynamic Lean graph.

    Content-addressed derivation outputs cannot be inspected with IFD during the
    same pure flake evaluation.  This explicit orchestration boundary preserves
    Nix caching for both phases while giving the graph evaluator a realized,
    concrete store path.
    """

    if not isinstance(prepared_nix_ref, str) or not prepared_nix_ref.strip():
        raise StageAInputError("prepared Nix reference must be a non-empty string")
    relative = Path(prepared_subpath)
    if relative.is_absolute() or ".." in relative.parts:
        raise StageAInputError("prepared Nix subpath must remain inside its output")

    out = Path(out).resolve()
    flake_root = _find_relational_flake_root(flake)
    builders_path: Path | None = None
    if builders_file is not None:
        builders_path = Path(builders_file).resolve()
        if not builders_path.is_file():
            raise StageAInputError(f"Nix builders file does not exist: {builders_path}")
    trusted_keys_path = (
        Path(builder_trusted_public_keys_file).resolve()
        if builder_trusted_public_keys_file is not None
        else None
    )
    trusted_keys = _trusted_builder_public_keys(trusted_keys_path)
    command = _relational_nix_realize_command(
        prepared_nix_ref, builders_path, trusted_keys_path
    )
    started = time.monotonic()
    process = subprocess.run(
        command,
        cwd=flake_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    realization_elapsed = round(time.monotonic() - started, 3)
    if process.returncode != 0:
        _remove_relational_build_output(out)
        out.mkdir(parents=True)
        (out / "prepared-nix.stdout").write_text(process.stdout, encoding="utf-8")
        (out / "prepared-nix.stderr").write_text(process.stderr, encoding="utf-8")
        failure = {
            "format": "stage-a-prepared-nix-realization-v1",
            "status": "incomplete",
            "prepared_nix_ref": prepared_nix_ref,
            "prepared_subpath": relative.as_posix(),
            "returncode": process.returncode,
            "elapsed_seconds": realization_elapsed,
        }
        write_json(out / "prepared-nix-realization.json", failure)
        raise StageAInputError(
            "Nix prepared-proof realization failed; complete logs are in "
            f"{out / 'prepared-nix.stderr'}:\n"
            + process.stderr[-8000:]
        )

    result_path = _nix_single_output_path(
        process.stdout, operation="prepared-proof realization"
    ).resolve()
    prepared = (result_path / relative).resolve()
    if prepared != result_path and result_path not in prepared.parents:
        raise StageAInputError("prepared Nix subpath resolves outside its output")
    if not prepared.is_dir():
        raise StageAInputError(
            f"prepared Nix subpath does not exist as a directory: {prepared}"
        )

    result = stage_a_build_relational(
        prepared=prepared,
        out=out,
        flake=flake_root,
        builders_file=builders_path,
        builder_trusted_public_keys_file=trusted_keys_path,
        target_nodes=target_nodes,
    )
    realization = {
        "format": "stage-a-prepared-nix-realization-v1",
        "status": "realized",
        "prepared_nix_ref": prepared_nix_ref,
        "prepared_subpath": relative.as_posix(),
        "result_path": str(result_path),
        "prepared_path": str(prepared),
        "builders_file": str(builders_path) if builders_path is not None else None,
        "builder_trusted_public_keys": trusted_keys,
        "local_derivation_builds": builders_path is None,
        "elapsed_seconds": realization_elapsed,
    }
    write_json(out / "prepared-nix-realization.json", realization)
    return {**result, "prepared_realization": realization}


def _relational_node_closure(
    graph: dict[str, Any], target_nodes: list[str]
) -> set[str]:
    nodes = {node["id"]: node for node in graph["nodes"]}
    closure: set[str] = set()

    def include(node_id: str) -> None:
        if node_id in closure:
            return
        closure.add(node_id)
        for dependency in nodes[node_id]["dependencies"]:
            include(dependency)

    for target_node in target_nodes:
        include(target_node)
    return closure


def _lean_source_projection_sha256(graph: Mapping[str, Any]) -> str:
    modules = graph.get("modules")
    if not isinstance(modules, Mapping):
        raise StageAInputError("Lean module graph omits source provenance")
    return sha256_bytes(
        json.dumps(
            [
                {
                    "module": module,
                    "source_sha256": metadata["source_sha256"],
                }
                for module, metadata in sorted(modules.items())
            ],
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    )


def _lean_semantic_projection_sha256(
    graph: Mapping[str, Any], node_ids: set[str] | None = None
) -> str:
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise StageAInputError("Lean module graph omits semantic nodes")
    projection = [
        {
            "id": node["id"],
            "semantic_id": node["semantic_id"],
        }
        for node in nodes
        if node_ids is None or node["id"] in node_ids
    ]
    return sha256_bytes(
        json.dumps(
            sorted(projection, key=lambda row: row["id"]),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    )


def _numbered_relational_modules(
    modules: set[str] | dict[str, Any], prefix: str,
) -> list[str]:
    return sorted(
        (
            module
            for module in modules
            if module.startswith(prefix)
            and module.removeprefix(prefix).isdigit()
        ),
        key=lambda module: int(module.removeprefix(prefix)),
    )


def _relational_raw_build_nodes(reachable: set[str]) -> list[dict[str, Any]]:
    stable_pack_buckets = max(
        1,
        int(
            os.environ.get(
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NIX_PACK_BUCKETS",
                "32",
            )
        ),
    )
    static_usage_pack_buckets = max(
        1,
        int(
            os.environ.get(
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_USAGE_NIX_PACK_BUCKETS",
                "64",
            )
        ),
    )
    static_code_map_pack_size = max(
        1,
        int(
            os.environ.get(
                # These proofs reduce a full PE-backed mapping context and can
                # take minutes apiece. Keep each one as its own CA derivation so
                # cancellation or a later sibling failure cannot discard
                # already-completed kernel work.
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_CODE_MAP_NIX_PACK_MODULES",
                "1",
            )
        ),
    )
    packed: set[str] = set()
    raw_nodes: list[dict[str, Any]] = []
    for prefix, label, bucket_count in (
        (
            "RelationalDefinitionsShard",
            "definitions-pack",
            stable_pack_buckets,
        ),
        ("RelationalProofShard", "local-proof-pack", stable_pack_buckets),
        (
            "RelationalProofStaticUsageLeaf",
            "static-usage-pack",
            static_usage_pack_buckets,
        ),
    ):
        modules = _numbered_relational_modules(reachable, prefix)
        buckets: dict[int, list[str]] = {}
        for module in modules:
            bucket = int.from_bytes(
                bytes.fromhex(sha256_bytes(module.encode("ascii")))[:8],
                "big",
            ) % bucket_count
            buckets.setdefault(bucket, []).append(module)
        width = max(2, len(f"{bucket_count - 1:x}"))
        for bucket, members in sorted(buckets.items()):
            members.sort()
            packed.update(members)
            raw_nodes.append({
                "id": f"{label}-{bucket:0{width}x}",
                "modules": members,
            })
    static_code_map_modules = _numbered_relational_modules(
        reachable, "RelationalStaticCodeMapChunk"
    )
    for pack_index, offset in enumerate(
        range(0, len(static_code_map_modules), static_code_map_pack_size)
    ):
        members = static_code_map_modules[
            offset : offset + static_code_map_pack_size
        ]
        packed.update(members)
        raw_nodes.append({
            "id": f"static-code-map-pack-{pack_index:03d}",
            "modules": members,
        })
    for module in sorted(reachable - packed):
        node_id = re.sub(r"[^a-z0-9]+", "-", module.lower()).strip("-")
        raw_nodes.append({"id": node_id, "modules": [module]})
    return raw_nodes


def _attach_relational_semantic_identities(
    nodes: list[dict[str, Any]],
) -> None:
    """Bind each build node to source and direct semantic dependencies only."""

    by_id = {node["id"]: node for node in nodes}
    identities: dict[str, str] = {}
    visiting: set[str] = set()

    def identify(node_id: str) -> str:
        if node_id in identities:
            return identities[node_id]
        if node_id in visiting:
            raise StageAInputError(
                f"generated Lean build graph contains a cycle at {node_id}"
            )
        node = by_id.get(node_id)
        if node is None:
            raise StageAInputError(
                f"generated Lean build graph names missing node {node_id}"
            )
        visiting.add(node_id)
        dependencies = [
            {
                "node": dependency,
                "semantic_id": identify(dependency),
            }
            for dependency in node["dependencies"]
        ]
        visiting.remove(node_id)
        identity = sha256_bytes(
            json.dumps(
                {
                    "format": _LEAN_SEMANTIC_NODE_ID_FORMAT,
                    "recipe_version": _LEAN_SEMANTIC_RECIPE_VERSION,
                    "modules": node["modules"],
                    "source_sha256": node["source_sha256"],
                    "dependencies": dependencies,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        )
        node["semantic_id"] = identity
        node["dependency_semantic_ids"] = [
            dependency["semantic_id"] for dependency in dependencies
        ]
        node["semantic_recipe_version"] = _LEAN_SEMANTIC_RECIPE_VERSION
        identities[node_id] = identity
        return identity

    for node_id in sorted(by_id):
        identify(node_id)


def _relational_nix_expression(
    *,
    prepared: Path,
    graph: dict[str, Any],
    evaluator: Path,
    flake_root: Path,
    target_nodes: list[str],
    active_node_ids: list[str] | None = None,
    prebuilt_nodes: Mapping[str, Mapping[str, str]] | None = None,
) -> str:
    content_addressed = (
        "true" if _content_addressed_derivations_requested() else "false"
    )
    locked_nixpkgs = _locked_flake_input(flake_root / "flake.lock", "nixpkgs")
    artifact_manifest_lines = (
        [
            "  artifactManifest = builtins.path {",
            f"    path = builtins.toPath {json.dumps(str(prepared / 'artifact-manifest.json'))};",
            '    name = "stage-a-checked-artifact-manifest.json";',
            "  };",
        ]
        if graph.get("format") == LEAN_MODULE_GRAPH_V2_FORMAT
        else ["  artifactManifest = null;"]
    )
    prepared_manifest_lines = (
        ["  preparedManifest = null;"]
        if target_nodes
        else [
            "  preparedManifest = builtins.path {",
            f"    path = builtins.toPath {json.dumps(str(prepared / 'prepared-proof.json'))};",
            '    name = "stage-a-prepared-proof.json";',
            "  };",
        ]
    )
    return "\n".join([
        "let",
        f"  nixpkgs = builtins.fetchTree (builtins.fromJSON {json.dumps(json.dumps(locked_nixpkgs, sort_keys=True))});",
        "  pkgs = import nixpkgs {",
        "    system = builtins.currentSystem;",
        "    config = {};",
        "    overlays = [];",
        "  };",
        "  graphFile = builtins.path {",
        f"    path = builtins.toPath {json.dumps(str(prepared / 'module-graph.json'))};",
        '    name = "stage-a-module-graph.json";',
        "  };",
        *prepared_manifest_lines,
        *artifact_manifest_lines,
        f"  sourceRoot = builtins.toPath {json.dumps(str(prepared))};",
        "  targetNodes = [ "
        + " ".join(json.dumps(node) for node in target_nodes)
        + " ];",
        "  activeNodeIds = [ "
        + " ".join(json.dumps(node) for node in (active_node_ids or []))
        + " ];",
        "  prebuiltNodes = builtins.fromJSON "
        + json.dumps(json.dumps(prebuilt_nodes or {}, sort_keys=True))
        + ";",
        f"in import (builtins.toPath {json.dumps(str(evaluator))}) {{",
        "  inherit pkgs graphFile preparedManifest artifactManifest sourceRoot "
        "targetNodes activeNodeIds prebuiltNodes;",
        f"  contentAddressed = {content_addressed};",
        "}",
    ])


def _relational_focused_input(
    prepared: Path,
    graph: Mapping[str, Any],
    target_nodes: list[str],
) -> dict[str, int] | None:
    if not target_nodes:
        return None
    closure = _relational_node_closure(dict(graph), target_nodes)
    modules = sorted({
        module
        for node in graph["nodes"]
        if node["id"] in closure
        for module in node["modules"]
    })
    return {
        "nodes": len(closure),
        "modules": len(modules),
        "source_bytes": sum(
            (prepared / graph["modules"][module]["source"]).stat().st_size
            for module in modules
        ),
    }


def stage_a_build_relational(
    *,
    prepared: Path,
    out: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
    builder_trusted_public_keys_file: Path | None = None,
    target_nodes: list[str] | None = None,
) -> dict[str, Any]:
    prepared = Path(prepared).resolve()
    out = Path(out).resolve()
    graph = _validate_prepared_relational(prepared)
    graph_node_ids = {node["id"] for node in graph["nodes"]}
    requested_target_nodes = list(target_nodes or [])
    if len(requested_target_nodes) != len(set(requested_target_nodes)):
        raise StageAInputError("relational target-node inventory contains duplicates")
    missing_target_nodes = sorted(set(requested_target_nodes) - graph_node_ids)
    if missing_target_nodes:
        raise StageAInputError(
            "prepared module graph has no nodes " + repr(missing_target_nodes)
        )
    if out == prepared or prepared in out.parents:
        raise StageAInputError("build output must not be inside the prepared proof directory")
    acceptance = graph["acceptance"]
    if not requested_target_nodes and acceptance["status"] != "ready":
        _remove_relational_build_output(out)
        out.mkdir(parents=True)
        result = {
            "format": "stage-a-relational-nix-build-v1",
            "status": "incomplete",
            "verdict": "incomplete",
            "acceptance": acceptance,
            "checks": {
                "prepared_graph_valid": True,
                "whole_program_acceptance_ready": False,
                "nix_graph_built": False,
            },
            "diagnostic": {
                "category": "whole_program_certificate_missing",
                "severity": "hard",
                "next_action": acceptance["blockers"][0]["next_action"],
            },
            "elapsed_seconds": 0.0,
        }
        write_json(out / "verdict.json", result)
        return result

    evaluator = _relational_nix_evaluator()
    flake_root = _find_relational_flake_root(flake)
    focused_input = _relational_focused_input(
        prepared, graph, requested_target_nodes
    )
    builders_path: Path | None = None
    if builders_file is not None:
        builders_path = Path(builders_file).resolve()
        if not builders_path.is_file():
            raise StageAInputError(f"Nix builders file does not exist: {builders_path}")
    if _content_addressed_derivations_requested():
        _check_remote_ca_build_trace_compatibility(builders_path)
    trusted_keys_path = (
        Path(builder_trusted_public_keys_file).resolve()
        if builder_trusted_public_keys_file is not None
        else None
    )
    trusted_keys = _trusted_builder_public_keys(trusted_keys_path)
    cache_key = _relational_nix_evaluation_cache_key(
        prepared=prepared,
        evaluator=evaluator,
        flake_root=flake_root,
        requested_target_nodes=requested_target_nodes,
    )
    evaluation_cache_path = _relational_nix_evaluation_cache_path(cache_key)
    cached_installables = _cached_relational_nix_installables(
        evaluation_cache_path,
        cache_key=cache_key,
    )
    evaluation_reused = cached_installables is not None
    incremental_active_nodes: list[str] = []
    incremental_boundaries: dict[str, dict[str, str]] = {}

    def plan_incremental_evaluation() -> str:
        nonlocal incremental_active_nodes, incremental_boundaries
        incremental_active_nodes, incremental_boundaries = (
            _relational_incremental_evaluation(
                graph, requested_target_nodes
            )
        )
        return _relational_nix_expression(
            prepared=prepared,
            graph=graph,
            evaluator=evaluator,
            flake_root=flake_root,
            target_nodes=requested_target_nodes,
            active_node_ids=incremental_active_nodes,
            prebuilt_nodes=incremental_boundaries,
        )

    expression = None
    if cached_installables is not None:
        command = _relational_nix_installable_build_command(
            cached_installables,
            builders_path,
            trusted_keys_path,
        )
    else:
        expression = plan_incremental_evaluation()
        command = _relational_nix_build_command(
            expression, builders_path, trusted_keys_path
        )
    started = time.monotonic()
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0 and cached_installables is not None:
        evaluation_reused = False
        expression = plan_incremental_evaluation()
        command = _relational_nix_build_command(
            expression, builders_path, trusted_keys_path
        )
        process = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    elapsed = round(time.monotonic() - started, 3)
    nix_work_reused = _relational_nix_work_reused(
        process.stderr, succeeded=process.returncode == 0
    )
    if process.returncode != 0:
        _remove_relational_build_output(out)
        out.mkdir(parents=True)
        (out / "nix.stdout").write_text(process.stdout, encoding="utf-8")
        (out / "nix.stderr").write_text(process.stderr, encoding="utf-8")
        failure = {
            "format": "stage-a-relational-nix-build-v1",
            "status": "incomplete",
            "verdict": "incomplete",
            "diagnostic": {
                "category": "nix_graph_build_failed",
                "severity": "hard",
                "next_action": "inspect nix.stderr and the first failed derivation log",
            },
            "returncode": process.returncode,
            "elapsed_seconds": elapsed,
        }
        write_json(out / "verdict.json", failure)
        raise StageAInputError(
            f"Nix relational proof graph failed; complete logs are in {out / 'nix.stderr'}:\n"
            + process.stderr[:4000]
            + ("\n...\n" if len(process.stderr) > 12000 else "")
            + process.stderr[-8000:]
        )
    try:
        build_outputs = json.loads(process.stdout)
        result_paths = [Path(output["outputs"]["out"]) for output in build_outputs]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
        raise StageAInputError("Nix returned a malformed relational graph result") from exc
    if not evaluation_reused:
        _publish_relational_nix_evaluation(
            evaluation_cache_path,
            cache_key=cache_key,
            build_outputs=build_outputs,
        )
    semantic_boundaries_published = _publish_relational_semantic_boundaries(
        result_paths,
        graph,
    )
    evaluated_node_count = (
        0 if evaluation_reused else len(incremental_active_nodes)
    )
    prebuilt_boundary_count = (
        0 if evaluation_reused else len(incremental_boundaries)
    )
    if requested_target_nodes:
        node_results = [_read_json(path / "module-result.json") for path in result_paths]
        observed_target_nodes = {node_result.get("id") for node_result in node_results}
        expected_nodes = {
            node["id"]: node
            for node in graph["nodes"]
            if node["id"] in requested_target_nodes
        }
        if (
            observed_target_nodes != set(requested_target_nodes)
            or len(node_results) != len(requested_target_nodes)
            or any(
                node_result.get("format") != "stage-a-lean-node-result-v1"
                or not isinstance(node_result.get("outputs"), list)
                for node_result in node_results
            )
            or any(
                node_result.get("semantic_id")
                    != expected_nodes[node_result["id"]]["semantic_id"]
                or node_result.get("dependency_semantic_ids")
                    != expected_nodes[node_result["id"]][
                        "dependency_semantic_ids"
                    ]
                or node_result.get("source_sha256")
                    != expected_nodes[node_result["id"]]["source_sha256"]
                for node_result in node_results
            )
        ):
            raise StageAInputError("Nix returned malformed relational node-set provenance")
        _remove_relational_build_output(out)
        out.mkdir(parents=True)
        if len(requested_target_nodes) == 1:
            result_path = result_paths[0]
            node_result = node_results[0]
            shutil.copytree(result_path, out, dirs_exist_ok=True, symlinks=True)
            out.chmod(out.stat().st_mode | 0o700)
            result = {
                "format": "stage-a-relational-nix-node-build-v1",
                "status": "checked",
                "target_node": requested_target_nodes[0],
                "result_path": str(result_path),
                "elapsed_seconds": elapsed,
                "focused_input": focused_input,
                "nix_work_reused": nix_work_reused,
                "nix_evaluation_reused": evaluation_reused,
                "nix_evaluated_nodes": evaluated_node_count,
                "nix_prebuilt_boundaries": prebuilt_boundary_count,
                "semantic_boundaries_published": semantic_boundaries_published,
                "node": node_result,
            }
            write_json(out / "node-build.json", result)
        else:
            result_by_id = {node_result["id"]: node_result for node_result in node_results}
            path_by_id = {
                node_result["id"]: path
                for node_result, path in zip(node_results, result_paths, strict=True)
            }
            result = {
                "format": "stage-a-relational-nix-node-set-build-v1",
                "status": "checked",
                "target_nodes": requested_target_nodes,
                "result_paths": [str(path_by_id[node]) for node in requested_target_nodes],
                "elapsed_seconds": elapsed,
                "focused_input": focused_input,
                "nix_work_reused": nix_work_reused,
                "nix_evaluation_reused": evaluation_reused,
                "nix_evaluated_nodes": evaluated_node_count,
                "nix_prebuilt_boundaries": prebuilt_boundary_count,
                "semantic_boundaries_published": semantic_boundaries_published,
                "nodes": [result_by_id[node] for node in requested_target_nodes],
            }
            write_json(out / "node-set-build.json", result)
        for directory in [out, *(
            child for child in out.rglob("*") if child.is_dir() and not child.is_symlink()
        )]:
            directory.chmod(directory.stat().st_mode | 0o700)
        return result
    result_path = result_paths[0]
    final_node = graph.get("final_node")
    if not isinstance(final_node, str) or not final_node:
        raise StageAInputError("relational graph omits its final node")
    acceptance_node_ids = _relational_node_closure(graph, [final_node])
    acceptance_dependency_ids = acceptance_node_ids - {final_node}
    audit = _read_json(result_path / "audit.json")
    dependency_view = _read_json(result_path / "dependency-view.json")
    if (
        dependency_view.get("format")
            != "stage-a-lean-root-dependency-view-v2"
        or dependency_view.get("node_count") != len(acceptance_dependency_ids)
        or dependency_view.get("reference_count") != len(acceptance_node_ids)
        or dependency_view.get("root_node") != final_node
        or dependency_view.get("archive_bytes") != 0
        or dependency_view.get("materialized_oleans") != 0
    ):
        raise StageAInputError(
            "Nix relational graph emitted invalid dependency-view provenance"
        )
    node_provenance_payload = _read_json(result_path / "node-provenance.json")
    node_provenance = node_provenance_payload.get("nodes")
    if (
        node_provenance_payload.get("format") != "stage-a-lean-node-provenance-v1"
        or not isinstance(node_provenance, list)
        or not all(isinstance(node, dict) for node in node_provenance)
    ):
        raise StageAInputError("Nix relational graph omitted node content provenance")
    expected_nodes = {
        node["id"]: node
        for node in graph["nodes"]
        if node["id"] in acceptance_node_ids
    }
    observed_nodes = {node.get("id"): node for node in node_provenance}
    if set(observed_nodes) != set(expected_nodes) or len(observed_nodes) != len(node_provenance):
        raise StageAInputError("Nix relational node provenance does not match the prepared graph")
    for node_id, expected_node in expected_nodes.items():
        observed_node = observed_nodes[node_id]
        if (
            observed_node.get("source_sha256") != expected_node["source_sha256"]
            or observed_node.get("semantic_id") != expected_node["semantic_id"]
            or observed_node.get("dependency_semantic_ids")
                != expected_node["dependency_semantic_ids"]
            or observed_node.get("semantic_recipe_version")
                != expected_node["semantic_recipe_version"]
        ):
            raise StageAInputError(
                f"Nix node semantic provenance mismatch for {node_id}"
            )
        outputs = observed_node.get("outputs")
        if not isinstance(outputs, list) or {
            output.get("module") for output in outputs if isinstance(output, dict)
        } != set(expected_node["modules"]):
            raise StageAInputError(f"Nix node output inventory mismatch for {node_id}")
        if not all(
            isinstance(output, dict)
            and isinstance(output.get("olean_bytes"), int)
            and output["olean_bytes"] > 0
            and isinstance(output.get("olean_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", output["olean_sha256"])
            for output in outputs
        ):
            raise StageAInputError(f"Nix node output hash is invalid for {node_id}")
    path_info_process = subprocess.run(
        [_nix_executable(), "path-info", "--json", str(result_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if path_info_process.returncode != 0:
        raise StageAInputError(
            "cannot query Nix proof provenance:\n" + path_info_process.stderr[-4000:]
        )
    try:
        path_info = json.loads(path_info_process.stdout)
    except json.JSONDecodeError as exc:
        raise StageAInputError("Nix returned malformed path provenance") from exc

    prepared_proof_ir = _read_json(prepared / "relational-proof-ir.json")
    RelationalProofIR.parse(prepared_proof_ir)
    approved_axioms = set(graph["approved_axioms"])
    observed_axioms = audit.get("observed_axioms")
    theorem_checked = (
        audit.get("status") == "checked"
        and audit.get("lean_trust") == 0
        and audit.get("theorem") == graph["expected_final_theorem"]
        and isinstance(observed_axioms, list)
        and set(observed_axioms).issubset(approved_axioms)
    )
    proof_ir = _finalize_nix_proof_ir(
        prepared_proof_ir,
        theorem_checked=theorem_checked,
        theorem=graph["expected_final_theorem"],
        result_path=result_path,
    )
    RelationalProofIR.parse(proof_ir)
    checks = {
        "prepared_graph_valid": True,
        "nix_graph_built": audit.get("status") == "checked",
        "lean_trust_zero": audit.get("lean_trust") == 0,
        "final_theorem_matches": audit.get("theorem") == graph["expected_final_theorem"],
        "axioms_approved": isinstance(observed_axioms, list)
        and set(observed_axioms).issubset(approved_axioms),
        "proof_ir_satisfied": proof_ir["status"] == "satisfied",
        "contract_families_closed": all(
            family.get("status") in {"satisfied", "not_applicable"}
            for family in proof_ir.get("families", [])
        ),
        "original_artifact_matches": sha256_file(prepared / graph["artifacts"]["original"]["path"])
        == graph["artifacts"]["original"]["sha256"],
        "candidate_artifact_matches": sha256_file(prepared / graph["artifacts"]["candidate"]["path"])
        == graph["artifacts"]["candidate"]["sha256"],
    }
    status = "pass" if all(checks.values()) else "incomplete"
    _remove_relational_build_output(out)
    out.mkdir(parents=True)
    for name in RELATIONAL_PREPARED_REPORT_FILES:
        source = prepared / name
        if source.is_file():
            shutil.copyfile(source, out / name)
    shutil.copytree(prepared / "artifacts", out / "artifacts")
    source_projection_sha256 = _lean_source_projection_sha256(graph)
    source_reference = {
        "format": "stage-a-lean-source-reference-v1",
        "materialized": False,
        "module_count": len(graph["modules"]),
        "module_graph_sha256": sha256_file(prepared / "module-graph.json"),
        "prepared_path": str(prepared),
        "source_projection_sha256": source_projection_sha256,
    }
    write_json(out / "lean-source-reference.json", source_reference)
    semantic_reference = {
        "format": "stage-a-lean-semantic-graph-reference-v1",
        "root_node": final_node,
        "root_semantic_id": expected_nodes[final_node]["semantic_id"],
        "node_count": len(acceptance_node_ids),
        "semantic_projection_sha256": _lean_semantic_projection_sha256(
            graph, acceptance_node_ids
        ),
        "recipe_versions": sorted({
            expected_node["semantic_recipe_version"]
            for expected_node in expected_nodes.values()
        }),
    }
    write_json(
        out / "semantic-graph-reference.json",
        semantic_reference,
    )
    shutil.copyfile(result_path / "audit.json", out / "lean-audit.json")
    shutil.copyfile(result_path / "lean.stdout", out / "lean.stdout")
    shutil.copyfile(result_path / "lean.stderr", out / "lean.stderr")
    shutil.copyfile(
        result_path / "dependency-view.json",
        out / "dependency-view.json",
    )
    write_json(out / "relational-proof-ir.json", proof_ir)
    analysis_manifest = _read_json(out / "relational-analysis-manifest.json")
    proof_ir_sha256 = sha256_file(out / "relational-proof-ir.json")
    proof_ir_rows = [
        row
        for row in analysis_manifest.get("files", [])
        if isinstance(row, dict) and row.get("path") == "relational-proof-ir.json"
    ]
    if len(proof_ir_rows) != 1:
        raise StageAInputError(
            "relational analysis manifest does not bind exactly one proof IR"
        )
    proof_ir_rows[0]["sha256"] = proof_ir_sha256
    write_json(out / "relational-analysis-manifest.json", analysis_manifest)
    report_manifest = _read_json(out / "prepared-proof.json")
    report_manifest["proof_ir_sha256"] = proof_ir_sha256
    report_manifest["analysis_manifest_sha256"] = sha256_file(
        out / "relational-analysis-manifest.json"
    )
    write_json(out / "prepared-proof.json", report_manifest)
    provenance = {
        "format": "stage-a-relational-nix-provenance-v1",
        "executor": "nix",
        "flake": str(flake_root),
        "builders_file": str(Path(builders_file).resolve()) if builders_file is not None else None,
        "builder_trusted_public_keys": trusted_keys,
        "local_derivation_builds": builders_file is None,
        "flake_lock_sha256": sha256_file(flake_root / "flake.lock"),
        "evaluator_sha256": sha256_file(evaluator),
        "result_path": str(result_path),
        "nodes": node_provenance,
        "dependency_view": dependency_view,
        "lean_source_reference": source_reference,
        "semantic_graph_reference": semantic_reference,
        "nix_path_info": path_info,
        "elapsed_seconds": elapsed,
        "nix_work_reused": nix_work_reused,
        "nix_evaluation_reused": evaluation_reused,
        "nix_evaluated_nodes": evaluated_node_count,
        "nix_prebuilt_boundaries": prebuilt_boundary_count,
        "semantic_boundaries_published": semantic_boundaries_published,
    }
    write_json(out / "nix-provenance.json", provenance)
    result = {
        "format": "stage-a-relational-nix-build-v1",
        "status": status,
        "verdict": status,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "claim_scope": {
            "kind": "whole_program_observational_equivalence",
            "whole_program_observational_equivalence": status == "pass",
            "acceptance_eligible": status == "pass",
        },
        "expected_final_theorem": graph["expected_final_theorem"],
        "acceptance": graph["acceptance"],
        "original": {
            "path": graph["artifacts"]["original"]["path"],
            "sha256": graph["artifacts"]["original"]["sha256"],
        },
        "candidate": {
            "path": graph["artifacts"]["candidate"]["path"],
            "sha256": graph["artifacts"]["candidate"]["sha256"],
        },
        "interface_manifest_sha256": sha256_file(
            out / "stage-a-interface-manifest.json"
        ),
        "relation_contract_sha256": sha256_file(out / "relation-contract.json"),
        "proof_ir_sha256": sha256_file(out / "relational-proof-ir.json"),
        "static_word_relations_sha256": sha256_file(
            out / "relational-static-word-relations.json"
        ),
        "product_graph_sha256": sha256_file(out / "relational-product-graph.json"),
        "isa_requirements_sha256": sha256_file(out / "isa-requirements.json"),
        "whole_program_acceptance_sha256": sha256_file(
            out / "whole-program-acceptance.json"
        ),
        "composition_progress_sha256": sha256_file(
            out / "composition-progress.json"
        ),
        "module_graph_sha256": sha256_file(out / "module-graph.json"),
        "semantic_graph_reference_sha256": sha256_file(
            out / "semantic-graph-reference.json"
        ),
        "trusted_base_sha256": sha256_file(out / "trusted-base.json"),
        "checks": checks,
        "lean_audit": audit,
        "counts": graph["counts"],
        "elapsed_seconds": elapsed,
        "nix_work_reused": nix_work_reused,
        "nix_evaluation_reused": evaluation_reused,
        "nix_evaluated_nodes": evaluated_node_count,
        "nix_prebuilt_boundaries": prebuilt_boundary_count,
        "semantic_boundaries_published": semantic_boundaries_published,
        "provenance": {
            "result_path": str(result_path),
            "nix_paths": len(path_info),
            "node_derivations": len(node_provenance),
            "dependency_archive_bytes": dependency_view["archive_bytes"],
            "dependency_references": dependency_view["reference_count"],
            "materialized_dependency_oleans": dependency_view[
                "materialized_oleans"
            ],
        },
    }
    write_json(out / "verdict.json", result)
    return result


def _finalize_proof_ir(
    proof_ir: dict[str, Any],
    *,
    theorem_checked: bool,
    theorem: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    acceptance_theorem_checked = (
        theorem_checked and theorem in RELATIONAL_ACCEPTANCE_THEOREMS
    )
    certificate_type = (
        "LinkedWholeProgramCertificate"
        if theorem == RELATIONAL_LINKED_ACCEPTANCE_THEOREM
        else "WholeProgramCertificate"
    )
    execution_refinement_field = (
        f"{certificate_type}.runningProductNodesRefined"
        if theorem == RELATIONAL_LINKED_ACCEPTANCE_THEOREM
        else f"{certificate_type}.reachableExecutionEdgesRefined"
    )
    invariant_evidence = {
        **evidence,
        "kind": "lean_checked_inductive_invariant_family",
    }
    certificate_projection_by_kind = {
        "direct_call_push": (
            "lean_checked_reachable_running_node_refinement",
            (f"{certificate_type}.runningProductNodesRefined",),
        ),
        "return_slot_affine_transfer": (
            "lean_checked_reachable_running_node_refinement",
            (f"{certificate_type}.runningProductNodesRefined",),
        ),
        "return_slot_return_affine_transfer": (
            "lean_checked_reachable_running_node_refinement",
            (f"{certificate_type}.runningProductNodesRefined",),
        ),
        "machine_import_call_boundary": (
            "lean_checked_external_running_node_refinement",
            (
                f"{certificate_type}.runningProductNodesRefined",
                f"{certificate_type}.environmentsRefined",
            ),
        ),
        "external_jump_control_refinement": (
            "lean_checked_external_running_node_refinement",
            (
                f"{certificate_type}.runningProductNodesRefined",
                f"{certificate_type}.environmentsRefined",
            ),
        ),
        "memory_transition_preservation": (
            "lean_checked_reachable_execution_memory_refinement",
            tuple(dict.fromkeys((
                execution_refinement_field,
                f"{certificate_type}.runningProductNodesRefined",
            ))),
        ),
    }
    finalized_obligations = []
    for obligation in proof_ir["obligations"]:
        if obligation["kind"] == "relational_region_equivalence":
            finalized_obligations.append({
                **obligation,
                "status": "proved" if acceptance_theorem_checked else "incomplete",
                "evidence": evidence if acceptance_theorem_checked else None,
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] in {
                "product_graph_composition",
                "whole_program_observational_equivalence",
                "cfg_register_relation_preservation",
                "relational_product_graph_structure",
                "relational_product_graph_declared_edge_refinement",
                "relational_product_graph_decoded_exit_completeness",
                "relational_product_graph_reachable_local_refinement",
            }
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_whole_program_composition",
                    "theorem": theorem,
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] in {
                "cfg_bound_invariant", "cfg_address_separation_invariant",
            }
            and obligation.get("analysis", {}).get("status")
                == "candidate_requires_lean_replay"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": invariant_evidence,
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "mapped_relocation_image_relation"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_mapped_relocation_image_relation",
                    "lemma": (
                        "StageA.Relational."
                        "allMappedRelocationImageRelations_of_valueRegionsClosed"
                    ),
                },
            })
        elif acceptance_theorem_checked and obligation["kind"] == "static_proof_context":
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_static_proof_context",
                    "theorem": "StageA.GeneratedRelational.staticProofContextChecked",
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] in certificate_projection_by_kind
        ):
            evidence_kind, certificate_fields = certificate_projection_by_kind[
                obligation["kind"]
            ]
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": evidence_kind,
                    "certificate_fields": list(certificate_fields),
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "iat_memory_relation_override"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_iat_masked_memory_relation",
                    "lemma": "StageA.Relational.StateRel.ordinaryMemoryRelation",
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "external_call_product_edge_refinement"
            and obligation.get("status") == "pending_lean"
        ):
            edge_id = int(obligation["edge_id"])
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_paired_external_call_refinement",
                    "theorem": (
                        "StageA.GeneratedRelational."
                        f"externalCallEdge{edge_id}ProductRefinementChecked"
                    ),
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "paired_stack_range_world"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_launch_realizability",
                    "certificate_field": f"{certificate_type}.launchRealizable",
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] in {
                "return_pop",
                "return_slot_runtime_frame",
                "stack_window_reachability",
            }
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_reachable_running_node_refinement",
                    "certificate_field": (
                        f"{certificate_type}.runningProductNodesRefined"
                    ),
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "relational_segment_refinement"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_reachable_execution_edge_refinement",
                    "certificate_field": (
                        execution_refinement_field
                    ),
                },
            })
        else:
            finalized_obligations.append(obligation)
    assumption_obligations = [
        obligation for obligation in finalized_obligations
        if obligation["kind"] != "relational_region_equivalence"
        and obligation.get("status") != "proved"
    ]
    external_obligations = [
        obligation for obligation in finalized_obligations
        if obligation["kind"] == "external_call_product_edge_refinement"
    ]
    external_assumptions = [
        obligation for obligation in assumption_obligations
        if obligation["kind"] == "external_call_product_edge_refinement"
    ]
    finalized = dict(proof_ir)
    finalized["status"] = (
        "satisfied"
        if acceptance_theorem_checked and not assumption_obligations
        else "incomplete"
    )
    finalized["families"] = [
        {"family": "exact_pe_decode", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "x86_semantics", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "executable_coverage", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "roots_and_targets", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "static_proof_context", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "relational_regions", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {
            "family": "segment_refinement",
            "status": "incomplete" if any(
                obligation["kind"] == "relational_segment_refinement"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "cfg_register_relations",
            "status": "incomplete" if any(
                obligation["kind"] == "cfg_register_relation_preservation"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "whole_program_composition",
            "status": "incomplete" if any(
                obligation["kind"] == "product_graph_composition"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "whole_program_observational_equivalence",
            "status": "satisfied" if acceptance_theorem_checked else "incomplete",
        },
        {
            "family": "cfg_invariants",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "cfg_bound_invariant", "cfg_address_separation_invariant",
                }
                for obligation in assumption_obligations
            ) else "not_applicable",
        },
        {
            "family": "memory_relation",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "mapped_relocation_image_relation",
                    "memory_transition_preservation",
                    "iat_memory_relation_override",
                }
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "paired_external_environment_refinement",
            "status": (
                "incomplete" if external_assumptions else
                "satisfied" if external_obligations else
                "not_applicable"
            ),
        },
        {
            "family": "adversarial_environment",
            "status": "incomplete" if external_assumptions else "satisfied",
        },
    ]
    finalized["obligations"] = finalized_obligations
    return finalized


def _finalize_nix_proof_ir(
    proof_ir: dict[str, Any],
    *,
    theorem_checked: bool,
    theorem: str,
    result_path: Path,
) -> dict[str, Any]:
    return _finalize_proof_ir(
        proof_ir,
        theorem_checked=theorem_checked,
        theorem=theorem,
        evidence={
            "kind": "lean_trust_zero_nix_graph",
            "theorem": theorem,
            "lean_trust": 0,
            "nix_result_path": str(result_path),
        },
    )


def _finalize_local_proof_ir(
    proof_ir: dict[str, Any],
    *,
    theorem_checked: bool,
    theorem: str,
) -> dict[str, Any]:
    return _finalize_proof_ir(
        proof_ir,
        theorem_checked=theorem_checked,
        theorem=theorem,
        evidence={
            "kind": "lean_kernel_checked_local_graph",
            "theorem": theorem,
            "lean_trust": 0,
        },
    )


def _check_nix_relational_report(
    *, report: Path, verdict: dict[str, Any], out: Path | None
) -> dict[str, Any]:
    checks: dict[str, bool] = {
        "report_pass": verdict.get("verdict") == "pass",
        "profile_matches": verdict.get("profile") == STAGE_A_RELATIONAL_PROFILE_ID,
        "model_matches": verdict.get("model") == STAGE_A_RELATIONAL_MODEL_ID,
        "claim_scope_acceptance_eligible": (
            verdict.get("claim_scope", {}).get("acceptance_eligible") is True
            and verdict.get("claim_scope", {}).get(
                "whole_program_observational_equivalence"
            ) is True
        ),
    }
    audit: dict[str, Any] = {}
    if checks["report_pass"]:
        try:
            graph = _validate_prepared_relational(report, require_sources=False)
            proof_ir = _read_json(report / "relational-proof-ir.json")
            acceptance = _read_json(report / "whole-program-acceptance.json")
            composition_progress = _read_json(report / "composition-progress.json")
            RelationalProofIR.parse(proof_ir)
            WholeProgramAcceptanceIR.parse(acceptance)
            CompositionProgressIR.parse(composition_progress)
            audit = _read_json(report / "lean-audit.json")
            provenance = _read_json(report / "nix-provenance.json")
            dependency_view = _read_json(report / "dependency-view.json")
            source_reference = _read_json(report / "lean-source-reference.json")
            semantic_reference = _read_json(
                report / "semantic-graph-reference.json"
            )
            trusted_base = _read_json(report / "trusted-base.json")
        except StageAInputError:
            checks["prepared_report_valid"] = False
        else:
            checks["prepared_report_valid"] = True
            expected_theorem = graph.get("expected_final_theorem")
            checks.update({
                "acceptance_ready": (
                    acceptance.get("status") == "ready"
                    and expected_theorem in RELATIONAL_ACCEPTANCE_THEOREMS
                    and acceptance.get("required_theorem") == expected_theorem
                    and acceptance.get("theorem") == expected_theorem
                    and verdict.get("expected_final_theorem") == expected_theorem
                    and verdict.get("acceptance") == acceptance
                ),
                "lean_trust_zero": audit.get("lean_trust") == 0,
                "final_theorem_matches": (
                    audit.get("status") == "checked"
                    and audit.get("theorem") == expected_theorem
                ),
                "axioms_approved": (
                    isinstance(audit.get("observed_axioms"), list)
                    and set(audit["observed_axioms"]).issubset(
                        set(graph.get("approved_axioms", []))
                    )
                    and audit.get("unexpected_axioms") == []
                ),
                "proof_ir_satisfied": proof_ir.get("status") == "satisfied",
                "contract_families_closed": all(
                    family.get("status") in {"satisfied", "not_applicable"}
                    for family in proof_ir.get("families", [])
                ),
                "proof_ir_hash_matches": (
                    sha256_file(report / "relational-proof-ir.json")
                    == verdict.get("proof_ir_sha256")
                ),
                "contract_hash_matches": (
                    sha256_file(report / "relation-contract.json")
                    == verdict.get("relation_contract_sha256")
                ),
                "product_graph_hash_matches": (
                    sha256_file(report / "relational-product-graph.json")
                    == verdict.get("product_graph_sha256")
                ),
                "isa_requirements_hash_matches": (
                    sha256_file(report / "isa-requirements.json")
                    == verdict.get("isa_requirements_sha256")
                ),
                "acceptance_hash_matches": (
                    sha256_file(report / "whole-program-acceptance.json")
                    == verdict.get("whole_program_acceptance_sha256")
                ),
                "composition_progress_hash_matches": (
                    sha256_file(report / "composition-progress.json")
                    == verdict.get("composition_progress_sha256")
                ),
                "composition_ready": (
                    composition_progress.get("status") == "ready_for_lean"
                    and composition_progress.get("acceptance", {}).get("theorem")
                        == expected_theorem
                ),
                "module_graph_hash_matches": (
                    sha256_file(report / "module-graph.json")
                    == verdict.get("module_graph_sha256")
                ),
                "semantic_graph_reference_hash_matches": (
                    sha256_file(report / "semantic-graph-reference.json")
                    == verdict.get("semantic_graph_reference_sha256")
                ),
                "trusted_base_hash_matches": (
                    sha256_file(report / "trusted-base.json")
                    == verdict.get("trusted_base_sha256")
                ),
                "original_matches": (
                    sha256_file(report / graph["artifacts"]["original"]["path"])
                    == graph["artifacts"]["original"]["sha256"]
                    == proof_ir.get("original", {}).get("sha256")
                ),
                "candidate_matches": (
                    sha256_file(report / graph["artifacts"]["candidate"]["path"])
                    == graph["artifacts"]["candidate"]["sha256"]
                    == proof_ir.get("candidate", {}).get("sha256")
                ),
                "kernel_matches": all(
                    module not in graph["modules"]
                    or sha256_file(_LEAN_SOURCE_ROOT / f"{module}.lean")
                        == graph["modules"][module]["source_sha256"]
                    for module in RELATIONAL_KERNEL_MODULES
                ),
                "lean_source_reference_matches": (
                    source_reference.get("format")
                        == "stage-a-lean-source-reference-v1"
                    and source_reference.get("materialized") is False
                    and source_reference.get("module_count")
                        == len(graph["modules"])
                    and source_reference.get("module_graph_sha256")
                        == sha256_file(report / "module-graph.json")
                    and source_reference.get("source_projection_sha256")
                        == _lean_source_projection_sha256(graph)
                    and provenance.get("lean_source_reference")
                        == source_reference
                    and not (report / "lean").exists()
                ),
            })
            final_node = graph.get("final_node")
            acceptance_node_ids = (
                _relational_node_closure(graph, [final_node])
                if isinstance(final_node, str) and final_node
                else set()
            )
            acceptance_dependency_ids = acceptance_node_ids - {final_node}
            expected_nodes = {
                node["id"]: node
                for node in graph["nodes"]
                if node["id"] in acceptance_node_ids
            }
            observed_rows = provenance.get("nodes")
            observed_nodes = {
                row.get("id"): row
                for row in observed_rows or []
                if isinstance(row, dict)
            }
            checks["nix_node_provenance_matches"] = (
                provenance.get("format") == "stage-a-relational-nix-provenance-v1"
                and isinstance(observed_rows, list)
                and len(observed_rows) == len(observed_nodes)
                and set(observed_nodes) == set(expected_nodes)
                and all(
                    observed_nodes[node_id].get("source_sha256")
                        == expected["source_sha256"]
                    and observed_nodes[node_id].get("semantic_id")
                        == expected["semantic_id"]
                    and observed_nodes[node_id].get(
                        "dependency_semantic_ids"
                    ) == expected["dependency_semantic_ids"]
                    and observed_nodes[node_id].get(
                        "semantic_recipe_version"
                    ) == expected["semantic_recipe_version"]
                    and {
                        output.get("module")
                        for output in observed_nodes[node_id].get("outputs", [])
                        if isinstance(output, dict)
                    } == set(expected["modules"])
                    for node_id, expected in expected_nodes.items()
                )
            )
            checks["semantic_graph_reference_matches"] = (
                semantic_reference.get("format")
                    == "stage-a-lean-semantic-graph-reference-v1"
                and semantic_reference.get("root_node") == final_node
                and semantic_reference.get("root_semantic_id")
                    == expected_nodes.get(final_node, {}).get("semantic_id")
                and semantic_reference.get("node_count")
                    == len(acceptance_node_ids)
                and semantic_reference.get("semantic_projection_sha256")
                    == _lean_semantic_projection_sha256(
                        graph, acceptance_node_ids
                    )
                and semantic_reference.get("recipe_versions")
                    == sorted({
                        expected["semantic_recipe_version"]
                        for expected in expected_nodes.values()
                    })
                and provenance.get("semantic_graph_reference")
                    == semantic_reference
            )
            checks["dependency_view_provenance_matches"] = (
                dependency_view.get("format")
                    == "stage-a-lean-root-dependency-view-v2"
                and provenance.get("dependency_view") == dependency_view
                and dependency_view.get("node_count")
                    == len(acceptance_dependency_ids)
                and dependency_view.get("reference_count")
                    == len(acceptance_node_ids)
                and dependency_view.get("archive_bytes") == 0
                and dependency_view.get("materialized_oleans") == 0
            )
            checks["declared_build_checks_hold"] = all(
                value is True for value in verdict.get("checks", {}).values()
            )
            checks["trusted_base_matches_graph"] = (
                trusted_base.get("approved_axioms") == graph.get("approved_axioms")
            )
    status = "pass" if checks and all(checks.values()) else "incomplete"
    result = {
        "format": "stage-a-relational-proof-check-v1",
        "status": status,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "claim_scope": {
            "kind": "whole_program_observational_equivalence",
            "whole_program_observational_equivalence": status == "pass",
        },
        "checks": checks,
        "lean_check": audit,
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def _validate_checked_artifact_source_boundaries(
    sources: dict[str, Path],
) -> None:
    """Keep expensive semantics below a narrow, mechanically checked boundary."""
    raw_full_image_calls = (
        "regionBehaviorWithImports",
        "regionBehaviorWithMachineCallContracts",
    )

    def replays_raw_semantics(source: str) -> bool:
        for call in raw_full_image_calls:
            if re.search(
                rf"\b(?:def|abbrev)\b[^\n]*:=\s*{call}\b",
                source,
            ):
                return True
            if re.search(
                rf"{call}\b[^:]{{0,2048}}?:=\s*by\s+"
                r"(?:native_)?decide\b",
                source,
            ):
                return True
        return False

    for module, path in sources.items():
        if module in RELATIONAL_KERNEL_MODULES:
            continue
        source = path.read_text(encoding="utf-8")
        if re.fullmatch(
            r"RelationalProof(?:Original|Candidate)Semantic"
            r"(?:Chunk[0-9]+|Pack[0-9a-f]+)",
            module,
        ):
            forbidden_imports = tuple(
                imported
                for imported in _LEAN_IMPORT_PATTERN.findall(source)
                if imported.startswith("RelationalDefinitionsShard")
                or imported in {
                    "RelationalProofOriginal",
                    "RelationalProofCandidate",
                }
            )
            if forbidden_imports:
                raise StageAInputError(
                    f"checked semantic leaf StageA.{module} imports broad "
                    f"artifacts: {forbidden_imports!r}"
                )
            if any(call in source for call in raw_full_image_calls):
                raise StageAInputError(
                    f"checked semantic leaf StageA.{module} replays full-image "
                    "semantics"
                )
            if ".evaluate" not in source or "CheckedLocalRegionSemantics" not in source:
                raise StageAInputError(
                    f"checked semantic leaf StageA.{module} lacks a local replay"
                )
            continue
        if "DecodeChunk" in module:
            # Exact-image bindings and explicitly marked legacy x87 leaves are
            # the only generated modules allowed to mention the full-PE API.
            continue
        if any(call in source for call in raw_full_image_calls) and (
            replays_raw_semantics(source)
            or "CheckedDecoded" not in source
        ):
            raise StageAInputError(
                f"downstream generated module StageA.{module} replays raw "
                "region semantics"
            )


def _write_relational_module_graph(
    prepared: Path,
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    trusted_base: dict[str, Any],
) -> dict[str, Any]:
    stage_a = prepared / "lean" / "StageA"
    sources = {path.stem: path for path in stage_a.glob("*.lean")}
    if (prepared / "checked-region-artifacts.json").is_file():
        _validate_checked_artifact_source_boundaries(sources)
    acceptance_path = prepared / "whole-program-acceptance.json"
    acceptance = _read_json(acceptance_path) if acceptance_path.is_file() else {
        "format": "stage-a-whole-program-acceptance-v1",
        "status": "incomplete",
        "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
        "theorem": None,
        "profile": None,
        "blockers": [{
            "code": "whole_program_certificate_missing",
            "message": "no whole-program acceptance analysis was generated",
            "next_action": "regenerate the relational proof graph",
        }],
    }
    if acceptance.get("format") != "stage-a-whole-program-acceptance-v1":
        raise StageAInputError("prepared proof has an invalid whole-program acceptance artifact")
    acceptance_ready = acceptance.get("status") == "ready"
    try:
        selected_acceptance_theorem = selected_relational_acceptance_theorem(
            acceptance
        )
    except SchemaError as exc:
        raise StageAInputError(str(exc)) from exc
    root = "RelationalAcceptance" if acceptance_ready else "RelationalBundle"
    if root not in sources:
        raise StageAInputError(f"prepared proof is missing StageA.{root}")

    imports = {
        module: _LEAN_IMPORT_PATTERN.findall(path.read_text(encoding="utf-8"))
        for module, path in sources.items()
    }
    reachable: set[str] = set()
    visiting: set[str] = set()

    def visit(module: str) -> None:
        if module in reachable:
            return
        if module in visiting:
            raise StageAInputError(f"generated Lean module graph contains a cycle at {module}")
        path = sources.get(module)
        if path is None:
            raise StageAInputError(f"generated Lean import StageA.{module} has no source")
        visiting.add(module)
        for dependency in imports[module]:
            visit(dependency)
        visiting.remove(module)
        reachable.add(module)

    visit(root)
    auxiliary_modules: list[str] = []
    if "RelationalLaunchRealizabilityCertificate" in sources:
        visit("RelationalLaunchRealizabilityCertificate")
        auxiliary_modules.append("RelationalLaunchRealizabilityCertificate")
    if "RelationalAffineLinkedControl" in sources:
        visit("RelationalAffineLinkedControl")
        auxiliary_modules.append("RelationalAffineLinkedControl")
    if "RelationalAffineLinkedControlBindings" in sources:
        visit("RelationalAffineLinkedControlBindings")
        auxiliary_modules.append("RelationalAffineLinkedControlBindings")
    if "RelationalAffineLinkedCallBindings" in sources:
        visit("RelationalAffineLinkedCallBindings")
        auxiliary_modules.append("RelationalAffineLinkedCallBindings")
    if "RelationalAffineLinkedExternalCallBindings" in sources:
        visit("RelationalAffineLinkedExternalCallBindings")
        auxiliary_modules.append("RelationalAffineLinkedExternalCallBindings")
    if "RelationalAffineLinkedMemoryBindings" in sources:
        visit("RelationalAffineLinkedMemoryBindings")
        auxiliary_modules.append("RelationalAffineLinkedMemoryBindings")
    logical_modules = {
        module: {
            "source": f"lean/StageA/{module}.lean",
            "source_sha256": sha256_file(sources[module]),
            "imports": imports[module],
            "source_bytes": sources[module].stat().st_size,
        }
        for module in sorted(reachable)
    }
    artifact_manifest = None
    if (prepared / "checked-region-artifacts.json").is_file():
        try:
            artifact_manifest = write_checked_artifact_manifest(
                destination=prepared / "artifact-manifest.json",
                model=STAGE_A_RELATIONAL_MODEL_ID,
                original_sha256=original_bin.sha256,
                candidate_sha256=candidate_bin.sha256,
                root_module=root,
                expected_final_theorem=selected_acceptance_theorem,
                module_sources={
                    module: sources[module] for module in sorted(reachable)
                },
                # The checked-artifact graph remains a parity path until its
                # theorem and frontier audit matches the existing acceptance root.
                authoritative=False,
            )
        except SchemaError as exc:
            raise StageAInputError(
                f"cannot construct checked artifact manifest: {exc}"
            ) from exc
    artifact_ids_by_module: dict[str, list[str]] = {
        module: [] for module in reachable
    }
    if artifact_manifest is not None:
        for artifact in artifact_manifest.artifacts:
            for module in artifact.modules:
                if module in artifact_ids_by_module:
                    artifact_ids_by_module[module].append(
                        artifact.identity.artifact_id
                    )
    legacy_full_image_replay_modules = (
        set()
        if artifact_manifest is None
        else {
            module
            for artifact in artifact_manifest.artifacts
            if artifact.metadata.get("legacy_full_image_replay") is True
            for module in artifact.modules
        }
    )

    raw_nodes = _relational_raw_build_nodes(reachable)

    module_node = {
        module: node["id"]
        for node in raw_nodes
        for module in node["modules"]
    }
    if len(module_node) != len(reachable):
        raise StageAInputError("generated build packs do not assign every Lean module exactly once")

    def resource_class(modules: list[str]) -> tuple[str, int]:
        names = " ".join(modules)
        source_bytes = sum(logical_modules[module]["source_bytes"] for module in modules)
        if "RelationalLaunchRealizabilityCertificate" in modules:
            # This compact certificate reduces all checked launch-frame leaves.
            # GNU hello measured an 8.0 GiB peak despite a small source file, so
            # source size is not a useful estimator for this module.
            return "high-memory", max(10240, source_bytes // 1024 * 3)
        if any(
            module.startswith("RelationalLaunch") and "Leaf" in module
            for module in modules
        ):
            # Launch realization is partitioned into independent finite-range
            # leaves.  Each still reduces image or paired-stack memory, so keep
            # intra-process parallelism at one while allowing Nix to schedule
            # the bounded leaves independently across builders.
            return "high-memory", max(4096, source_bytes // 1024 * 3)
        if any(
            module.startswith("RelationalAffineLinkedControl")
            or module.startswith("RelationalAffineLinkedMemory")
            for module in modules
        ):
            return "high-memory", max(6144, source_bytes // 1024 * 3)
        if any(
            module in (
                "RelationalProofOriginalCoverageData",
                "RelationalProofCandidateCoverageData",
            )
            for module in modules
        ):
            return "high-memory", max(12288, source_bytes // 1024 * 3)
        if any(
            module.startswith("RelationalProofStaticUsageLeaf")
            or module in (
                "RelationalProofStaticUsageCertificate",
                "RelationalProofClosureData",
            )
            for module in modules
        ):
            return "high-memory", max(6144, source_bytes // 1024 * 3)
        if any(
            module.startswith("RelationalProofRegionIndexChunk")
            or module.startswith("RelationalProofStaticUsageChunk")
            or module in (
                "RelationalProofRegionIndexData",
                "RelationalProofRegionInventoryData",
                "RelationalProofPaddingData",
                "RelationalProofRequiredInputsData",
            )
            for module in modules
        ):
            return "medium", max(2048, source_bytes // 1024 * 2)
        if "RelationalStaticContext" in modules:
            return "high-memory", max(4096, source_bytes // 1024 * 3)
        if any(module.startswith("RelationalStaticCodeMapChunk") for module in modules):
            # The generated source is small, but reducing indexed lookups through a
            # jq-sized imported map dominates the Lean process's resident set. Full
            # jq measurements peak near 9 GiB per module, independent of source size.
            return "high-memory", max(
                10240, source_bytes // 1024 * 3
            )
        if any(
            module.startswith(prefix)
            for module in modules
            for prefix in (
                "RelationalAcceptanceRegionChunk",
                "RelationalAcceptanceChunk",
                "RelationalProductGraphChunk",
                "RelationalDynamicRangeIndirectCallChunk",
                "RelationalDynamicCallFanout",
                "RelationalProductDecodedControlChunk",
                "RelationalProductReachabilityChunk",
                "RelationalProductEdgeRefinementChunk",
                "RelationalProductNodeCoverageChunk",
                "RelationalReachableProduct",
            )
        ):
            # Each checker reduces indexed lookups through the full imported jq
            # graph. Six GiB is conservative for the bounded 16-entry chunks.
            return "high-memory", max(6144, source_bytes // 1024 * 3)
        if re.search(
            r"RelationalProof(?:Original|Candidate)Semantic"
            r"(?:Chunk[0-9]+|Pack[0-9a-f]+)",
            names,
        ):
            # These leaves evaluate compact local bytes and no longer import a
            # whole PE or shared definition inventory.
            return "medium", max(2048, source_bytes // 1024 * 2)
        if "DecodeChunk" in names:
            if any(
                module in legacy_full_image_replay_modules
                for module in modules
            ):
                return "high-memory", max(4096, source_bytes // 1024 * 3)
            # Ordinary decode chunks only bind an already-checked local
            # semantic artifact to exact PE bytes. A representative measured
            # 1.12 GiB peak and 1.84 seconds, so these should use the wide
            # medium lane instead of serializing with legacy full-PE replay.
            return "medium", max(2048, source_bytes // 1024 * 2)
        if any(
            re.fullmatch(
                r"RelationalProof(?:Original|Candidate)ImagePack[0-9]+",
                module,
            )
            for module in modules
        ):
            # Exact image payloads are intentionally bounded so a changed PE
            # rebuilds several independent byte leaves instead of one
            # multi-gigabyte elaboration.
            return "medium", max(2048, source_bytes // 1024 * 3)
        if any(
            module in {"RelationalProofOriginal", "RelationalProofCandidate"}
            for module in modules
        ):
            # Compatibility facades only re-export the three independent
            # image-attestation phases.
            return "light", max(512, source_bytes // 1024 + 256)
        if any(
            re.fullmatch(
                r"RelationalProof(?:Original|Candidate)Image",
                module,
            )
            for module in modules
        ):
            return "medium", max(3072, source_bytes // 1024 * 3)
        if any(
            re.fullmatch(
                r"RelationalProof(?:Original|Candidate)"
                r"(?:Imports|Relocations)Attestation",
                module,
            )
            for module in modules
        ):
            return "high-memory", max(8192, source_bytes // 1024 * 3)
        if (
            "InstructionAdequacyChunk" in names
            or "RelationalInstructionAdequacyCertificate" in modules
            or "StructuralPadding" in names
            or "StructuralCoverage" in names
        ):
            return "high-memory", max(4096, source_bytes // 1024 * 3)
        if "RelationalProofOriginal" in names or "RelationalProofCandidate" in names:
            return "high-memory", max(16384, source_bytes // 1024 * 3)
        if "DirectChunk" in names or any(
            module.startswith("RelationalProofShard") for module in modules
        ):
            return "medium", max(1536, source_bytes // 1024 * 2)
        if source_bytes >= 512 * 1024:
            return "medium", max(1536, source_bytes // 1024 * 2)
        return "light", max(512, source_bytes // 1024 + 256)

    nodes: list[dict[str, Any]] = []
    for raw in raw_nodes:
        packed_modules = set(raw["modules"])
        internal_dependencies = sorted({
            (module, dependency)
            for module in raw["modules"]
            for dependency in logical_modules[module]["imports"]
            if dependency in packed_modules
        })
        if internal_dependencies:
            raise StageAInputError(
                f"generated build pack {raw['id']} contains internal imports "
                f"{internal_dependencies!r}"
            )
        dependencies = sorted({
            module_node[dependency]
            for module in raw["modules"]
            for dependency in logical_modules[module]["imports"]
            if module_node[dependency] != raw["id"]
        })
        classification, estimated_memory_mb = resource_class(raw["modules"])
        node = {
            "id": raw["id"],
            "modules": raw["modules"],
            "dependencies": dependencies,
            "resource_class": classification,
            "estimated_memory_mb": estimated_memory_mb,
            "source_sha256": sha256_bytes("".join(
                logical_modules[module]["source_sha256"] for module in raw["modules"]
            ).encode("ascii")),
        }
        if artifact_manifest is not None:
            node.update({
                "kind": (
                    "checked-region-semantics"
                    if any(
                        re.fullmatch(
                            r"RelationalProof(?:Original|Candidate)Semantic"
                            r"(?:Chunk[0-9]+|Pack[0-9a-f]+)",
                            module,
                        )
                        for module in raw["modules"]
                    )
                    else "exact-image-binding"
                    if any(
                        "DecodeChunk" in module for module in raw["modules"]
                    )
                    else "exact-image-chunk"
                    if any(
                        re.fullmatch(
                            r"RelationalProof(?:Original|Candidate)"
                            r"ImagePack[0-9]+",
                            module,
                        )
                        for module in raw["modules"]
                    )
                    else "exact-image-attestation"
                    if any(
                        re.fullmatch(
                            r"RelationalProof(?:Original|Candidate)Image",
                            module,
                        )
                        for module in raw["modules"]
                    )
                    else "exact-import-attestation"
                    if any(
                        re.fullmatch(
                            r"RelationalProof(?:Original|Candidate)"
                            r"ImportsAttestation",
                            module,
                        )
                        for module in raw["modules"]
                    )
                    else "exact-relocation-attestation"
                    if any(
                        re.fullmatch(
                            r"RelationalProof(?:Original|Candidate)"
                            r"RelocationsAttestation",
                            module,
                        )
                        for module in raw["modules"]
                    )
                    else "checked-segment-refinement"
                    if any(
                        "SegmentRefinement" in module
                        for module in raw["modules"]
                    )
                    else "checked-product-graph"
                    if any(
                        "ProductGraph" in module for module in raw["modules"]
                    )
                    else "whole-program-acceptance"
                    if root in raw["modules"]
                    else "lean-module-pack"
                ),
                "stable_key": raw["id"],
                "artifact_ids": sorted({
                    artifact_id
                    for module in raw["modules"]
                    for artifact_id in artifact_ids_by_module[module]
                }),
                "checker_version": CHECKED_ARTIFACT_CHECKER_VERSION,
            })
        nodes.append(node)
    _attach_relational_semantic_identities(nodes)

    lean_version = None
    lean_githash = None
    lean = shutil.which("lean")
    if lean is not None:
        lean_version = subprocess.run(
            [lean, "--version"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        ).stdout.strip()
        lean_githash = subprocess.run(
            [lean, "--githash"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        ).stdout.strip()
    graph = {
        "format": (
            LEAN_MODULE_GRAPH_V2_FORMAT
            if artifact_manifest is not None
            else "stage-a-lean-module-graph-v1"
        ),
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "root_module": root,
        "auxiliary_modules": auxiliary_modules,
        "final_node": module_node[root],
        "expected_final_theorem": selected_acceptance_theorem,
        "acceptance": acceptance,
        "approved_axioms": trusted_base["approved_axioms"],
        "lean": {"version": lean_version, "githash": lean_githash, "trust": 0},
        "artifacts": {
            "original": {"path": "artifacts/original.pe", "sha256": original_bin.sha256},
            "candidate": {"path": "artifacts/candidate.pe", "sha256": candidate_bin.sha256},
            **({} if artifact_manifest is None else {"checked_manifest": {
                "path": "artifact-manifest.json",
                "sha256": sha256_file(prepared / "artifact-manifest.json"),
                "authoritative": artifact_manifest.authoritative,
            }}),
        },
        "modules": logical_modules,
        "nodes": sorted(nodes, key=lambda node: node["id"]),
        "counts": {
            "logical_modules": len(logical_modules),
            "derivations": len(nodes),
            "definition_modules": len(_numbered_relational_modules(
                logical_modules, "RelationalDefinitionsShard"
            )),
            "local_proof_modules": len(_numbered_relational_modules(
                logical_modules, "RelationalProofShard"
            )),
            "decode_modules": sum("DecodeChunk" in module for module in logical_modules),
            "semantic_modules": sum(
                re.fullmatch(
                    r"RelationalProof(?:Original|Candidate)Semantic"
                    r"(?:Chunk[0-9]+|Pack[0-9a-f]+)",
                    module,
                )
                is not None
                for module in logical_modules
            ),
            "image_chunk_modules": sum(
                re.fullmatch(
                    r"RelationalProof(?:Original|Candidate)ImagePack[0-9]+",
                    module,
                )
                is not None
                for module in logical_modules
            ),
            "image_attestation_modules": sum(
                re.fullmatch(
                    r"RelationalProof(?:Original|Candidate)"
                    r"(?:Image|ImportsAttestation|RelocationsAttestation)",
                    module,
                )
                is not None
                for module in logical_modules
            ),
            "instruction_adequacy_modules": sum(
                "InstructionAdequacy" in module for module in logical_modules
            ),
            "direct_modules": sum("DirectChunk" in module for module in logical_modules),
            "structural_modules": sum(module.startswith("RelationalProofStructural") for module in logical_modules),
        },
    }
    write_json(prepared / "module-graph.json", graph)
    _validate_relational_module_graph(prepared, graph)
    return graph


def _validate_relational_module_graph(
    prepared: Path,
    graph: dict[str, Any] | None = None,
    *,
    require_sources: bool = True,
) -> dict[str, Any]:
    prepared = Path(prepared)
    graph = graph or _read_json(prepared / "module-graph.json")
    try:
        typed_graph = ModuleGraph.parse(graph)
    except SchemaError as exc:
        raise StageAInputError(f"malformed prepared Lean module graph: {exc}") from exc
    if graph.get("format") not in LEAN_MODULE_GRAPH_FORMATS:
        raise StageAInputError("unsupported prepared Lean module graph format")
    if typed_graph.root_module != graph.get("root_module"):
        raise StageAInputError("prepared Lean module graph has an invalid root module")
    modules = graph.get("modules")
    nodes = graph.get("nodes")
    if not isinstance(modules, dict) or not modules or not isinstance(nodes, list) or not nodes:
        raise StageAInputError("prepared Lean module graph is empty or malformed")
    assigned: dict[str, str] = {}
    node_by_id: dict[str, dict[str, Any]] = {}
    for module, metadata in modules.items():
        if not re.fullmatch(r"[A-Za-z0-9_]+", module) or not isinstance(metadata, dict):
            raise StageAInputError(f"invalid generated Lean module name {module!r}")
        relative = metadata.get("source")
        if relative != f"lean/StageA/{module}.lean":
            raise StageAInputError(f"module {module} has a noncanonical source path")
        source_sha256 = metadata.get("source_sha256")
        declared_imports = metadata.get("imports")
        if (
            not isinstance(source_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None
            or not isinstance(declared_imports, list)
            or any(not isinstance(dependency, str) for dependency in declared_imports)
        ):
            raise StageAInputError(
                f"module {module} has malformed source provenance"
            )
        if require_sources:
            source = prepared / relative
            if not source.is_file() or sha256_file(source) != source_sha256:
                raise StageAInputError(f"module {module} source hash does not match")
            observed_imports = _LEAN_IMPORT_PATTERN.findall(
                source.read_text(encoding="utf-8")
            )
            if observed_imports != declared_imports:
                raise StageAInputError(
                    f"module {module} import inventory does not match source"
                )
        else:
            observed_imports = declared_imports
        if any(dependency not in modules for dependency in observed_imports):
            raise StageAInputError(f"module {module} imports an undeclared StageA module")
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise StageAInputError("malformed Lean graph node")
        node_id = node["id"]
        if node_id in node_by_id:
            raise StageAInputError(f"duplicate Lean graph node {node_id}")
        node_by_id[node_id] = node
        for module in node.get("modules", []):
            if module not in modules or module in assigned:
                raise StageAInputError(f"module {module} has an invalid or duplicate build assignment")
            assigned[module] = node_id
    if set(assigned) != set(modules):
        raise StageAInputError("not every Lean module is assigned to a build node")
    if graph.get("format") == LEAN_MODULE_GRAPH_V2_FORMAT:
        manifest_path = prepared / "artifact-manifest.json"
        try:
            manifest_payload = _read_json(manifest_path)
            artifact_manifest = CheckedArtifactManifest.parse(manifest_payload)
        except (StageAInputError, SchemaError) as exc:
            raise StageAInputError(
                f"prepared checked artifact manifest is invalid: {exc}"
            ) from exc
        checked_manifest = graph.get("artifacts", {}).get("checked_manifest")
        if (
            not isinstance(checked_manifest, dict)
            or checked_manifest.get("path") != "artifact-manifest.json"
            or checked_manifest.get("sha256") != sha256_file(manifest_path)
            or checked_manifest.get("authoritative")
                is not artifact_manifest.authoritative
        ):
            raise StageAInputError(
                "prepared graph does not exactly bind its checked artifact manifest"
            )
        declared_artifact_ids = {
            artifact.identity.artifact_id
            for artifact in artifact_manifest.artifacts
        }
        for node in typed_graph.nodes:
            if node.checker_version != CHECKED_ARTIFACT_CHECKER_VERSION:
                raise StageAInputError(
                    f"prepared graph node {node.id} has a stale checker version"
                )
            unknown = set(node.artifact_ids) - declared_artifact_ids
            if unknown:
                raise StageAInputError(
                    f"prepared graph node {node.id} names unknown checked artifacts"
                )
    for node_id, node in node_by_id.items():
        module_positions = {module: index for index, module in enumerate(node["modules"])}
        for module in node["modules"]:
            for dependency in modules[module]["imports"]:
                if assigned[dependency] == node_id and module_positions[dependency] >= module_positions[module]:
                    raise StageAInputError(
                        f"node {node_id} does not order internal import {dependency} before {module}"
                    )
        expected = sorted({
            assigned[dependency]
            for module in node["modules"]
            for dependency in modules[module]["imports"]
            if assigned[dependency] != node_id
        })
        if node.get("dependencies") != expected:
            raise StageAInputError(f"node {node_id} dependency inventory does not match imports")
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit_node(node_id: str) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            raise StageAInputError(f"Lean build graph contains a cycle at {node_id}")
        if node_id not in node_by_id:
            raise StageAInputError(f"Lean build graph references missing node {node_id}")
        visiting.add(node_id)
        for dependency in node_by_id[node_id]["dependencies"]:
            visit_node(dependency)
        visiting.remove(node_id)
        visited.add(node_id)
    visit_node(str(graph.get("final_node")))
    auxiliary_modules = graph.get("auxiliary_modules", [])
    if not isinstance(auxiliary_modules, list) or any(
        not isinstance(module, str) or module not in assigned
        for module in auxiliary_modules
    ):
        raise StageAInputError("Lean graph has an invalid auxiliary module inventory")
    if len(auxiliary_modules) != len(set(auxiliary_modules)):
        raise StageAInputError("Lean graph has duplicate auxiliary modules")
    for module in auxiliary_modules:
        visit_node(assigned[module])
    if visited != set(node_by_id):
        raise StageAInputError(
            "Lean graph contains nodes outside the final or auxiliary theorem closures"
        )
    acceptance = graph.get("acceptance")
    if not isinstance(acceptance, dict):
        raise StageAInputError("prepared Lean graph omits its acceptance state")
    acceptance_status = acceptance.get("status")
    theorem = graph.get("expected_final_theorem")
    try:
        selected_theorem = selected_relational_acceptance_theorem(acceptance)
    except SchemaError as exc:
        raise StageAInputError(str(exc)) from exc
    if acceptance_status == "ready":
        if theorem != selected_theorem:
            raise StageAInputError(
                "acceptance-ready Lean graph does not name the closed whole-program theorem"
            )
    elif acceptance_status == "incomplete":
        if theorem is not None or acceptance.get("theorem") is not None:
            raise StageAInputError(
                "incomplete Lean graph must not advertise an acceptance theorem"
            )
        blockers = acceptance.get("blockers")
        if not isinstance(blockers, list) or not blockers:
            raise StageAInputError("incomplete Lean graph omits acceptance blockers")
    else:
        raise StageAInputError("prepared Lean graph has an invalid acceptance state")
    approved_axioms = graph.get("approved_axioms")
    if not isinstance(approved_axioms, list) or not all(
        isinstance(axiom, str) and re.fullmatch(r"[A-Za-z0-9_.]+", axiom)
        for axiom in approved_axioms
    ):
        raise StageAInputError("prepared Lean graph has an invalid approved-axiom inventory")
    return graph


def _validate_prepared_relational(
    prepared: Path, *, require_sources: bool = True
) -> dict[str, Any]:
    manifest = _read_json(prepared / "prepared-proof.json")
    try:
        PreparedProofDigests.parse(manifest)
    except SchemaError as exc:
        raise StageAInputError(f"malformed prepared relational proof: {exc}") from exc
    if manifest.get("format") not in {
        "stage-a-prepared-relational-v1",
        "stage-a-prepared-relational-v2",
    }:
        raise StageAInputError("unsupported prepared relational proof format")
    if manifest.get("status") != "prepared":
        raise StageAInputError("relational proof preparation did not complete")
    validate_relational_analysis(prepared)
    try:
        StageAInterfaceManifest.parse(
            _read_json(prepared / "stage-a-interface-manifest.json")
        )
    except SchemaError as exc:
        raise StageAInputError(f"malformed Stage A interface manifest: {exc}") from exc
    graph = _validate_relational_module_graph(
        prepared, require_sources=require_sources
    )
    expected_hashes = {
        "analysis_manifest_sha256": (
            prepared / "relational-analysis-manifest.json"
        ),
        "interface_manifest_sha256": prepared / "stage-a-interface-manifest.json",
        "relation_contract_sha256": prepared / "relation-contract.json",
        "proof_ir_sha256": prepared / "relational-proof-ir.json",
        "semantic_ir_sha256": prepared / "relational-semantic-ir.json",
        "memory_contracts_sha256": prepared / "relational-memory-contracts.json",
        "static_word_relations_sha256": (
            prepared / "relational-static-word-relations.json"
        ),
        "register_relations_sha256": prepared / "relational-register-relations.json",
        "runtime_frame_affine_sha256": (
            prepared / "relational-runtime-frame-affine-viability.json"
        ),
        "stack_windows_sha256": prepared / "relational-stack-windows.json",
        "segment_diagnostics_sha256": (
            prepared / "relational-segment-diagnostics.json"
        ),
        "product_graph_sha256": prepared / "relational-product-graph.json",
        "isa_requirements_sha256": prepared / "isa-requirements.json",
        "invariants_sha256": prepared / "relational-invariants.json",
        "whole_program_acceptance_sha256": (
            prepared / "whole-program-acceptance.json"
        ),
        "composition_progress_sha256": prepared / "composition-progress.json",
        "module_graph_sha256": prepared / "module-graph.json",
    }
    if graph.get("format") == LEAN_MODULE_GRAPH_V2_FORMAT:
        if manifest.get("format") != "stage-a-prepared-relational-v2":
            raise StageAInputError(
                "checked-artifact graph requires a v2 prepared proof manifest"
            )
        expected_hashes["artifact_manifest_sha256"] = (
            prepared / "artifact-manifest.json"
        )
    for field, path in expected_hashes.items():
        if not path.is_file() or manifest.get(field) != sha256_file(path):
            raise StageAInputError(f"prepared relational proof hash mismatch for {path.name}")
    if manifest.get("expected_final_theorem") != graph.get("expected_final_theorem"):
        raise StageAInputError("prepared relational theorem inventory does not match its graph")
    if manifest.get("acceptance") != graph.get("acceptance"):
        raise StageAInputError("prepared relational acceptance state does not match its graph")
    composition_progress = _read_json(prepared / "composition-progress.json")
    if (
        composition_progress.get("format") != "stage-a-composition-progress-v1"
        or composition_progress.get("trust", {}).get("acceptance_authority") is not False
    ):
        raise StageAInputError("prepared relational composition progress is malformed")
    if manifest.get("composition_progress") != composition_progress:
        raise StageAInputError(
            "prepared relational composition progress does not match its manifest"
        )
    if manifest.get("approved_axioms") != graph.get("approved_axioms"):
        raise StageAInputError("prepared relational axiom inventory does not match its graph")
    if manifest.get("original_sha256") != graph["artifacts"]["original"]["sha256"]:
        raise StageAInputError("prepared original artifact inventory does not match its graph")
    if manifest.get("candidate_sha256") != graph["artifacts"]["candidate"]["sha256"]:
        raise StageAInputError("prepared candidate artifact inventory does not match its graph")
    for artifact in graph["artifacts"].values():
        path = prepared / artifact["path"]
        if not path.is_file() or sha256_file(path) != artifact["sha256"]:
            raise StageAInputError(f"prepared artifact hash mismatch for {artifact['path']}")
    if require_sources and any(prepared.rglob("*.olean")):
        raise StageAInputError("prepared relational proof must not contain prebuilt Lean objects")
    return graph


def _relational_nix_evaluator() -> Path:
    candidates = [
        Path(__file__).resolve().parents[3] / "nix" / "stage-a-lean-graph.nix",
        Path(__file__).with_name("nix") / "stage-a-lean-graph.nix",
        *(
            parent / "share" / "spaghetti-extractor" / "nix" / "stage-a-lean-graph.nix"
            for parent in Path(__file__).resolve().parents
        ),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise StageAInputError("cannot locate nix/stage-a-lean-graph.nix")


def _find_relational_flake_root(explicit: Path | None) -> Path:
    if explicit is not None:
        root = Path(explicit).resolve()
        if not (root / "flake.nix").is_file() or not (root / "flake.lock").is_file():
            raise StageAInputError(f"{root} is not a locked Nix flake")
        return root
    starts = [Path.cwd().resolve(), Path(__file__).resolve()]
    for start in starts:
        for parent in (start, *start.parents):
            if (parent / "flake.nix").is_file() and (parent / "flake.lock").is_file():
                return parent
    raise StageAInputError("cannot locate the project flake; pass --flake")


def _locked_flake_input(lock_path: Path, input_name: str) -> dict[str, Any]:
    lock = _read_json(lock_path)
    nodes = lock.get("nodes")
    root_name = lock.get("root")
    if not isinstance(nodes, dict) or root_name not in nodes:
        raise StageAInputError(f"{lock_path} has no valid flake-lock node graph")
    root_inputs = nodes[root_name].get("inputs", {})
    node_name = root_inputs.get(input_name) if isinstance(root_inputs, dict) else None
    if not isinstance(node_name, str) or node_name not in nodes:
        raise StageAInputError(f"{lock_path} does not lock the {input_name} input directly")
    locked = nodes[node_name].get("locked")
    if not isinstance(locked, dict):
        raise StageAInputError(f"{lock_path} has no locked source for {input_name}")
    required = {"type", "narHash"}
    if not required.issubset(locked) or not all(
        isinstance(key, str) and isinstance(value, (str, int, bool))
        for key, value in locked.items()
    ):
        raise StageAInputError(f"{lock_path} contains an unsupported lock record for {input_name}")
    return locked
