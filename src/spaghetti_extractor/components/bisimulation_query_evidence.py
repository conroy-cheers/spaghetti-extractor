"""Retain and reuse exact CBMC process evidence, without activation authority.

Current generation and compilation still run. Only an identical compiled model,
checker and query can consume retained output, through the current CBMC parser.
"""

import hashlib
import json
import shutil
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_support import BisimulationRefinementError
from .bisimulation_assurance import checked_runtime_assurance
from .cbmc_backend import run_cbmc_process, validate_smt_solver_binding

POLICY = "exact-compiled-cbmc-query-evidence-v1"


def _output_digests(value):
    if isinstance(value, dict):
        return {v for k, v in value.items() if k.endswith("output_sha256") and isinstance(v, str)} | set().union(
            *(_output_digests(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(_output_digests(v) for v in value))
    return set()


def _previous_conditional_queries(root, runtime_assurance):
    from .conditional_check_result import checked_conditional_packet

    if runtime_assurance is None:
        raise ValueError("conditional query evidence requires explicit runtime contracts")
    if (root / "contextual-refinement-result.json").exists():
        raise ValueError("previous evidence mixes conditional and ordinary proof packets")
    packet = json.loads((root / "conditional-engine-result.json").read_text())
    result, assurance = checked_conditional_packet(packet, packet["inputs"]["component_id"])
    # A valid old selection is not a compatible new contract. Regenerate and
    # execute queries normally rather than borrowing its conditional outputs.
    if assurance != checked_runtime_assurance(runtime_assurance):
        return {}
    models = result["bindings"].get("operation_models")
    if not isinstance(models, list) or not models or not isinstance(result.get("checker"), dict):
        raise ValueError("conditional evidence lacks its model and checker inventory")
    checks = {(row["operation_id"], row["obligation_id"]): row for row in result["checks"]}
    if len(checks) != len(result["checks"]):
        raise ValueError("conditional evidence repeats an obligation")
    previous, seen = {}, set()
    for oi, operation in enumerate(models):
        if (not isinstance(operation, dict) or not isinstance(operation.get("obligation_models"), list)
                or operation.get("assurance") != assurance or operation.get("authorizing") is not False):
            raise ValueError("conditional operation has mixed assurance")
        for mi, model in enumerate(operation["obligation_models"]):
            if not isinstance(model, dict):
                raise ValueError("conditional obligation model is malformed")
            identity = (operation["operation_id"], model["obligation_id"])
            if identity in seen or identity not in checks:
                raise ValueError("conditional model obligation inventory differs")
            seen.add(identity)
            check = checks[identity]
            if (model.get("assurance") != assurance or model.get("authorizing") is not False
                    or any(model[field] != check[field] for field in ("goto_model_sha256", "proof_model_sha256"))):
                raise ValueError("conditional query model binding differs")
            if check.get('code') == 'conditional_region_deferred':
                if any(model.get(field) is not None for field in (
                        'goto_model_sha256', 'nonvacuity_goto_model_sha256', 'execution_binding_sha256')):
                    raise ValueError('deferred conditional model claims compiled evidence')
                continue
            previous[identity] = {
                "directory": root / "proof-diagnostics" / f"operation-{oi:04d}-obligation-{mi:04d}" / "query-evidence",
                "outputs": _output_digests(check), "goto_model_sha256": model["goto_model_sha256"],
                "checker": result["checker"], "assurance": assurance,
                "proof_receipt_sha256": result["receipt_sha256"],
                # Legacy incomplete packets can retain property process files
                # while publishing only coverage evidence. Do not offer those
                # unpublished files to the exact cache reader.
                "coverage_only": 'partitioned_evidence' not in check.get('property_result', check),
            }
            entry = check.get("source_entry_model", {})
            if "entry_check" in entry:
                previous[identity]["source_entry"] = {
                    "directory": root / "proof-diagnostics" / f"operation-{oi:04d}-obligation-{mi:04d}" / "source-entry" / "query-evidence",
                    "outputs": _output_digests(entry["entry_check"]),
                    "goto_model_sha256": entry["goto_model_sha256"],
                    "checker": result["checker"], "assurance": assurance,
                    "proof_receipt_sha256": result["receipt_sha256"],
                    "coverage_only": 'partitioned_evidence' not in entry['entry_check']['property_result'],
                }
    if seen != set(checks):
        raise ValueError("conditional model does not cover its query results")
    return previous


def previous_proof_queries(root, *, runtime_assurance=None):
    """Reuse completed processes from a validated satisfied or incomplete proof.

    An incomplete receipt supplies no theorem or activation authority. Each hit
    still requires identical compiled bytes, tools and arguments, retained output
    bound by that receipt, and the current result parser. Timed-out or missing
    processes have no complete cache entry and must run again.
    """
    if root is None:
        return {}
    from .contextual_bisimulation import validate_contextual_refinement_v2

    root = Path(root).resolve()
    try:
        if (root / "conditional-engine-result.json").is_file():
            return _previous_conditional_queries(root, runtime_assurance)
        value = json.loads((root / "contextual-refinement-result.json").read_text())
        proof = value["proof"]
        validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
        if proof["status"] not in {"satisfied", "incomplete"}:
            raise ValueError("previous local proof is neither satisfied nor incomplete")
        diagnostics = "proof-diagnostics" if "qualification_input" in value else "diagnostics"
        shards = {(s["operation_id"], s["obligation_id"]): s for s in proof["shards"]}
        return {(operation["operation_id"], model["obligation_id"]): {
                    "directory": root / diagnostics / f"operation-{oi:04d}-obligation-{mi:04d}" / "query-evidence",
                    "outputs": _output_digests(shards[(operation["operation_id"], model["obligation_id"])]),
                    "goto_model_sha256": model["goto_model_sha256"], "checker": proof["checker"],
                    # A nonvacuity failure can replace the property result in
                    # ordinary incomplete receipts. Files from those unpublished
                    # property processes are not evidence; rerun them instead.
                    "coverage_only": 'partitioned_evidence' not in shards[
                        (operation["operation_id"], model["obligation_id"])],
                    "proof_receipt_sha256": proof["receipt_sha256"]}
                for oi, operation in enumerate(proof["models"]["operation_models"])
                for mi, model in enumerate(operation["obligation_models"])
                if model['goto_model_sha256'] is not None}
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise BisimulationRefinementError("previous query proof: " + str(error)) from error


@contextmanager
def proof_workspace(path=None):
    """Own fresh staging; retain an explicitly located workspace on exceptions.

    Normal completion copies diagnostics before releasing staging. An exception
    can bypass that copy, so preserve the requested path and its exact inputs and
    query outputs for inspection. Retention confers no proof or reuse authority.
    Existing paths are still rejected, including a previous interrupted run.
    """
    if path is None:
        with tempfile.TemporaryDirectory(prefix="component-bisimulation-") as root:
            yield Path(root)
        return
    root = Path(path).resolve()
    root.parent.mkdir(parents=True, exist_ok=True)
    try:
        root.mkdir()
    except FileExistsError as error:
        raise BisimulationRefinementError("proof workspace already exists") from error
    completed = False
    try:
        yield root
        completed = True
    finally:
        if completed:
            shutil.rmtree(root)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


class CbmcQueryEvidence:
    def __init__(self, *, model, checker, compiler, output, previous=None, smt_solver=None, assurance=None):
        self.model = Path(model).resolve()
        self.output = Path(output).resolve()
        self.previous = None if previous is None else Path(previous["directory"]).resolve()
        self.previous_binding = previous
        if smt_solver is not None:
            validate_smt_solver_binding(smt_solver)
        self.smt_solver = None if smt_solver is None else dict(smt_solver)
        self.assurance = checked_runtime_assurance(assurance)
        self.allowed_outputs = None if previous is None else frozenset(previous["outputs"])
        self.checker = Path(checker).resolve()
        self.tools = {"checker": str(self.checker), "checker_sha256": _digest(self.checker.read_bytes()),
                      "compiler": str(Path(compiler).resolve()), "compiler_sha256": _digest(Path(compiler).read_bytes())}
        self.lock = threading.Lock()
        self.reused = self.executed = 0

    @staticmethod
    def _read(root, binding, *, allowed_outputs=None):
        if not root.exists():
            return None
        if not root.is_dir() or root.is_symlink():
            raise BisimulationRefinementError("query evidence directory is malformed")
        try:
            paths = [root / name for name in ("query.json", "stdout", "stderr")]
            if any(not path.is_file() or path.is_symlink() for path in paths):
                raise ValueError("query evidence is missing retained bytes")
            record = json.loads(paths[0].read_text())
            stdout, stderr = paths[1].read_bytes(), paths[2].read_bytes()
            if (set(record) != {"binding", "returncode", "stdout_sha256", "stderr_sha256"}
                    or canonical_sha256_v3(record["binding"]) != canonical_sha256_v3(binding)
                    or type(record["returncode"]) is not int
                    or record["returncode"] not in (0, 10)
                    or record["stdout_sha256"] != _digest(stdout) or record["stderr_sha256"] != _digest(stderr)):
                raise ValueError("query evidence binding or retained bytes differ")
            if allowed_outputs is not None and _digest(stdout + b"\0" + stderr) not in allowed_outputs:
                raise ValueError("query output is not bound by the previous local proof")
            return subprocess.CompletedProcess([], record["returncode"], stdout.decode(), stderr.decode())
        except (ValueError, TypeError, KeyError, OSError) as error:
            raise BisimulationRefinementError(f"query evidence {root}: {error}") from error

    def _binding(self, command, cwd=None):
        command = list(command)
        working_directory = Path.cwd() if cwd is None else Path(cwd).resolve()
        if (len(command) < 2 or Path(command[0]).resolve() != self.checker
                or (working_directory / command[1]).resolve().parent != self.model.parent):
            raise BisimulationRefinementError("query evidence requires the current compiled model and checker")
        model = (working_directory / command[1]).resolve()
        tools = dict(self.tools)
        if "--external-smt2-solver" in command:
            if command.count("--external-smt2-solver") != 1:
                raise BisimulationRefinementError("query has ambiguous external SMT solver")
            position = command.index("--external-smt2-solver") + 1
            if position >= len(command):
                raise BisimulationRefinementError("query lacks its external SMT solver")
            solver = Path(command[position])
            if not solver.is_absolute() or not solver.is_file():
                raise BisimulationRefinementError("external SMT solver must name an absolute executable file")
            tools.update(external_smt2_solver=str(solver.resolve()),
                         external_smt2_solver_sha256=_digest(solver.read_bytes()))
            if self.smt_solver is not None and (
                    tools["external_smt2_solver"] != self.smt_solver["executable"]
                    or tools["external_smt2_solver_sha256"] != self.smt_solver["sha256"]):
                raise BisimulationRefinementError("external SMT solver differs from the pinned checker")
        return {"policy": POLICY, "authorizing": False, "tools": tools,
                   "goto_model_sha256": _digest(model.read_bytes()),
                   "arguments": ["$GOTO_MODEL", *command[2:]],
                   **({"assurance": checked_runtime_assurance(self.assurance)} if self.assurance is not None else {}),
                   "cwd": str(working_directory)}

    def _compatible_previous(self, binding):
        return (self.previous_binding is not None
            and self.previous_binding.get("assurance") == self.assurance
            and self.previous_binding["goto_model_sha256"] == binding["goto_model_sha256"]
            and self.previous_binding["checker"]["cbmc_sha256"] == self.tools["checker_sha256"]
            and self.previous_binding["checker"]["goto_cc_sha256"] == self.tools["compiler_sha256"])

    def _previous_result(self, binding):
        if (self.previous_binding is not None and self.previous_binding.get('coverage_only') is True
                and '--cover' not in binding['arguments']):
            return None
        return (self._read(self.previous / canonical_sha256_v3(binding), binding,
                          allowed_outputs=self.allowed_outputs) if self._compatible_previous(binding) else None)

    def property_reuse_probe(self, command):
        """Bind a subdivision search once; execution still binds every query.

        A sparse cache may require inspecting the entire binary tree. Rehashing
        a large model at every node would turn that hint into substantial work.
        Only property selections may change within this probe. It supplies no
        execution result, and run() rechecks current model/tool/output bindings.
        """
        if self.previous_binding is None:
            return None

        def without_properties(arguments):
            result, iterator = [], iter(arguments)
            for argument in iterator:
                if argument == '--property':
                    if next(iterator, None) is None:
                        raise BisimulationRefinementError('query lacks a selected property')
                else:
                    result.append(argument)
            return result

        binding = self._binding(command)
        if not self._compatible_previous(binding):
            return None
        prefix = without_properties(command)

        def probe(selected_command):
            if without_properties(selected_command) != prefix:
                raise BisimulationRefinementError('query subdivision changes more than its properties')
            selected_binding = {**binding, 'arguments': ['$GOTO_MODEL', *selected_command[2:]]}
            with self.lock:
                return self._previous_result(selected_binding) is not None

        return probe

    def can_reuse(self, command):
        """Scheduling hint only: execution must still reparse the exact output.

        A completed counterexample is also reusable. Neither existence nor this
        integrity check classifies the result as a satisfied proof.
        """
        if self.previous_binding is None:
            return False
        with self.lock:
            return self._previous_result(self._binding(command)) is not None

    def run(self, command, *, timeout_seconds, cwd=None):
        command = list(command)
        binding = self._binding(command, cwd)
        key = canonical_sha256_v3(binding)
        destination = self.output / key
        with self.lock:
            retained = self._previous_result(binding)
            reused = retained is not None
            self.reused += int(reused)
            self.executed += int(not reused)
            self.output.mkdir(parents=True, exist_ok=True)
            (self.output / "reuse.json").write_text(json.dumps({"authorizing": False,
                "executed_queries": self.executed, "reused_queries": self.reused,
                "previous_proof_receipt_sha256": None if self.previous_binding is None else self.previous_binding.get("proof_receipt_sha256")},
                sort_keys=True) + "\n")
        if retained is None:
            try:
                retained = run_cbmc_process(command, text=True, capture_output=True, check=False,
                                          timeout=timeout_seconds, **({"cwd": str(cwd)} if cwd is not None else {}))
            except subprocess.TimeoutExpired as error:
                self._retain_failed_attempt(binding, key, error.stdout, error.stderr,
                    termination={"kind": "timeout", "timeout_seconds": timeout_seconds})
                raise
            if retained.returncode not in (0, 10):
                self._retain_failed_attempt(binding, key, retained.stdout, retained.stderr,
                    termination={"kind": "exit", "returncode": retained.returncode,
                                 "timeout_seconds": timeout_seconds})
        with self.lock:
            # Each directory is written as a complete unit. A duplicate query
            # consumes the already retained process, keeping its output binding.
            if retained.returncode in (0, 10):
                existing = self._read(destination, binding)
                if existing is not None:
                    retained = existing
                else:
                    with tempfile.TemporaryDirectory(prefix=".query-", dir=self.output) as temporary:
                        stage = Path(temporary) / "evidence"
                        stage.mkdir()
                        stdout, stderr = retained.stdout.encode(), retained.stderr.encode()
                        (stage / "stdout").write_bytes(stdout)
                        (stage / "stderr").write_bytes(stderr)
                        (stage / "query.json").write_text(json.dumps({"binding": binding,
                            "returncode": retained.returncode, "stdout_sha256": _digest(stdout),
                            "stderr_sha256": _digest(stderr)}, sort_keys=True) + "\n")
                        stage.rename(destination)
        retained.args = command
        return retained

    def _retain_failed_attempt(self, binding, key, stdout, stderr, *, termination):
        """Keep diagnostic bytes without making an exhausted attempt reusable.

        Repeated attempts at the same query remain separate observations. Only
        the existing top-level exact-key entries can enter the reuse reader.
        """
        stdout = stdout.encode() if isinstance(stdout, str) else stdout or b""
        stderr = stderr.encode() if isinstance(stderr, str) else stderr or b""
        with self.lock:
            attempts = self.output / "failed-attempts"
            attempts.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".attempt-", dir=attempts) as temporary:
                stage = Path(temporary) / "evidence"
                stage.mkdir()
                (stage / "stdout").write_bytes(stdout)
                (stage / "stderr").write_bytes(stderr)
                (stage / "attempt.json").write_text(json.dumps({
                    "authorizing": False, "reusable": False, "binding": binding,
                    "termination": termination, "stdout_sha256": _digest(stdout),
                    "stderr_sha256": _digest(stderr)}, sort_keys=True) + "\n")
                stage.rename(attempts / (key + "-" + Path(temporary).name.removeprefix(".attempt-")))
