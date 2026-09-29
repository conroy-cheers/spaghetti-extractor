"""Complete compiled-model partitions and exact read-only replay of retained queries.

The existing contextual engine owns assertion, language-safety and loop coverage.
Replay reparses its exact query outputs with that same engine, with no compiler,
solver, model rendering or write fallback. A missing query cannot become a pass.
"""
from pathlib import Path
from collections import Counter
import subprocess

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_call_evidence import read_json
from .bisimulation_diagnostics import ProofQueryTimings
from .bisimulation_execution import _run_partitioned_properties
from .bisimulation_property_evidence import _validate_partitioned_property_evidence
from .bisimulation_query_evidence import CbmcQueryEvidence
from .cbmc_backend import discover_cbmc_assertions
from ..util import sha256_file


def require(value, message):
    if not value: raise ValueError('compiled partitions: '+message)


def check_partitioned_model(*, model, entry, command, cbmc, evidence, timeout_seconds, subject):
    model = Path(model).resolve()
    arguments = [entry if v == '$PROPERTY_FUNCTION' else v for v in command['discovery_arguments']]
    inventory = discover_cbmc_assertions(command=[str(cbmc), str(model), *arguments],
        timeout_seconds=timeout_seconds, query_evidence=evidence)
    require(inventory['status'] == 'satisfied', 'complete compiled assertion inventory is unavailable')
    descriptions = _unique_descriptions(inventory)
    definition = {'proof_function': entry, 'property_checker_command': command,
        'required_assertion_sites': inventory['assertions'], 'required_assertion_descriptions': descriptions,
        'required_assertion_descriptions_sha256': canonical_sha256_v3(descriptions)}
    timings = ProofQueryTimings(model, subject, query_evidence=evidence)
    result = _run_partitioned_properties(cbmc=cbmc, goto_model=model, command=command,
        proof_function=entry, required_assertion_descriptions=descriptions, timeout_seconds=timeout_seconds,
        timings=timings, uniform_entry=True, required_assertion_sites=inventory['assertions'])
    return result, definition


def _unique_descriptions(inventory):
    # Repeated helper assertions are bound by their complete property-site
    # inventory. Named semantic markers additionally require a unique site.
    counts=Counter(r['description'] for r in inventory['assertions'])
    return sorted(name for name,count in counts.items() if count==1)


class _RetainedQueries:
    """Read only exact tool/model/options matches; never launch a process."""
    previous_binding = True

    def __init__(self, *, model, query_root, tool_hashes, smt_solver=None):
        self.queries = {}; self.binding = None
        model = Path(model).resolve(); model_hash = sha256_file(model)
        for path in sorted(Path(query_root).glob('*/query.json')):
            record = read_json(path); binding = record['binding']; tools = binding['tools']
            require(path.parent.name == canonical_sha256_v3(binding)
                    and binding['goto_model_sha256'] == model_hash, 'retained query model identity differs')
            expected = {'compiler', 'compiler_sha256', 'checker', 'checker_sha256'}
            uses_smt = '--external-smt2-solver' in binding['arguments']
            require(not uses_smt or smt_solver is not None, 'retained query has an unbound SMT solver')
            if uses_smt:
                expected |= {'external_smt2_solver', 'external_smt2_solver_sha256'}
            require(set(tools) == expected and binding.get('assurance') is None,
                    'unexpected retained solver or runtime assurance')
            for actual, logical in [('compiler', 'goto_cc'), ('checker', 'cbmc')]:
                require(sha256_file(Path(tools[actual])) == tools[actual+'_sha256'] == tool_hashes[logical],
                        'retained query tool differs')
            if uses_smt:
                require(tools['external_smt2_solver'] == smt_solver['executable'] and
                        sha256_file(Path(tools['external_smt2_solver'])) ==
                        tools['external_smt2_solver_sha256'] == smt_solver['sha256'], 'retained SMT solver differs')
            current = CbmcQueryEvidence(model=model, checker=Path(tools['checker']), compiler=Path(tools['compiler']),
                output=query_root, smt_solver=smt_solver)
            command = [tools['checker'], str(model), *binding['arguments'][1:]]
            require(current._binding(command, cwd=binding['cwd']) == binding, 'retained command binding differs')
            parsed = current._read(path.parent, binding)
            arguments = tuple(binding['arguments'][1:])
            previous = self.queries.get(arguments)
            require(previous is None or (previous.returncode, previous.stdout, previous.stderr) ==
                    (parsed.returncode, parsed.stdout, parsed.stderr), 'ambiguous retained query')
            self.queries[arguments] = parsed
            self.binding = binding
        require(self.binding is not None, 'retained query inventory is empty')

    def property_reuse_probe(self, command):
        return lambda candidate: tuple(candidate[2:]) in self.queries

    def run(self, command, *, timeout_seconds, cwd=None):
        result = self.queries.get(tuple(command[2:]))
        if result is None:
            # A timed-out parent group may have successful retained children.
            # The existing subdivision policy must cover all of them. If even
            # one required child is absent, the replay remains incomplete.
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        return result


class _ReplayTimings:
    def __init__(self, evidence): self.query_evidence = evidence

    def run(self, kind, function, *, command, **arguments):
        return function(command=command, query_evidence=self.query_evidence, **arguments)


def replay_partitioned_model(*, query, definition, model, query_root, tool_hashes, command):
    model = Path(model).resolve()
    require(definition['property_checker_command'] == command, 'property policy differs')
    _validate_partitioned_property_evidence(shard=query, model=definition, uniform_entry=True)
    evidence = _RetainedQueries(model=model, query_root=query_root, tool_hashes=tool_hashes,
                                smt_solver=command.get('smt_solver'))
    checker = Path(evidence.binding['tools']['checker'])
    entry = definition['proof_function']
    inventory = discover_cbmc_assertions(command=[str(checker), str(model),
        *[entry if v == '$PROPERTY_FUNCTION' else v for v in command['discovery_arguments']]],
        timeout_seconds=1, query_evidence=evidence)
    require(inventory['status'] == 'satisfied' and inventory['assertions'] == definition['required_assertion_sites']
            and _unique_descriptions(inventory) == definition['required_assertion_descriptions'],
            'compiled assertion sites were omitted or changed')
    replay = _run_partitioned_properties(cbmc=checker, goto_model=model, command=command,
        proof_function=entry, required_assertion_descriptions=definition['required_assertion_descriptions'],
        timeout_seconds=1, timings=_ReplayTimings(evidence), uniform_entry=True,
        required_assertion_sites=definition['required_assertion_sites'])
    require(replay['status'] == 'satisfied' and replay['property_ids'] == query['property_ids']
            and replay['properties'] == query['properties'], 'complete query replay is missing or unsuccessful')
    # Scheduling may use retained subdivisions directly. It cannot change any
    # assertion, safety property or loop inventory in the complete check.
    for name in ('assertions', 'language_safety_inventory', 'language_safety_baseline_inventory', 'loops'):
        require(replay['partitioned_evidence'][name] == query['partitioned_evidence'][name],
                'complete property inventory differs')
    return evidence.binding
