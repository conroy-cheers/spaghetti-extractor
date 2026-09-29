"""Caller entry points for the shared complete compiled-property checker."""
from pathlib import Path

from ..components.bisimulation_execution import property_checker_command
from ..components.bisimulation_property_replay import check_partitioned_model, replay_partitioned_model
from ..util import sha256_file


def check_partitioned_caller(*, proof, entry, command, cbmc, evidence, timeout_seconds):
    return check_partitioned_model(model=Path(proof)/'model.goto', entry=entry, command=command,
        cbmc=cbmc, evidence=evidence, timeout_seconds=timeout_seconds, subject={'subject': 'public-complete-caller'})


def validate_partitioned_caller(result, proof):
    proof = Path(proof).resolve(); key = result['proof_key']; model = result['property_model']
    command = property_checker_command([], source_unwind_limit=key['unwind'], smt_solver=None)
    if (key['property_checker_command'] != command or model['proof_function'] != key['bindings']['boundary']['proof_entry']
            or sha256_file(proof/'model.goto') != result['proof_files']['model.goto']):
        raise ValueError('caller partitions: property policy differs')
    return replay_partitioned_model(query=result['query'], definition=model, model=proof/'model.goto',
        query_root=proof/'query-evidence', tool_hashes=key['tools'], command=command)
