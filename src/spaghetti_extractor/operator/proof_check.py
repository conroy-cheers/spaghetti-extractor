"""Retain ordinary proof evidence and render non-authorizing diagnostics."""
import json
from pathlib import Path
import re
import shutil
import tempfile

from ..build_support.nix_invocation import nix_command
from ..components.bisimulation_query_evidence import previous_proof_queries
from ..components.contextual_bisimulation import validate_contextual_refinement_v2


def retain_component_proof(*, path, component_id, capture):
    """Validate an immutable snapshot; query readers still check every cache hit."""
    def validate(root):
        try:
            if (root / 'conditional-engine-result.json').exists():
                raise ValueError('conditional evidence cannot supply an ordinary component check')
            packet = json.loads((root / 'contextual-refinement-result.json').read_text())
            if packet['proof']['component_id'] != component_id:
                raise ValueError('retained proof names another component')
            previous_proof_queries(root)
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError(f'cannot reuse component proof at {root}: {error}') from error

    root = Path(path).resolve()
    validate(root)
    if re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/]+(?:/[^\n]+)?', str(root)):
        return str(root)
    # Local packages may reference retained package members through symlinks.
    # Materialize their bytes before importing so sandbox access does not depend
    # on undeclared symlink targets. Validate the imported snapshot again.
    with tempfile.TemporaryDirectory(prefix='component-proof-evidence-') as temporary:
        snapshot = Path(temporary) / 'evidence'
        try:
            shutil.copytree(root, snapshot, symlinks=False)
        except (OSError, shutil.Error) as error:
            raise ValueError(f'cannot snapshot component proof: {error}') from error
        retained = capture(nix_command('store', 'add-path', '--name', 'component-proof-evidence', str(snapshot)))
    if re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\n]+', retained) is None:
        raise ValueError('proof evidence import did not return a store path')
    validate(Path(retained))
    return retained


def render_component_proof_check(*, path, payload, component_id, as_json):
    packet = json.loads((path.parent / 'contextual-refinement-result.json').read_text())
    if packet.get('proof') != payload or payload.get('component_id') != component_id:
        raise ValueError('ordinary proof diagnostic binds another proof or component')
    validate_contextual_refinement_v2(payload, proof_plan=packet['proof_plan'], exact_c_slice=packet['exact_c_slice'])
    if 'diagnostic_selection' not in payload['models'] or payload['activation_authorized'] is not False:
        raise ValueError('ordinary proof diagnostic lacks non-authorizing region selection')
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{component_id}: {payload['status']} (ordinary regional diagnostic; activation=no)")
        for shard in payload['shards']:
            print(f"  {shard['operation_id']}/{shard['obligation_id']}: {shard['status']} ({shard.get('code', '')})")
        print(f'Evidence: {path.parent}')
        print('Next: run the complete component check to discharge all obligations before qualification and selection.')
    return 1  # Even an all-region diagnostic is not a qualified replacement.


def retain_candidate_proofs(*, entries, configuration, product, capture):
    """Hints recheck current providers; they never select historical objects."""
    if product not in configuration.get('products', []):
        raise ValueError('candidate configuration has no parameterized proof-reuse product')
    selected = set(configuration['selectedComponentIds'])
    paths = {}
    for entry in entries:
        identity, separator, path = entry.partition('=')
        if not separator or not path or identity not in selected or identity in paths:
            raise ValueError('candidate --reuse-proof requires unique selected COMPONENT=DIR entries')
        paths[identity] = path
    return {identity: retain_component_proof(path=path, component_id=identity, capture=capture)
            for identity, path in sorted(paths.items())}
