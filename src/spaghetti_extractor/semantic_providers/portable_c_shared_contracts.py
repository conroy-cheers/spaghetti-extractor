"""Retain shared source premises inside the existing provider proof package.

Source checking, paired qualification and caller substitution remain separate.
This module binds the first two; it does not select a connected summary strategy.
"""

import hashlib
import json
import shutil
from pathlib import Path

from ..components.bisimulation_readonly_evidence import _checked_memory_summary_certificate
from ..components.bisimulation_shared_model import SHARED_CONTRACT_POLICY
from ..components.bisimulation_shared_services import normalize_shared_service_bindings
from ..components.bisimulation_shared_summary import checked_shared_summary_inputs
from ..components.component_c_v5 import render_component_c_headers_v5


def prepare_provider_shared_contract(*, artifacts, bundle, source, source_profile_sha256,
                                     symbols, intent, service_bindings, connected_components, output=None,
                                     expected_file_sha256=None):
    """Check exact retained bytes and selected premises before machine queries."""
    if intent is None or connected_components:
        raise ValueError('shared provider source contract requires a leaf and checked normal-exit intent')
    artifacts = Path(artifacts)
    content = (artifacts/'local-contract-result.json').read_bytes()
    if expected_file_sha256 is not None and hashlib.sha256(content).hexdigest() != expected_file_sha256:
        raise ValueError('shared provider source contract differs from qualification input')
    certificate = json.loads(content)
    if certificate.get('policy') != SHARED_CONTRACT_POLICY:
        raise ValueError('shared provider source contract policy differs')
    _checked_memory_summary_certificate(
        bound={'certificate': certificate, 'implementation_sha256': source['implementation_sha256'],
               'source_profile_sha256': source_profile_sha256},
        bundle=bundle, source=source, source_profile_sha256=source_profile_sha256,
        operation_symbols=symbols, headers=render_component_c_headers_v5(bundle, symbols),
        artifacts=artifacts, mutable=True, shared=True)
    if certificate['shared_contract']['relation_intent'] != intent.to_payload():
        raise ValueError('shared provider source contract names another normal-exit request')
    selected = normalize_shared_service_bindings(bundle, service_bindings)
    if certificate['shared_contract'].get('service_contracts') != selected:
        raise ValueError('shared provider source contract differs from selected service premises')
    if output is not None:
        shutil.copytree(artifacts, output)
    return certificate


def check_provider_shared_binding(*, certificate, artifacts, normal_exit_inputs, proof_artifacts):
    """Require the existing checked source/service/alias/entry/frame conjunction."""
    return checked_shared_summary_inputs(certificate=certificate, artifacts=artifacts,
        normal_exit_inputs=normal_exit_inputs, proof_artifacts=proof_artifacts)
