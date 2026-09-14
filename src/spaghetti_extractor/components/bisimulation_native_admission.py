"""Conditional native access without reconstructing the process memory map.

The residual predicate is shared, arbitrary and stable during an operation.
It describes permissions, never bytes or reference identity. Instantiating it
with native admission requires the contract's frame/map closure premises.
"""

from ..artifacts.artifact_set import canonical_sha256_v3


POLICY = 'stable-residual-oracle-with-tracked-allocations-v1'


def native_admission_contract():
    return {
        'id': 'native-memory-admission', 'revision': 1,
        'policy': POLICY,
        'semantics': [
            'Scalar runtime reads and writes consult a shared permission function before private caches or byte effects.',
            'Zero address, zero width and an unrepresentable exclusive PE32 end are denied.',
            'Existing allocation span and lifetime checks remain necessary; live native-registered allocations admit whole contained spans.',
            'Other addresses consult an arbitrary stable residual permission function keyed by address, whole width and read/write direction.',
            'The residual function does not grant permissions from private footprints, reconstructed references or retained bytes.',
            'Native applicability requires null denial by every priority provider and the normal map, and correspondence of tracked registrations and releases.',
            'Tracked allocation spans have no overlapping residual mapping or priority override that could grant stale or crossing accesses.',
            'Residual mapping and priority-provider behavior remain unchanged during the operation; mapping-changing calls or interference require another contract.',
            'Input-memory contents, aliases, reference identity, allocation failure and observable effects retain their existing obligations.',
            'Connected summary consumption is rejected until its permission-context transport is implemented.',
        ],
        'authority': 'Conditional access abstraction only; caller applicability and independent runtime validation are separate and no native activation is authorized.',
    }


def native_admission_assurance():
    contract = native_admission_contract()
    return {'kind': 'conditional-runtime-contracts', 'contracts': [{
        'id': contract['id'], 'revision': contract['revision'],
        'contract_sha256': canonical_sha256_v3(contract),
    }]}


def source():
    digest = native_admission_assurance()['contracts'][0]['contract_sha256']
    return f'''
#ifndef SPX_CONDITIONAL_RUNTIME_CONTRACT_{digest}
#error "native memory admission requires explicitly conditional execution"
#endif
uint32_t __CPROVER_uninterpreted_spx_native_residual_access(
    uint32_t address, uint32_t width, uint32_t write_access);
static uint32_t spx_proof_native_access(
    const spx_proof_world *world, uint32_t address, uint32_t width,
    uint32_t write_access) {{
  if ((world != &spx_exact_world && world != &spx_source_world) ||
      address == 0U || width == 0U || address > UINT32_MAX - width ||
      write_access > 1U || !spx_proof_allocation_access(world, address, width))
    return 0U;
  uint32_t index = spx_proof_allocation_at(world, address);
  if (index != UINT32_MAX) {{
    spx_proof_allocation allocation = spx_proof_allocation_snapshot(world, index);
    if (allocation.native_rule_selector != 0U && allocation.native_generation != 0U)
      return 1U;
  }}
  return __CPROVER_uninterpreted_spx_native_residual_access(address, width, write_access) != 0U;
}}
'''


def access_expression(enabled, world, write_access):
    if enabled:
        return f'spx_proof_native_access({world}, address, width, {int(write_access)}U)'
    return f'spx_proof_allocation_access({world}, address, width)'
