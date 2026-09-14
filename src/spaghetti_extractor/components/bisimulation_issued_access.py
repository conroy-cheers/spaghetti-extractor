"""Conditional realization of already issued references.

This replaces only native re-realization. Resolution, origin issuance, memory,
allocation transitions and lifetime checks remain in the existing world. The
contract is an explicit trust boundary, not a native equivalence theorem.
"""

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_assurance import runtime_contract_selected
from .bisimulation_reference_origins import parse_capacity
from .bisimulation_support import BisimulationRefinementError


def issued_access_contract():
    return {
        "id": "issued-reference-access", "revision": 2,
        "backend": "x86-pe32",
        "authority_backends": ["x86-pe32", "x86-pe32-loader-relative-v2"],
        "requires": [
            "Every authority rule permits interior pointers.",
            "Issued identity, extent and permission metadata retain their native namespace binding until lifetime end.",
            "Origins are issued and transported by the existing checked world operations.",
        ],
        "behavior": [
            "Null references retain canonical-null and nullable checks.",
            "Non-null reference metadata must match an issued origin; otherwise a domain assertion fails.",
            "Requested permissions, offset, one-past policy and PE32 overflow remain checked.",
            "Current allocation lifetime is checked on every access, including after release or address reuse.",
            "Realization neither issues origins nor changes bytes, allocation state or observable effects.",
            "Native allocation-class qualification guards remain required.",
        ],
        "authority": "Conditional on the named runtime contract; no native activation.",
    }


def issued_access_assurance():
    contract = issued_access_contract()
    return {"kind": "conditional-runtime-contracts", "contracts": [{
        "id": contract["id"], "revision": contract["revision"],
        "contract_sha256": canonical_sha256_v3(contract),
    }]}


def issued_access_realization_source(*, authority, reference_capacity, realize_guards, assurance):
    if not runtime_contract_selected(assurance, "issued-reference-access"):
        raise BisimulationRefinementError("issued access requires its exact implemented runtime contract")
    if authority is None or authority.machine_backend not in issued_access_contract()["authority_backends"]:
        raise BisimulationRefinementError("issued access requires checked PE32 reference authority")
    if any(not rule.interior_pointers for rule in authority.rules):
        raise BisimulationRefinementError("issued access contract requires interior-pointer authority")
    capacity = parse_capacity(reference_capacity)
    digest = issued_access_assurance()["contracts"][0]["contract_sha256"]
    cases = "\n".join(f'''  if (origins->count > UINT32_C({i})) {{
    const spx_proof_origin candidate = origins->entries[{i}];
    issued |= candidate.domain == reference->domain && candidate.object == reference->object &&
        candidate.generation == reference->generation && candidate.extent == reference->extent &&
        candidate.permissions == reference->permissions;
  }}''' for i in range(capacity))
    return f'''
#ifndef SPX_CONDITIONAL_RUNTIME_CONTRACT_{digest}
#error "issued reference access requires explicitly conditional obligation execution"
#endif
static spx_boundary_status spx_proof_authority_runtime_realize(
    void *opaque, const spx_machine_reference_v1 *reference,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {{
  if (spx_proof_origins_for(opaque) == 0 || reference == 0 || address == 0)
    return SPX_BOUNDARY_UNSUPPORTED;
{chr(10).join(realize_guards)}
  const spx_proof_origins *origins = spx_proof_origins_for(opaque);
  uint32_t issued = reference->domain == 0U && reference->object == 0U;
{cases}
  __CPROVER_assert(issued, "spx-bisimulation-issued-access-contract-domain");
  return spx_proof_realize_reference(opaque, reference, permissions, nullable, one_past, address);
}}
'''
