"""Explicit conditional forwarding of canonical proof-runtime write callbacks.

The shared accessor contains both branches. Ordinary compilation retains its
native indirect call; the contract-specific define selects the checked direct
call. This is a trusted runtime contract, not an adapter-equivalence receipt.
"""

from ..artifacts.artifact_set import canonical_sha256_v3


CONTRACT_ID = "canonical-view-write-dispatch"
ASSERTION = "spx-bisimulation-runtime-write-dispatch-target"
SYMBOL = "__CPROVER_spx_checked_runtime_write"
NATIVE_CALL = "  runtime->write(runtime->context, address, width, (uint32_t)value, &fault);"


def runtime_dispatch_contract():
    return {
        "id": CONTRACT_ID, "revision": 1, "backend": "x86-pe32",
        "requires": [
            "The shared returned-view accessor performs its original reference realization and access checks.",
            "The current callback equals the generated source-world or exact-world write callback; this remains a required assertion.",
            "The callback ABI is void(void *, uint32_t, uint32_t, uint32_t, uint32_t *).",
        ],
        "behavior": [
            "Dispatch invokes exactly the selected callback once with unchanged context, address, width, value and fault pointer.",
            "The callback retains all byte, alias, allocation, lifetime, private-frame, effect-order and fault behavior.",
            "Reference realization and failure returns occur before dispatch exactly as in the native accessor.",
            "Unexpected callback targets fail the applicability assertion; they are not admitted by assumption alone.",
            "No callback body, heap state, progress or application-equivalence obligation is discharged by this contract.",
        ],
        "native_call": NATIVE_CALL.strip(),
        "authority": "Conditional runtime trust only; no strong qualification or native activation.",
    }


def runtime_dispatch_assurance():
    contract = runtime_dispatch_contract()
    return {"kind": "conditional-runtime-contracts", "contracts": [{
        "id": contract["id"], "revision": contract["revision"],
        "contract_sha256": canonical_sha256_v3(contract),
    }]}


def conditional_write_call():
    digest = canonical_sha256_v3(runtime_dispatch_contract())
    return f'''#ifdef SPX_CONDITIONAL_RUNTIME_CONTRACT_{digest}
  extern void {SYMBOL}(spx_runtime *, uint32_t, uint32_t, uint32_t, uint32_t *);
  {SYMBOL}(runtime, address, width, (uint32_t)value, &fault);
#else
{NATIVE_CALL}
#endif'''


def runtime_dispatch_source(assurance):
    from .bisimulation_assurance import runtime_contract_selected
    if not runtime_contract_selected(assurance, CONTRACT_ID):
        return ""
    digest = canonical_sha256_v3(runtime_dispatch_contract())
    return f'''
#ifndef SPX_CONDITIONAL_RUNTIME_CONTRACT_{digest}
#error "runtime write dispatch requires its explicit conditional contract"
#endif
void {SYMBOL}(spx_runtime *runtime,
    uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {{
  __CPROVER_assert(runtime != 0 && (runtime->write == spx_proof_source_write ||
      runtime->write == spx_proof_exact_write), "{ASSERTION}");
  __CPROVER_assume(runtime != 0 && (runtime->write == spx_proof_source_write ||
      runtime->write == spx_proof_exact_write));
  if (runtime->write == spx_proof_source_write)
    spx_proof_source_write(runtime->context, address, width, value, fault);
  else
    spx_proof_exact_write(runtime->context, address, width, value, fault);
}}
'''


def required_dispatch_assertions(assurance):
    from .bisimulation_assurance import runtime_contract_selected
    return {ASSERTION} if runtime_contract_selected(assurance, CONTRACT_ID) else set()
