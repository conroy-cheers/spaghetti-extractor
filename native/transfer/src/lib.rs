use pyo3::prelude::*;

#[path = "../../src/reference_kernel.rs"]
mod reference_kernel;
#[path = "../../src/reference_plan.rs"]
mod reference_plan;

#[pymodule]
fn spaghetti_extractor_transfer_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(
        reference_kernel::join_reference_state_batches,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_kernel::inspect_reference_closure_inputs,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_kernel::evaluate_reference_root_expressions,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_kernel::evaluate_reference_root_effects,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_kernel::evaluate_reference_closure_frontier,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_kernel::evaluate_reference_closure_summary,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_kernel::evaluate_reference_closure_receipt,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_kernel::evaluate_semantic_link_closure_receipt,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        reference_plan::inspect_reference_transfer_plan,
        module
    )?)?;
    module.add("REFERENCE_KERNEL_API_VERSION", 1_u32)?;
    module.add(
        "REFERENCE_KERNEL_OPERATION_REGISTRY_SHA256",
        reference_plan::OPERATION_REGISTRY_SHA256,
    )?;
    Ok(())
}
