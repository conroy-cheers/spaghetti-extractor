#include "portable-component-inductive.h"

spx_h_run_control_v1 component_h_initialize(
    spx_h_run_state_v1 *state,
    spx_h_context_v2 *context,
    uint32_t count) {
  (void)context;
  state->n = count;
  return (spx_h_run_control_v1) {
    SPX_H_RUN_CONTROL_RUNNING,
    SPX_H_RUN_PHASE_LOOP,
    SPX_H_RUN_COMPLETION_RETURN
  };
}

spx_h_run_control_v1 component_h_step(
    spx_h_run_state_v1 *state,
    uint32_t phase_id,
    spx_h_context_v2 *context,
    uint32_t count) {
  (void)phase_id;
  (void)context;
  (void)count;
  if (state->n == 0u) {
    return (spx_h_run_control_v1) {
      SPX_H_RUN_CONTROL_COMPLETE,
      SPX_H_RUN_PHASE_LOOP,
      SPX_H_RUN_COMPLETION_RETURN
    };
  }
  state->n -= 1u;
  return (spx_h_run_control_v1) {
    SPX_H_RUN_CONTROL_RUNNING,
    SPX_H_RUN_PHASE_LOOP,
    SPX_H_RUN_COMPLETION_RETURN
  };
}

uint32_t component_h_finish(
    const spx_h_run_state_v1 *state,
    uint32_t completion_id,
    spx_h_context_v2 *context,
    uint32_t count) {
  (void)completion_id;
  (void)context;
  (void)count;
  return state->n;
}
