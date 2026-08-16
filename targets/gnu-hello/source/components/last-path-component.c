#include "portable-component-inductive.h"

static uint8_t byte_at(const spx_bytes_view_v2 *value, uint32_t index) {
  uint8_t result = 0U;
  (void)value->read_u8(value->context, index, &result);
  return result;
}

static uint32_t is_separator(uint8_t value) {
  return value == (uint8_t)'/' || value == (uint8_t)'\\';
}

spx_last_path_component_find_control_v1
gnu_hello_last_path_component_initialize(
    spx_last_path_component_find_state_v1 *state,
    spx_last_path_component_context_v2 *context,
    const spx_bytes_view_v2 *value) {
  uint8_t first = byte_at(value, 0U);
  uint32_t cursor = 0U;
  (void)context;

  if ((((uint32_t)(first | 0x20U) - (uint32_t)'a') < 26U) &&
      byte_at(value, 1U) == (uint8_t)':') {
    cursor = 2U;
  }
  state->component = 0U;
  state->cursor = cursor;
  state->saw_separator = 0U;
  first = byte_at(value, cursor);
  if (is_separator(first) != 0U) {
    return (spx_last_path_component_find_control_v1) {
      SPX_LAST_PATH_COMPONENT_FIND_CONTROL_RUNNING,
      SPX_LAST_PATH_COMPONENT_FIND_PHASE_SKIP_PREFIX,
      SPX_LAST_PATH_COMPONENT_FIND_COMPLETION_RETURN
    };
  }
  state->component = cursor;
  if (first == 0U) {
    return (spx_last_path_component_find_control_v1) {
      SPX_LAST_PATH_COMPONENT_FIND_CONTROL_COMPLETE,
      SPX_LAST_PATH_COMPONENT_FIND_PHASE_SCAN,
      SPX_LAST_PATH_COMPONENT_FIND_COMPLETION_RETURN
    };
  }
  return (spx_last_path_component_find_control_v1) {
    SPX_LAST_PATH_COMPONENT_FIND_CONTROL_RUNNING,
    SPX_LAST_PATH_COMPONENT_FIND_PHASE_SCAN,
    SPX_LAST_PATH_COMPONENT_FIND_COMPLETION_RETURN
  };
}

spx_last_path_component_find_control_v1
gnu_hello_last_path_component_step(
    spx_last_path_component_find_state_v1 *state,
    uint32_t phase_id,
    spx_last_path_component_context_v2 *context,
    const spx_bytes_view_v2 *value) {
  uint8_t current;
  (void)context;

  if (phase_id == SPX_LAST_PATH_COMPONENT_FIND_PHASE_SKIP_PREFIX) {
    state->cursor += 1U;
    current = byte_at(value, state->cursor);
    if (is_separator(current) != 0U) {
      return (spx_last_path_component_find_control_v1) {
        SPX_LAST_PATH_COMPONENT_FIND_CONTROL_RUNNING,
        SPX_LAST_PATH_COMPONENT_FIND_PHASE_SKIP_PREFIX,
        SPX_LAST_PATH_COMPONENT_FIND_COMPLETION_RETURN
      };
    }
    state->component = state->cursor;
    if (current == 0U) {
      return (spx_last_path_component_find_control_v1) {
        SPX_LAST_PATH_COMPONENT_FIND_CONTROL_COMPLETE,
        SPX_LAST_PATH_COMPONENT_FIND_PHASE_SCAN,
        SPX_LAST_PATH_COMPONENT_FIND_COMPLETION_RETURN
      };
    }
    return (spx_last_path_component_find_control_v1) {
      SPX_LAST_PATH_COMPONENT_FIND_CONTROL_RUNNING,
      SPX_LAST_PATH_COMPONENT_FIND_PHASE_SCAN,
      SPX_LAST_PATH_COMPONENT_FIND_COMPLETION_RETURN
    };
  }

  current = byte_at(value, state->cursor);
  if (is_separator(current) != 0U) {
    state->saw_separator = 1U;
  } else if (state->saw_separator != 0U) {
    state->component = state->cursor;
    state->saw_separator = 0U;
  }
  state->cursor += 1U;
  return (spx_last_path_component_find_control_v1) {
    byte_at(value, state->cursor) == 0U
        ? SPX_LAST_PATH_COMPONENT_FIND_CONTROL_COMPLETE
        : SPX_LAST_PATH_COMPONENT_FIND_CONTROL_RUNNING,
    SPX_LAST_PATH_COMPONENT_FIND_PHASE_SCAN,
    SPX_LAST_PATH_COMPONENT_FIND_COMPLETION_RETURN
  };
}

uint32_t gnu_hello_last_path_component_finish(
    const spx_last_path_component_find_state_v1 *state,
    uint32_t completion_id,
    spx_last_path_component_context_v2 *context,
    const spx_bytes_view_v2 *value) {
  (void)completion_id;
  (void)context;
  (void)value;
  return state->component;
}
