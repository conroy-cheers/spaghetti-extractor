#ifndef DXBALL_FLOW_RUNTIME_H
#define DXBALL_FLOW_RUNTIME_H
#include "flow-state.h"
#include "lifecycle-runtime.h"
void flow_enter(unsigned);
uint32_t fixture_flow_frame(flow_state *);
void fixture_flow_key(flow_state *, uint32_t);
void fixture_flow_enter(flow_state *);
void fixture_flow_leave(flow_state *, uint32_t);
void fixture_flow_redraw(flow_state *);
void fixture_flow_restore(flow_state *);
void fixture_flow_check_surfaces(flow_state *);
void fixture_flow_shutdown(flow_state *, uint32_t);
void flow_initialize(void *, flow_state *);
void flow_scene_enter(void *, flow_state *, uint32_t);
void flow_scene_update(void *, flow_state *, uint32_t);
void flow_scene_key(void *, flow_state *, uint32_t, uint32_t);
void flow_scene_leave(void *, flow_state *, uint32_t, uint32_t);
void flow_scene_redraw(void *, flow_state *, uint32_t);
uint32_t flow_surface_status(void *, flow_state *, font_surface *);
uint32_t flow_surface_restore(void *, flow_state *, font_surface *);
uint32_t flow_audio_status(void *, flow_state *, flow_audio *);
void flow_audio_restore(void *, flow_state *, flow_audio *);
void flow_restore_banks(void *, asset_state *);
void flow_release(void *, flow_state *, font_surface *);
#endif
