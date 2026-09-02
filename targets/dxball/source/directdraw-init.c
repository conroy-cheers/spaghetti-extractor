#include "portable-component-implementation.h"

enum {
  DXBALL_MESSAGE_DIRECTDRAW_CREATE_FAILURE = 1,
  DXBALL_MESSAGE_COOPERATIVE_LEVEL_FAILURE = 2,
  DXBALL_MESSAGE_PRIMARY_SURFACE_CREATE_FAILURE = 3,
  DXBALL_MESSAGE_BACKBUFFER_CREATE_FAILURE = 4,
  DXBALL_MESSAGE_CLIPPER_CREATE_FAILURE = 5,
  DXBALL_MESSAGE_CLIPPER_WINDOW_FAILURE = 6,
  DXBALL_MESSAGE_CLIPPER_ATTACH_FAILURE = 7,
};

uint32_t dxball_directdraw_initialize(
    spx_directdraw_init_context_v5 *context,
    spx_resource_v2 window) {
  spx_resource_v2 directdraw = {0};
  const int32_t create_status = context->services->directdraw_create(
      context->services->context, &directdraw);
  if (create_status != INT32_C(0)) {
    context->services->hide_window(context->services->context, window);
    (void)context->services->message_box(
        context->services->context, window,
        (uint32_t)DXBALL_MESSAGE_DIRECTDRAW_CREATE_FAILURE);
    context->services->destroy_window(context->services->context, window);
    return UINT32_C(0);
  }
  const uint32_t cooperative = context->services->set_cooperative_level(
      context->services->context, directdraw, window, UINT32_C(8));
  if (cooperative != 0U) {
    context->services->hide_window(context->services->context, window);
    (void)context->services->message_box(
        context->services->context, window,
        (uint32_t)DXBALL_MESSAGE_COOPERATIVE_LEVEL_FAILURE);
    context->services->destroy_window(context->services->context, window);
    return UINT32_C(0);
  }
  context->state.directdraw_initialized = UINT32_C(1);
  context->state.capability_mode = UINT32_C(0);
  const uint32_t capabilities = context->services->get_caps(
      context->services->context, directdraw);
  context->state.video_memory_capability =
      (capabilities >> UINT32_C(25)) & UINT32_C(1);
  spx_resource_v2 primary = {0};
  const int32_t primary_status = context->services->create_primary_surface(
      context->services->context, directdraw, &primary);
  if (primary_status != INT32_C(0)) {
    context->services->hide_window(context->services->context, window);
    (void)context->services->message_box(
        context->services->context, window,
        (uint32_t)DXBALL_MESSAGE_PRIMARY_SURFACE_CREATE_FAILURE);
    context->services->destroy_window(context->services->context, window);
    return UINT32_C(0);
  }
  spx_resource_v2 backbuffer = {0};
  const int32_t backbuffer_status = context->services->create_backbuffer(
      context->services->context, directdraw, &backbuffer);
  if (backbuffer_status != INT32_C(0)) {
    context->services->hide_window(context->services->context, window);
    (void)context->services->message_box(
        context->services->context, window,
        (uint32_t)DXBALL_MESSAGE_BACKBUFFER_CREATE_FAILURE);
    context->services->destroy_window(context->services->context, window);
    return UINT32_C(0);
  }
  if (context->state.clipper_mode == UINT32_C(1)) {
    spx_resource_v2 clipper = {0};
    const int32_t clipper_status = context->services->create_clipper(
        context->services->context, directdraw, &clipper);
    if (clipper_status != INT32_C(0)) {
      context->services->hide_window(context->services->context, window);
      (void)context->services->message_box(
          context->services->context, window,
          (uint32_t)DXBALL_MESSAGE_CLIPPER_CREATE_FAILURE);
      context->services->destroy_window(context->services->context, window);
      return UINT32_C(0);
    }
    const int32_t window_status = context->services->set_clipper_window(
        context->services->context, clipper, window);
    if (window_status != INT32_C(0)) {
      context->services->hide_window(context->services->context, window);
      (void)context->services->message_box(
          context->services->context, window,
          (uint32_t)DXBALL_MESSAGE_CLIPPER_WINDOW_FAILURE);
      context->services->destroy_window(context->services->context, window);
      return UINT32_C(0);
    }
    const int32_t attach_status = context->services->attach_clipper(
        context->services->context, primary, clipper);
    if (attach_status != INT32_C(0)) {
      context->services->hide_window(context->services->context, window);
      (void)context->services->message_box(
          context->services->context, window,
          (uint32_t)DXBALL_MESSAGE_CLIPPER_ATTACH_FAILURE);
      context->services->destroy_window(context->services->context, window);
      return UINT32_C(0);
    }
  }
  return UINT32_C(1);
}
