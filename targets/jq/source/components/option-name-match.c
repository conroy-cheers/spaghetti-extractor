#include "implementation.h"

int match_token_cursor(token_cursor_services *services, uint32_t cursor_slot,
                       uint8_t short_name, uint32_t long_name,
                       uint32_t short_mode) {
  uint32_t cursor;
  uint32_t next;

  if (short_mode != 0U) {
    if (short_name == 0U)
      return 0;

    cursor = services->load_word(services->context, cursor_slot);
    if (services->load_byte(services->context, cursor) != short_name)
      return 0;

    next = cursor + UINT32_C(1);
    services->store_word(services->context, cursor_slot, next);
    if (services->load_byte(services->context, next) == 0U)
      services->store_word(services->context, cursor_slot, UINT32_C(0));
    return 1;
  }

  cursor = services->load_word(services->context, cursor_slot);
  if (services->compare_strings(services->context, cursor, long_name) != 0)
    return 0;

  services->store_word(services->context, cursor_slot, UINT32_C(0));
  return 1;
}
