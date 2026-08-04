#include "implementation.h"

static uint32_t is_dir_sep(uint8_t value) {
  return value == UINT8_C(0x2f) || value == UINT8_C(0x5c);
}

static uint32_t is_drive_letter(uint8_t value) {
  uint8_t folded = (uint8_t)(value & UINT8_C(0xdf));
  return folded >= UINT8_C('A') && folded <= UINT8_C('Z');
}

static uint8_t read_path(windows_path_info_services *services,
                         uint32_t address, uint32_t *ok) {
  if (*ok == 0U) return 0U;
  return services->read_byte(services->context, address, ok);
}

static void store_path_info(windows_path_info_services *services,
                            uint32_t info, uint32_t offset, uint32_t value,
                            uint32_t *ok) {
  if (*ok != 0U)
    services->write_pointer(services->context, info + offset, value, ok);
}

uint32_t scan_windows_path_info(windows_path_info_services *services,
                                uint32_t info, uint32_t path,
                                uint32_t max_path_bytes) {
  uint32_t ok = 1U, pos = path, unc_components = 0U;
  uint32_t dbcs_trail = 0U, previous_separator = 0U, separator;
  uint32_t code_page, terminal_separator = 0U;
  uint8_t value, next;

  if (services == 0 || services->read_byte == 0 ||
      services->write_pointer == 0 || services->are_file_apis_ansi == 0 ||
      services->is_dbcs_lead_byte == 0 || services->begin_unc_scan == 0)
    return 1U;

  code_page = services->are_file_apis_ansi(services->context) ? 0U : 1U;
  store_path_info(services, info, 0U, 0U, &ok);
  store_path_info(services, info, 4U, 0U, &ok);
  store_path_info(services, info, 8U, 0U, &ok);
  store_path_info(services, info, 12U, 0U, &ok);
  if (ok == 0U) return 1U;

  value = read_path(services, pos, &ok);
  if (ok == 0U) return 1U;
  if (is_dir_sep(value)) {
    next = read_path(services, pos + 1U, &ok);
    if (ok == 0U) return 1U;
    if (is_dir_sep(next)) {
      pos += 2U;
      value = read_path(services, pos, &ok);
      if (ok == 0U) return 1U;
      if (value != 0U) {
        services->begin_unc_scan(services->context, &ok);
        if (ok == 0U) return 1U;
        while (value != 0U) {
          separator = 0U;
          if (dbcs_trail != 0U) {
            dbcs_trail = 0U;
          } else if (services->is_dbcs_lead_byte(
                         services->context, code_page, value, pos, 1U)) {
            dbcs_trail = 1U;
          } else {
            separator = is_dir_sep(value);
          }
          if (separator != 0U && previous_separator == 0U) {
            ++unc_components;
            if (unc_components == 2U) break;
          }
          previous_separator = separator;
          ++pos;
          if (pos - path > max_path_bytes) return 1U;
          value = read_path(services, pos, &ok);
          if (ok == 0U) return 1U;
        }
      }
      store_path_info(services, info, 0U, pos, &ok);
    }
  } else if (is_drive_letter(value)) {
    next = read_path(services, pos + 1U, &ok);
    if (ok == 0U) return 1U;
    if (next == UINT8_C(':')) {
      pos += 2U;
      store_path_info(services, info, 0U, pos, &ok);
    }
  }
  if (ok == 0U) return 1U;

  dbcs_trail = 0U;
  previous_separator = 0U;
  value = read_path(services, pos, &ok);
  if (ok == 0U) return 1U;
  while (value != 0U) {
    separator = 0U;
    if (dbcs_trail != 0U) {
      dbcs_trail = 0U;
    } else if (services->is_dbcs_lead_byte(
                   services->context, code_page, value, pos, 0U)) {
      dbcs_trail = 1U;
    } else {
      separator = is_dir_sep(value);
    }
    if (separator != 0U && previous_separator == 0U) {
      terminal_separator = pos;
      store_path_info(services, info, 12U, pos, &ok);
    }
    if (separator == 0U && previous_separator != 0U) {
      store_path_info(services, info, 4U, terminal_separator, &ok);
      store_path_info(services, info, 8U, pos, &ok);
      store_path_info(services, info, 12U, 0U, &ok);
    }
    if (ok == 0U) return 1U;
    previous_separator = separator;
    ++pos;
    if (pos - path > max_path_bytes) return 1U;
    value = read_path(services, pos, &ok);
    if (ok == 0U) return 1U;
  }
  store_path_info(services, info, 16U, pos, &ok);
  return ok == 0U;
}
