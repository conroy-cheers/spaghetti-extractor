/* Native fixture services preserve jq's user-visible error messages. */
#include "native-api.h"
#include "path-contract.h"
/* The pinned jv_set NaN-index branch loses the incoming item's reference.
 * Transfer the descriptor out of the portable token frame without freeing the
 * native reference. This explicitly preserves that original lifetime defect. */
void path_abandon(jv value) { (void)value; }
jv path_error(unsigned code) {
  const char *messages[] = {"Path must be specified as an array", "Path too deep",
    "Cannot set array element at NaN index",
    "A slice of an array can only be assigned another array", "Cannot update string slices"};
  return jv_invalid_with_msg(jv_string(messages[code]));
}
jv path_index_error(jv value, jv key) {
  jv message;
  if (jv_get_kind(key) == JV_KIND_STRING && jv_string_length_bytes(jv_copy(key)) < 30)
    message = jv_string_fmt("Cannot index %s with string \"%s\"",
                           jv_kind_name(jv_get_kind(value)), jv_string_value(key));
  else message = jv_string_fmt("Cannot index %s with %s",
                              jv_kind_name(jv_get_kind(value)), jv_kind_name(jv_get_kind(key)));
  jv_free(value); jv_free(key);
  return jv_invalid_with_msg(message);
}
jv path_update_error(jv value, jv key, jv item) {
  jv message = jv_string_fmt("Cannot update field at %s index of %s",
                           jv_kind_name(jv_get_kind(key)), jv_kind_name(jv_get_kind(value)));
  jv_free(value); jv_free(key); jv_free(item);
  return jv_invalid_with_msg(message);
}
