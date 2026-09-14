/* Experimental native-context-spans:1 predicate. A contained span is only a
 * permission promise after native backing, priority and lifetime premises have
 * been established. This does not describe bytes, allocation or target identity.
 */
static uint32_t spx_context_span_contains(
    uint32_t low, uint32_t high, uint32_t address, uint32_t width) {
  return low != 0U && low < high && width != 0U &&
      address >= low && address < high && width <= high - address;
}
