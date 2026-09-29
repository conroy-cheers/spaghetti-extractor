/* Borrowed: kind, valid, number, copy. Every other value argument transfers
 * ownership. Raw value words are private transport, not a heap proof.
 * slice_bounds consumes both inputs and returns owned true/error plus bounds.
 * Contracts here are fixture assumptions, not checked semantic summaries. */
enum {
  PATH_INVALID = 0, PATH_NULL = 1, PATH_NUMBER = 4,
  PATH_STRING = 5, PATH_ARRAY = 6, PATH_OBJECT = 7
};
enum {
  PATH_NOT_ARRAY, PATH_TOO_DEEP, PATH_NAN_INDEX,
  PATH_SLICE_VALUE, PATH_STRING_UPDATE
};
