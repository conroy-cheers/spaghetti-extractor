/* UTF-8 Unix argv -> the observed Windows-1252 narrow argv contract.
 * This is an entry adapter, separate from the application's locale/decoder. */
#ifndef SPX_WINDOWS_ARGV_H
#define SPX_WINDOWS_ARGV_H
#include <stddef.h>

enum spx_argv_result { SPX_ARGV_OK, SPX_ARGV_INVALID_UTF8, SPX_ARGV_NO_SPACE, SPX_ARGV_NO_MEMORY };

/* Input is a stable NUL-terminated UTF-8 string. Surrogates, overlong forms and
 * out-of-range scalars reject. Best-fit and '?' replacement match the selected
 * Windows service. A supplementary scalar produces two target '?' bytes.
 * required includes the terminator; NULL output queries size. Failure leaves
 * output untouched. Input/output must be disjoint or exactly the same pointer.
 * A non-NULL required points to writable metadata disjoint from both buffers. */
int spx_windows1252_from_utf8(const char *input, char *output, size_t capacity, size_t *required);

typedef struct { int argc; char **values; void *storage; } spx_windows_argv;
/* Supply an empty writable owner disjoint from argv and its argc valid strings.
 * One allocation owns the mutable
 * argv vector and all converted strings. Reordering the vector does not affect
 * disposal. Keep the owner alive through application atexit handlers. */
int spx_windows1252_argv_init(spx_windows_argv *owner, int argc, char *const argv[]);
void spx_windows1252_argv_dispose(spx_windows_argv *owner);
#endif
