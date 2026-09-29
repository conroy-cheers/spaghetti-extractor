#ifndef SPX_WINDOWS_PATHS_H
#define SPX_WINDOWS_PATHS_H
#include <stddef.h>

/* UTF-8/single-byte Windows path syntax. Expand/to_host return malloc storage;
 * full writes the caller's buffer only on success. Path parts borrow storage.
 * These routines never infer heap ownership from numeric addresses. */
char *spx_path_expand(const char *path);
char *spx_path_full(char *buffer, const char *path, size_t capacity);
char *spx_path_to_host(const char *path);
char *spx_path_dirname(char *path);
char *spx_path_basename(char *path);
/* PathIsRelativeA for the selected non-DBCS profile. A leading forward slash
 * alone is relative under this API; a backslash or drive prefix is not. */
int spx_path_is_relative(const char *path);

/* Environment adapter: returned strings are owned. Current and per-drive
 * directories describe the same namespace used by spx_path_to_host. */
char *spx_path_current(void);
char *spx_path_drive_current(char drive);
#endif
