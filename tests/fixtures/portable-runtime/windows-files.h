#ifndef SPX_WINDOWS_FILES_H
#define SPX_WINDOWS_FILES_H

#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>

/* A scoped Windows input profile, implemented over the host filesystem.
 * Names use ASCII case folding; non-ASCII bytes match exactly. The caller owns
 * resolved paths and stream handles. No process-wide stream registry is used. */
typedef struct spx_input spx_input;
char *spx_file_resolve(const char *path);
int spx_file_stat(const char *path, struct stat *result);
spx_input *spx_input_open(const char *path, int text_mode);
spx_input *spx_input_attach(FILE *file, int text_mode, int owned);
size_t spx_input_read(void *buffer, size_t length, spx_input *input);
char *spx_input_gets(char *buffer, int capacity, spx_input *input);
int spx_input_eof(const spx_input *input);
int spx_input_error(const spx_input *input);
int spx_input_borrowed(const spx_input *input);
void spx_input_clear(spx_input *input);
FILE *spx_input_detach(spx_input *input);
int spx_input_close(spx_input *input);

#endif
