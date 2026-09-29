/* Portable bindings for the observed PE32 Windows-1252 text profile.
 * Redirected bytes and the bounded POSIX UTF-8 terminal profile are distinct;
 * see README.md for cursor, control-character and lifetime assumptions. */
#ifndef SPX_PORTABLE_WINDOWS_1252_H
#define SPX_PORTABLE_WINDOWS_1252_H
#include <stdint.h>
#include <stdio.h>

int spx_target_fprintf(FILE *stream, const char *format, ...);
int spx_target_put16(FILE *stream, const uint16_t *text);
uint32_t spx_target_decode16(uint16_t *output, const unsigned char *input,
                           uint32_t size, unsigned char state[4]);
void spx_target_console_init(void);
uint32_t spx_target_stream_pending(FILE *stream);
int spx_target_stream_error(FILE *stream);
int spx_target_stream_close(FILE *stream);
/* The assembled stream-close component adapter supplies this policy entry. */
int spx_target_close(FILE *stream);
const char *spx_target_basename(const char *name);
#endif
