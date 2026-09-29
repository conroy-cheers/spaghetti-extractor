#ifndef SPX_WINDOWS_OUTPUT_H
#define SPX_WINDOWS_OUTPUT_H
/* Process-owned standard output/error streams. Install once before jq obtains
 * FILE pointers; the host adapter owns buffering, errors and close. Changing to
 * binary mode flushes pending text before changing either stream. This is the
 * redirected Windows text profile, not a console or general FILE emulation. */
int spx_output_initialize(void);
void spx_output_binary(void);
/* The exercised CRT wide diagnostic consists of ASCII code points. Text mode
 * uses byte text output; binary mode emits their UTF-16LE representation. */
void spx_output_wide_stderr_ascii(const char *);
#endif
