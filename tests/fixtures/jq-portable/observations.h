#ifndef SPX_PORTABLE_JQ_OBSERVATIONS_H
#define SPX_PORTABLE_JQ_OBSERVATIONS_H
#include <stdio.h>
#include <string.h>
void portable_component_entry(const char *, unsigned *);
void portable_component_report(void);
/* Comparison trace scaffolding must not enter jq's stdout/stderr protocol.
 * Actual service-outcome violations keep their diagnostic and exit behavior. */
static inline int portable_binding_message(const char *message, FILE *stream) {
    return strncmp(message,"SPX_",4)==0 ? 0 : fputs(message,stream);
}
#endif
