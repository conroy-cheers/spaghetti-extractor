#ifndef HELLO_QUOTE_BUFFER_RUNTIME_H
#define HELLO_QUOTE_BUFFER_RUNTIME_H
#include <stdint.h>
/* Private native-fixture bridge; none of these raw addresses enter authored C. */
uint32_t fixture_quote_buffer(unsigned char *image, unsigned char *output, uint32_t capacity,
    unsigned char *argument, uint32_t size, uint32_t style, uint32_t flags,
    const uint32_t *mask, unsigned char *left, unsigned char *right);
#endif
