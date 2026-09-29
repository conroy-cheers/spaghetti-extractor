#include "test-input.h"
#include <stdlib.h>
_Noreturn void spx_test_exit(int status) { exit(status); }
int spx_test_thread_create(pthread_t *id, const pthread_attr_t *attributes,
        void *(*entry)(void *), void *data) {
    (void)&jv_is_valid;
    return pthread_create(id, attributes, entry, data);
}
int spx_test_thread_join(pthread_t id, void **result) {
    return pthread_join(id, result);
}
