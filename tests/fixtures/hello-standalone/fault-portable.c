/* Test-only GNU link wrappers, omitted from ordinary builds. The existing
 * allocation adapter publishes its count and size immediately before malloc.
 * Entry/observer/formatting allocations are deliberately outside this boundary.
 * A changed adapter must re-establish this selection; this is not a heap model. */
#include "services.h"
#include "allocation-fault.h"

extern void *__real_malloc(size_t size);
extern int __real_main(int argc,char **argv);

int __wrap_main(int argc,char **argv) {
    spx_fault_begin();
    return __real_main(argc,argv);
}

void *__wrap_malloc(size_t size) {
    if (hello_runtime.allocations!=spx_fault_attempts) {
        if (hello_runtime.allocations!=spx_fault_attempts+1 ||
                size!=hello_runtime.allocated_bytes) _Exit(125);
        if (spx_fault_visit(size)) {
            errno=ENOMEM;
            return NULL;
        }
    }
    return __real_malloc(size);
}
