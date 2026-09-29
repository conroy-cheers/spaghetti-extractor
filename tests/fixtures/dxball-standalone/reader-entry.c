/* Bind every declared reader service with the actual program owner. */
#include "portable-component-implementation.h"
#include "file-storage.h"
#include "reader-runtime.h"

reader_bytes *dxball_program_file_read(dxball_program *p, reader_name *name,
                                      reader_bytes *supplied, uint32_t allocate) {
    spx_file_reader_services_v5 services = {
        .context=p, .open=reader_open, .size=reader_size, .allocate=reader_allocate,
        .read=reader_read, .free=reader_free, .close=reader_close
    };
    spx_file_reader_context_v5 context = {.services=&services};
    return lifted_file_read(&context, name, supplied, allocate);
}
