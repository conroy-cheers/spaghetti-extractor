#include "portable-component-implementation.h"
#include "reader-state.h"
#include <stddef.h>
#include <string.h>

reader_bytes *lifted_file_read(spx_file_reader_context_v5 *context, reader_name *name,
                               reader_bytes *supplied, uint32_t allocate) {
    const spx_file_reader_services_v5 *services=context->services;
    void *user=services->context;
    reader_handle *file=services->open(user,name,0x80000000,1,3,0x80);
    if (!file) {
        char path[260];
        strcpy(path,"..\\");
        strcat(path,name->text);
        reader_name fallback={path};
        file=services->open(user,&fallback,0x80000000,1,3,0x80);
        if (!file) return NULL;
    }
    uint32_t size=services->size(user,file);
    reader_bytes *buffer=allocate ? services->allocate(user,size) : supplied;
    if (allocate && !buffer) return NULL;
    if (!services->read(user,file,buffer,size)) {
        services->free(user,buffer);
        return NULL;
    }
    services->close(user,file);
    return buffer;
}
