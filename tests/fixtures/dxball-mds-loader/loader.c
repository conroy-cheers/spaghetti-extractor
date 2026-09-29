#include "portable-component-implementation.h"
#include "mds-loader-state.h"

uint32_t lifted_mds_load(spx_mds_loader_context_v5 *context,mds_output *output,
                        mds_input *input,uint32_t length,uint32_t flags) {
    const spx_mds_loader_services_v5 *services=context->services;
    void *user=services->context;
    uint32_t mode=flags&3,result=4;
    mds_info *info=NULL;
    mds_handle *file=NULL,*mapping=NULL;
    mds_file memory={input->data},*view=NULL;
    if (mode!=1 && mode!=2) return result;
    info=services->allocate(user,0x40,36);
    if (!info) return 1;
    info->signature=UINT32_C(0x4953444d); info->stream=0; info->pending=0;
    if (mode==1) {
        result=2;
        file=services->open(user,input,0x80000000,1,3,0x80);
        if (!file) goto done;
        length=services->size(user,file);
        mapping=services->mapping(user,file,2);
        if (!mapping) goto done;
        view=services->map(user,mapping,4);
        if (!view) goto done;
    }
    result=services->parse(user,info,mode==1 ? view : &memory,length);
 done:
    if (result) (void)services->free(user,info);
    else output->value=info;
    if (view) (void)services->unmap(user,view);
    if (mapping) (void)services->close(user,mapping);
    if (file) (void)services->close(user,file);
    return result;
}
