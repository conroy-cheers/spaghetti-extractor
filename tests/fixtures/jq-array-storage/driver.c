#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <inttypes.h>
#include "native.h"
#include "allocation-observer.h"
#include "comparison-services.h"

static jq_cell copy_value(jq_cell value) {
    jq_cell output; storage_copy(0,&value,&output); return output;
}
static jq_cell create(unsigned capacity) {
    jq_cell output; storage_create(0,capacity,&output); return output;
}
static jq_cell set(jq_cell value,int index,jq_cell item) {
    jq_cell output; storage_set(0,&value,index,&item,&output); return output;
}
static jq_cell slice(jq_cell value,int start,int end) {
    jq_cell output; storage_slice(0,&value,start,end,&output); return output;
}
static jq_cell get(jq_cell value,int index) {
    jq_cell output; storage_get(0,&value,index,&output); return output;
}
static jq_cell number(int n) { return storage_pack(jv_number(n)); }

static uint32_t random_word(uint32_t *seed) {
    uint32_t value=*seed;
    value ^= value << 13;value ^= value >> 17;value ^= value << 5;
    *seed=value;return value;
}
static void generated_sequence(jq_cell root,jq_cell *values,unsigned *count,uint32_t seed) {
    values[0]=root;
    for(unsigned i=1;i<5;++i) values[i]=copy_value(root);
    values[5]=storage_pack(jv_invalid());*count=6;
    for(unsigned step=0;step<48;++step) {
        unsigned operation=random_word(&seed)%7U;
        unsigned target=random_word(&seed)%5U,source=random_word(&seed)%5U;
        int index=(int)(random_word(&seed)%12U);
        int value=(int)(random_word(&seed)%101U)-50;
        fprintf(stderr,"generated-step step=%u operation=%u target=%u source=%u index=%d value=%d\n",
            step,operation,target,source,index,value);
        if (operation==0) values[target]=set(values[target],index,number(value));
        else if (operation==1) {
            jq_cell replacement=copy_value(values[source]);
            storage_release(0,&values[target]);values[target]=replacement;
        } else if (operation==2) {
            jq_cell replacement=slice(copy_value(values[source]),index-2,index+3);
            storage_release(0,&values[target]);values[target]=replacement;
        } else if (operation==3) {
            storage_release(0,&values[target]);values[target]=create((unsigned)index);
        } else if (operation==4) {
            storage_release(0,&values[5]);values[5]=get(copy_value(values[source]),index-2);
        } else if (operation==5) {
            jq_cell child=create(2);child=set(child,0,number(value));child=set(child,1,number(-value));
            values[target]=set(values[target],index,child);
        } else {
            jq_cell measured=copy_value(values[source]);int length=storage_length(0,&measured);
            values[target]=set(values[target],0,number(length));
        }
    }
}

static void observe(jq_cell *values,unsigned count,int entry_length,const char *outcome) {
    printf("{\"outcome\":\"%s\",\"entry_length\":%d,\"values\":[",outcome,entry_length);
    for (unsigned i=0;i<count;++i) {
        jv value=jv_copy(storage_unpack(values[i]));
        if (!jv_is_valid(value)) value=jv_object_set(jv_object(),jv_string("invalid"),jv_invalid_get_msg(value));
        jv text=jv_dump_string(value,JV_PRINT_SORTED);
        printf("%s%s",i?",":"",jv_string_value(text)); jv_free(text);
    }
    printf("],\"alias_matrix\":[");
    for (unsigned i=0;i<count;++i) for (unsigned j=0;j<count;++j) {
        jq_value a=values[i].value,b=values[j].value;
        printf("%s%d",i||j?",":"",jq_allocated(a) && jq_allocated(b) && a.u.ptr==b.u.ptr);
    }
    printf("],\"references\":[");
    for (unsigned i=0;i<count;++i)
        printf("%s%d",i?",":"",jv_get_refcnt(storage_unpack(values[i])));
    printf("]");
}

/* State inspected after longjmp has static storage. No changed automatic local
 * is read after the jump, and only retained caller references are reclaimed. */
static jmp_buf failure_landing;
static jq_cell failure_input,failure_item,failure_values[3];
static unsigned failure_callbacks,failure_marker=0x5a170123U;
static int failure_context_matches;
static void allocation_exhausted(void *context) {
    ++failure_callbacks;
    failure_context_matches=context==&failure_marker && failure_marker==0x5a170123U;
    longjmp(failure_landing,1);
}
static int allocation_failure(const char *scenario) {
    int create_failure=!strcmp(scenario,"create");
    int slice_failure=!strcmp(scenario,"empty-slice");
    int index=!strcmp(scenario,"shared-set") ? 1 : !strcmp(scenario,"grow-set") ? 12 : -4;
    if (!create_failure && !slice_failure && strcmp(scenario,"shared-set") &&
        strcmp(scenario,"grow-set") && strcmp(scenario,"error")) return 2;
    allocation_observer_begin();
    failure_input=create(8);
    for (int i=0;i<3;++i) failure_input=set(failure_input,i,number(10+i));
    failure_item=create(1);failure_item=set(failure_item,0,number(55));
    failure_values[0]=copy_value(failure_input);failure_values[1]=copy_value(failure_item);
    failure_values[2]=number(12345);
    jv_nomem_handler(allocation_exhausted,&failure_marker);
#if SPX_COMPARISON_NONLOCAL
    uint32_t handler=storage_selected ? spx_service_handler_begin() : 0;
#endif
    if (!setjmp(failure_landing)) {
        allocation_observer_fail_next_malloc();
        if (create_failure) storage_create(0,8,&failure_values[2]);
        else if (slice_failure) storage_slice(0,&failure_input,2,1,&failure_values[2]);
        else storage_set(0,&failure_input,index,&failure_item,&failure_values[2]);
        fputs("guarded allocation unexpectedly returned after injected failure\n",stderr);return 86;
    }
#if SPX_COMPARISON_NONLOCAL
    if (storage_selected) {
        spx_service_handler_catch(handler,"nomem");
        spx_service_handler_end(handler);
    }
#endif
    allocation_observer_pause(1);
    observe(failure_values,3,3,"nonlocal-nomem");
    printf(",\"allocation_failure\":{\"callbacks\":%u,\"context_preserved\":%s,"
        "\"failed_allocations\":%" PRIu64 ",\"requested_bytes\":%zu}",failure_callbacks,
        failure_context_matches ? "true" : "false",allocation_observer_failures(),allocation_observer_failed_size());
    allocation_observer_pause(0);
    for (unsigned i=0;i<3;++i) storage_release(0,&failure_values[i]);
    if (create_failure) storage_release(0,&failure_input);
    if (create_failure || slice_failure) storage_release(0,&failure_item);
    printf(",\"allocation_lifetime\":");allocation_observer_finish(stdout);printf("}\n");
    return 0;
}

int main(int argc,char **argv) {
    if (argc!=3 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
    storage_selected=!strcmp(argv[1],"source");
    if (!strncmp(argv[2],"nomem-",6)) return allocation_failure(argv[2]+6);
    int generated=!strncmp(argv[2],"generated:",10);
    int scenario=generated?0:atoi(argv[2]); if(scenario<0 || scenario>10) return 2;
    char *end=NULL;
    uint32_t seed=generated?(uint32_t)strtoul(argv[2]+10,&end,10):0;
    if(generated && (!seed || !end || *end)) return 2;
    allocation_observer_begin();
    jq_cell values[6]; unsigned count=0;
    jq_cell root=create(scenario==2 ? 1U : 8U);
    root=set(root,0,number(10));root=set(root,1,number(20));root=set(root,2,number(30));
    jq_cell measured=copy_value(root);
    int entry_length=storage_length(0,&measured);
    if (generated) generated_sequence(root,values,&count,seed);
    else if (scenario==0) { /* retained aliases must keep old contents after mutation */
        values[count++]=copy_value(root);values[count++]=set(root,1,number(77));
    } else if (scenario==1) { /* unique backing permits an in-place update */
        values[count++]=set(root,-1,number(99));
    } else if (scenario==2) { /* grow, initialize holes, preserve the old prefix */
        values[count++]=set(root,12,number(55));
    } else if (scenario==3 || scenario==4) {
        values[count++]=copy_value(root);
        values[count++]=set(root,scenario==3 ? -4 : INT32_MAX,number(55));
    } else if (scenario==5) { /* a slice aliases a backing object, not a new array */
        values[count++]=copy_value(root);
        jq_cell part=slice(root,1,3); values[count++]=copy_value(part);
        values[count++]=set(part,0,number(88));
    } else if (scenario==6) { /* empty slices have fresh backing */
        values[count++]=copy_value(root);values[count++]=slice(root,2,1);
    } else if (scenario==7) { /* the two outer slots own the same child array */
        jq_cell outer=create(2);
        outer=set(outer,0,copy_value(root));outer=set(outer,1,root);
        jq_cell child=get(copy_value(outer),0);
        values[count++]=copy_value(outer);
        values[count++]=set(child,0,number(101));
        values[count++]=get(outer,1);
    } else if (scenario==8) {
        values[count++]=get(copy_value(root),-1);
        values[count++]=get(copy_value(root),3);
        values[count++]=get(root,2);
    } else if (scenario==9) {
        /* Exercise the real 16-bit slice-offset overflow branch without tens
         * of thousands of fixture calls or a fixed-capacity heap model. */
        storage_release(0,&root);
        root=create(65540U); root=set(root,65538,number(42));
        root=slice(root,65535,65539);
        values[count++]=copy_value(root);values[count++]=slice(root,1,4);
    } else {
        /* Final destruction must also release allocated elements outside the
         * surviving slice's visible range. Output equality cannot detect this. */
        jq_cell outer=create(3);
        outer=set(outer,0,copy_value(root));
        outer=set(outer,1,copy_value(root));
        outer=set(outer,2,root);
        values[count++]=slice(outer,1,2);
    }
    allocation_observer_pause(1);
    observe(values,count,entry_length,"return");
    allocation_observer_pause(0);
    for (unsigned i=0;i<count;++i) storage_release(0,&values[i]);
    printf(",\"allocation_failure\":null,\"allocation_lifetime\":");
    allocation_observer_finish(stdout);printf("}\n");
    if (storage_selected) {
        unsigned sum=0;
        for (unsigned i=0;i<7;++i) { sum+=storage_calls[i]; fprintf(stderr,"storage-unit-%u=%u\n",i,storage_calls[i]); }
        if (!sum) return 84;
    }
    return 0;
}
