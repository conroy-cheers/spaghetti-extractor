#include <stdlib.h>
#include <pthread.h>
#include "observations.h"
#include "component-observation-names.h"
static unsigned long long calls[sizeof(names)/sizeof(*names)];
static pthread_once_t report_once=PTHREAD_ONCE_INIT;
static void register_report(void) {
    if (atexit(portable_component_report)) abort();
}
void portable_component_report(void) {
    const char *path=getenv("SPX_COMPONENT_COUNTS");
    if (!path || !*path) return;
    FILE *out=fopen(path,"w");
    if (!out) { perror("component observations"); return; }
    fputs("{",out);
    for (unsigned i=0;i<sizeof(names)/sizeof(*names);++i)
        fprintf(out,"%s\"%s\":%llu",i ? "," : "",names[i],__atomic_load_n(&calls[i],__ATOMIC_RELAXED));
    fputs("}\n",out);
    if (fclose(out)) perror("component observations");
}
void portable_component_entry(const char *name, unsigned *cached_slot) {
    pthread_once(&report_once,register_report);
    /* Resolve once per entry. Stable names keep unrelated binding C unchanged
     * when the selected component list grows; warm calls still index directly. */
    unsigned slot=__atomic_load_n(cached_slot,__ATOMIC_RELAXED);
    if (!slot) {
        for (unsigned i=0;i<sizeof(names)/sizeof(*names);++i) {
            if (!strcmp(name,names[i])) { slot=i+1; break; }
        }
        if (!slot) abort();
        __atomic_store_n(cached_slot,slot,__ATOMIC_RELAXED);
    }
    unsigned index=slot-1;
    if (index>=sizeof(names)/sizeof(*names)) abort();
    __atomic_fetch_add(&calls[index],1,__ATOMIC_RELAXED);
}
