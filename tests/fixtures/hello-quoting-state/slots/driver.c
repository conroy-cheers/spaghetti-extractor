/* Finite controlled comparison of the complete retained quoting/free bodies.
 * Memory synchronization below is a fixture relation, never proof authority. */
#include "behavioral-c.h"
#include "portable-component-implementation.h"
#include "quote-objects.h"
#include "growth-config.h"
#if HELLO_REAL_GROWTH
#include "runtime.h"
#include "comparison-services.h"
#endif
#include <inttypes.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BASE = 0x400000, MEMORY_SIZE = 0x50000, TABLE_GLOBAL = 0x420050,
    INITIAL_TABLE = 0x420054, COUNT_GLOBAL = 0x42005c, INITIAL_BUFFER = 0x4300c0,
    IAT = 0x4321e4, ERRNO = 0x440040, OPTIONS = 0x440080, BUFFER_BASE = 0x444000,
    STACK = 0x448000, RETURN_WORD = 0x401234, ERRNO_TARGET = 0x401111,
    TABLES = 4, SLOTS = 16, BUFFERS = 24, BUFFER_SIZE = 64, EVENTS = 100 };
enum { EV_ERRNO = 1, EV_GROW, EV_CLEAR, EV_QUOTE, EV_RELEASE, EV_FREE, EV_ALLOCATE, EV_ABORT, EV_RESIZE, EV_GROW_FAILED };

struct spx_opaque_quote_bytes_v5 { uint32_t address; };
typedef struct spx_opaque_quote_table_v5 Slot;
typedef struct spx_opaque_quote_word_v5 Word;
typedef struct spx_opaque_quote_bytes_v5 Buffer;

struct event { uint32_t kind, arguments[10], observed[8]; };
struct world {
    unsigned char memory[MEMORY_SIZE];
    Slot initial, tables[TABLES][SLOTS];
    Buffer buffers[BUFFERS];
    struct spx_opaque_quote_options_v5 options;
    struct spx_opaque_quote_state_v5 state;
    uint32_t alive[BUFFERS], generation[BUFFERS], table_alive[TABLES];
    uint32_t table_sizes[TABLES], growth_count_cell;
    uint32_t allocation, growth, errno_calls, quote_calls;
    uint32_t needed, extra, relocate, alternate_errno, mutate_options, free_errno;
    uint32_t fail_grow, fail_allocate, slot_index, result, outcome;
    struct event events[EVENTS];
    uint32_t event_count, sites[16];
    jmp_buf terminal;
};

spx_step_result spx_sub_00001b34(spx_runtime *, spx_machine_state *, uint32_t);
#if HELLO_REAL_GROWTH
spx_step_result spx_sub_000063ac(spx_runtime *, spx_machine_state *, uint32_t);
#endif
void fixture_source_release(void *, uint32_t);

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "fixture domain error: %s\n", message); exit(2); }
}

static uint32_t memory_read(void *context, uint32_t address, uint32_t width, uint32_t *fault) {
    struct world *w = context;
    if (address < BASE || width > 4U || width == 0U || address-BASE > MEMORY_SIZE-width) {
        *fault = 1; return 0;
    }
    uint32_t value = 0;
    for (uint32_t i = 0; i < width; i++) value |= (uint32_t)w->memory[address-BASE+i] << (i*8U);
    return value;
}

static void memory_write(void *context, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
    struct world *w = context;
    if (address < BASE || width > 4U || width == 0U || address-BASE > MEMORY_SIZE-width) {
        *fault = 1; return;
    }
    for (uint32_t i = 0; i < width; i++) w->memory[address-BASE+i] = (unsigned char)(value >> (i*8U));
}

uint32_t fixture_load(void *world, uint32_t address) {
    uint32_t fault = 0, result = memory_read(world, address, 4, &fault);
    require(!fault, "word read outside arena"); return result;
}

void fixture_store(void *world, uint32_t address, uint32_t value) {
    uint32_t fault = 0; memory_write(world, address, 4, value, &fault);
    require(!fault, "word write outside arena");
}

static uint32_t table_address(uint32_t i) { return 0x441000U + i*0x100U; }
static uint32_t buffer_address(uint32_t i) { return i == 0U ? INITIAL_BUFFER : BUFFER_BASE+i*BUFFER_SIZE; }
static Buffer *buffer(struct world *w, uint32_t address) {
    if (!address) return NULL;
    for (uint32_t i = 0; i < BUFFERS; i++) if (w->buffers[i].address == address) return &w->buffers[i];
    require(0, "unmapped buffer identity"); return NULL;
}
static uint32_t buffer_id(const Buffer *value) { return value ? value->address : 0U; }
static Slot *table(struct world *w, uint32_t address) {
    if (!address) return NULL;
    if (address == INITIAL_TABLE) return &w->initial;
    for (uint32_t i = 0; i < TABLES; i++) if (address == table_address(i)) return w->tables[i];
    require(0, "unmapped table identity"); return NULL;
}
static uint32_t table_id(struct world *w, const Slot *value) {
    if (!value) return 0;
    if (value == &w->initial) return INITIAL_TABLE;
    for (uint32_t i = 0; i < TABLES; i++) if (value == w->tables[i]) return table_address(i);
    require(0, "unknown logical table"); return 0;
}
static void slot_read(struct world *w, Slot *slot, uint32_t address) {
    slot->size = fixture_load(w, address); slot->buffer = buffer(w, fixture_load(w, address+4U));
}
static void slot_write(struct world *w, const Slot *slot, uint32_t address) {
    fixture_store(w, address, slot->size); fixture_store(w, address+4U, buffer_id(slot->buffer));
}

/* A finite explicit relation, with disjoint scalar/record storage. Buffer
 * identities may alias each other; arbitrary partial typed-record aliases are
 * outside this experiment and still require checked byte-level transport. */
static void to_objects(struct world *w) {
    slot_read(w, &w->initial, INITIAL_TABLE);
    for (uint32_t i = 0; i < TABLES; i++) for (uint32_t j = 0; j < SLOTS; j++)
        slot_read(w, &w->tables[i][j], table_address(i)+8U*j);
    w->options.style = fixture_load(w, OPTIONS); w->options.flags = fixture_load(w, OPTIONS+4U);
    for (uint32_t i = 0; i < 8; i++) w->options.mask.words[i] = fixture_load(w, OPTIONS+8U+4U*i);
    w->options.left_quote = buffer(w, fixture_load(w, OPTIONS+40U));
    w->options.right_quote = buffer(w, fixture_load(w, OPTIONS+44U));
    w->state.table = table(w, fixture_load(w, TABLE_GLOBAL));
    w->state.count = fixture_load(w, COUNT_GLOBAL);
    w->state.initial_table = &w->initial; w->state.initial_buffer = &w->buffers[0];
}
static void to_memory(struct world *w) {
    slot_write(w, &w->initial, INITIAL_TABLE);
    for (uint32_t i = 0; i < TABLES; i++) for (uint32_t j = 0; j < SLOTS; j++)
        slot_write(w, &w->tables[i][j], table_address(i)+8U*j);
    fixture_store(w, OPTIONS, w->options.style); fixture_store(w, OPTIONS+4U, w->options.flags);
    for (uint32_t i = 0; i < 8; i++) fixture_store(w, OPTIONS+8U+4U*i, w->options.mask.words[i]);
    fixture_store(w, OPTIONS+40U, buffer_id(w->options.left_quote));
    fixture_store(w, OPTIONS+44U, buffer_id(w->options.right_quote));
    fixture_store(w, TABLE_GLOBAL, table_id(w, w->state.table)); fixture_store(w, COUNT_GLOBAL, w->state.count);
}

static struct event *event(struct world *w, uint32_t kind) {
    require(w->event_count < EVENTS, "event capacity");
    struct event *e = &w->events[w->event_count++]; memset(e, 0, sizeof *e); e->kind = kind;
    e->observed[0] = fixture_load(w, TABLE_GLOBAL); e->observed[1] = fixture_load(w, COUNT_GLOBAL);
    if (w->slot_index < e->observed[1] && w->slot_index < SLOTS) {
        e->observed[2] = fixture_load(w, e->observed[0]+8U*w->slot_index);
        e->observed[3] = fixture_load(w, e->observed[0]+8U*w->slot_index+4U);
    }
    for (uint32_t i = 0; i < 3; i++) e->observed[4+i] = fixture_load(w, ERRNO+4U*i);
    e->observed[7] = fixture_load(w, OPTIONS);
    return e;
}
static void terminate(struct world *w, uint32_t reason) { w->outcome = reason; longjmp(w->terminal, 1); }

uint32_t fixture_errno(void *context) {
    struct world *w = context;
    uint32_t result = ERRNO+4U*(w->alternate_errno ? w->errno_calls%3U : 0U);
    event(w, EV_ERRNO)->arguments[0] = result; w->errno_calls++;
    return result;
}
void fixture_free(void *context, uint32_t address) {
    struct world *w = context; event(w, EV_FREE)->arguments[0] = address;
    if (address) {
        Buffer *b = buffer(w, address); uint32_t i = (uint32_t)(b-w->buffers);
        require(i > 0U && w->alive[i], "free requires a current nonstatic allocation");
        w->alive[i] = 0; w->generation[i]++;
        memset(w->memory+address-BASE, 0xdd, BUFFER_SIZE);
    }
    if (w->free_errno) for (uint32_t i = 0; i < 3; i++) fixture_store(w, ERRNO+4U*i, 91U+i);
}
static void growth_entry(struct world *w, uint32_t old, uint32_t count, uint32_t additional, uint32_t maximum, uint32_t width) {
    struct event *e = event(w, EV_GROW);
    e->arguments[0] = old; e->arguments[1] = count; e->arguments[2] = additional;
    e->arguments[3] = maximum; e->arguments[4] = width;
    require(width == 8U && maximum == 2147483647U, "xpalloc physical element size or limit");
}
#if HELLO_REAL_GROWTH
static uint32_t resize_table(void *context, uint32_t old, uint32_t bytes, uint32_t count) {
    struct world *w = context; struct event *e = event(w, EV_RESIZE);
    e->arguments[0] = old; e->arguments[1] = bytes; e->arguments[2] = count;
    require(bytes > 0 && bytes <= SLOTS*8U && bytes%8U == 0, "physical table allocation extent");
    if (w->fail_grow) terminate(w, 2);
    require(w->growth < TABLES, "table identity capacity");
    uint32_t result = old && !w->relocate ? old : table_address(w->growth++);
    if (old) {
        uint32_t index = (old-table_address(0))/0x100U;
        require(index<TABLES && w->table_alive[index] && w->table_sizes[index]<=bytes, "live growing table");
        if (result != old) {
            memcpy(w->memory+result-BASE,w->memory+old-BASE,w->table_sizes[index]);
            w->table_alive[index] = 0;
        }
    }
    uint32_t index = (result-table_address(0))/0x100U;
    w->table_alive[index] = 1; w->table_sizes[index] = bytes;
    return result;
}
static void growth_failed(void *context, uint32_t count) {
    struct world *w = context; event(w, EV_GROW_FAILED)->arguments[0] = count; terminate(w, 2);
}
#else
static uint32_t grow(struct world *w, uint32_t old, uint32_t *count, uint32_t additional, uint32_t maximum, uint32_t width) {
    growth_entry(w, old, *count, additional, maximum, width);
    if (w->fail_grow) terminate(w, 2);
    uint32_t next = *count+additional+w->extra;
    require(next <= SLOTS && w->growth < TABLES, "finite table capacity");
    uint32_t result = old && !w->relocate ? old : table_address(w->growth++);
    if (old && result != old) {
        memcpy(w->memory+result-BASE, w->memory+old-BASE, *count*8U);
        w->table_alive[(old-table_address(0))/0x100U] = 0;
    }
    w->table_alive[(result-table_address(0))/0x100U] = 1;
    *count = next; return result;
}
#endif
static void clear(struct world *w, uint32_t address, uint32_t byte, uint32_t size) {
    struct event *e = event(w, EV_CLEAR); e->arguments[0] = address; e->arguments[1] = byte; e->arguments[2] = size;
    require(address >= table_address(0) && address+size <= table_address(TABLES-1)+SLOTS*8U && byte == 0, "clear span");
    memset(w->memory+address-BASE, (int)byte, size);
}
static uint32_t quote(struct world *w, const uint32_t args[9]) {
    struct event *e = event(w, EV_QUOTE); memcpy(e->arguments, args, 9U*sizeof(uint32_t));
    require(args[6] == OPTIONS+8U, "quote mask correspondence");
    uint32_t n = w->needed == UINT32_MAX ? BUFFER_SIZE : w->needed+1U;
    if (n > args[1]) n = args[1];
    if (n > BUFFER_SIZE) n = BUFFER_SIZE;
    if (n) {
        require(args[0] != 0 && args[2] != 0, "quote readable/writable buffers");
        (void)buffer(w, args[0]); (void)buffer(w, args[2]);
        for (uint32_t i = 0; i < n; i++)
            w->memory[args[0]-BASE+i] = (unsigned char)(w->memory[args[2]-BASE+(i%BUFFER_SIZE)]+args[4]+i);
    }
    if (w->mutate_options) {
        fixture_store(w, OPTIONS, fixture_load(w, OPTIONS)+1U);
        fixture_store(w, OPTIONS+4U, fixture_load(w, OPTIONS+4U)^0x32U);
        fixture_store(w, OPTIONS+40U, buffer_address(2));
    }
    w->quote_calls++; return w->needed;
}
static uint32_t allocate(struct world *w, uint32_t size) {
    event(w, EV_ALLOCATE)->arguments[0] = size;
    if (w->fail_allocate) terminate(w, 3);
    uint32_t i = 4U+w->allocation++; require(i < BUFFERS, "buffer capacity");
    w->alive[i] = 1; w->generation[i]++;
    memset(w->memory+buffer_address(i)-BASE, 0xac, BUFFER_SIZE);
    return buffer_address(i);
}

static uint32_t source_errno_read(void *context, spx_ref_v5 reference, uint64_t offset,
                                  uint32_t width, uint64_t *value) {
    if (offset != 0U || width != 4U || !value) return SPX_REF_FAULT;
    *value = fixture_load(context, (uint32_t)reference.object);
    return SPX_REF_OK;
}
static uint32_t source_errno_write(void *context, spx_ref_v5 reference, uint64_t offset,
                                   uint32_t width, uint64_t value) {
    if (offset != 0U || width != 4U) return SPX_REF_FAULT;
    fixture_store(context, (uint32_t)reference.object, (uint32_t)value);
    to_objects(context);
    return SPX_REF_OK;
}
static spx_view_v5 source_errno(void *context) {
    struct world *w = context; to_memory(w); uint32_t address = fixture_errno(w); to_objects(w);
    return (spx_view_v5){.base = {.object = address, .extent = 4U, .permissions = 3U},
        .extent = 4U, .element_width = 1U, .access_context = w,
        .read = source_errno_read, .write = source_errno_write};
}
static Slot *source_grow(void *context, Slot *old, Word *count, uint32_t additional, uint32_t maximum) {
    struct world *w = context; to_memory(w);
#if HELLO_REAL_GROWTH
    growth_entry(w, table_id(w,old), count->value, additional, maximum, 8U);
    const struct allocation_adapter adapter = {w, resize_table, growth_failed};
    uint32_t result = fixture_source_growth(&adapter, table_id(w,old), &count->value, additional, maximum, 8U);
#else
    uint32_t result = grow(w, table_id(w, old), &count->value, additional, maximum, 8U);
#endif
    to_objects(w); return table(w, result);
}
static void source_clear(void *context, Slot *slots, uint32_t first, uint32_t count) {
    struct world *w = context; to_memory(w); clear(w, table_id(w, slots)+8U*first, 0, count*8U); to_objects(w);
}
static uint32_t source_quote(void *context, Buffer *output, uint32_t capacity, Buffer *argument,
        uint32_t size, uint32_t style, uint32_t flags, struct spx_opaque_quote_mask_v5 *mask, Buffer *left, Buffer *right) {
    struct world *w = context; require(mask == &w->options.mask, "logical mask identity"); to_memory(w);
    uint32_t args[9] = {buffer_id(output), capacity, buffer_id(argument), size, style, flags, OPTIONS+8U, buffer_id(left), buffer_id(right)};
    uint32_t result = quote(w, args); to_objects(w); return result;
}
static void source_release(void *context, Buffer *value) {
    struct world *w = context; to_memory(w); event(w, EV_RELEASE)->arguments[0] = buffer_id(value);
    fixture_source_release(w, buffer_id(value)); to_objects(w);
}
static Buffer *source_allocate(void *context, uint32_t size) {
    struct world *w = context; to_memory(w); uint32_t result = allocate(w, size); to_objects(w); return buffer(w, result);
}
static void source_abort(void *context) {
    struct world *w = context; to_memory(w); event(w, EV_ABORT); terminate(w, 1);
}

spx_call_status spx_invoke_call(spx_runtime *rt, const spx_call_event *call,
                               const spx_machine_state *input, spx_machine_state *output) {
    struct world *w = rt->context; *output = *input;
    static const uint32_t sites[] = {0x4ec6,0x4f1b,0x4f54,0x4fa6,0x4fc3,0x4fd3,0x5017,0x501e,0x504c,0x14645,
                                    0x1b3f,0x1b41,0x1b49,0x1b51,0x1b63,0x1b6f};
    for (uint32_t i = 0; i < 16; i++) if (sites[i] == call->source_rva) w->sites[i]++;
    if (call->kind == SPX_CALL_INDIRECT) {
        require(call->target_rva == ERRNO_TARGET, "captured errno target"); output->eax = fixture_errno(w);
    } else if (call->target_rva == 0x63ac) {
        uint32_t pointer = fixture_load(w, input->esp+4U), count = fixture_load(w, pointer);
#if HELLO_REAL_GROWTH
        growth_entry(w, fixture_load(w,input->esp), count, fixture_load(w,input->esp+8U),
            fixture_load(w,input->esp+12U), fixture_load(w,input->esp+16U));
        w->growth_count_cell = pointer;
        output->esp -= 4U; fixture_store(w, output->esp, BASE+call->return_rva);
        spx_step_result result = spx_sub_000063ac(rt, output, 0x63ac);
        require(result.kind == SPX_RETURN && result.value == BASE+call->return_rva
            && output->esp == input->esp, "actual xpalloc return");
    } else if (call->target_rva == 0x6257) {
        output->eax = resize_table(w, fixture_load(w,input->esp), fixture_load(w,input->esp+4U),
            fixture_load(w,w->growth_count_cell));
    } else if (call->target_rva == 0x658c) {
        growth_failed(w, fixture_load(w,w->growth_count_cell));
#else
        output->eax = grow(w, fixture_load(w, input->esp), &count,
            fixture_load(w, input->esp+8U), fixture_load(w, input->esp+12U), fixture_load(w, input->esp+16U));
        fixture_store(w, pointer, count);
#endif
    } else if (call->target_rva == 0x36ea) {
        uint32_t args[9] = {input->eax, input->edx, input->ecx};
        for (uint32_t i = 3; i < 9; i++) args[i] = fixture_load(w, input->esp+(i-3U)*4U);
        output->eax = quote(w, args);
    } else if (call->target_rva == 0x1b34) {
        event(w, EV_RELEASE)->arguments[0] = fixture_load(w, input->esp);
        output->esp -= 4U; fixture_store(w, output->esp, BASE+call->return_rva);
        spx_step_result result = spx_sub_00001b34(rt, output, 0x1b34);
        require(result.kind == SPX_RETURN && result.value == BASE+call->return_rva
                && output->esp == input->esp, "actual free wrapper return");
    } else if (call->target_rva == 0x6255) output->eax = allocate(w, fixture_load(w, input->esp));
    else if (call->symbol && !strcmp(call->symbol, "memset")) {
        clear(w, fixture_load(w, input->esp), fixture_load(w, input->esp+4U), fixture_load(w, input->esp+8U));
        output->eax = fixture_load(w, input->esp);
    } else if (call->symbol && !strcmp(call->symbol, "free")) fixture_free(w, fixture_load(w, input->esp));
    else if (call->symbol && !strcmp(call->symbol, "abort")) { event(w, EV_ABORT); terminate(w, 1); }
    else { fprintf(stderr, "unhandled call %x target %x\n", call->source_rva, call->target_rva); exit(2); }
    return SPX_CALL_OK;
}

static void initialize(struct world *w, uint32_t seed) {
    memset(w, 0, sizeof *w);
    for (uint32_t i = 0; i < BUFFERS; i++) {
        w->buffers[i].address = buffer_address(i); w->alive[i] = i < 4U; w->generation[i] = 1;
        for (uint32_t j = 0; j < BUFFER_SIZE; j++) w->memory[buffer_address(i)-BASE+j] = (unsigned char)(seed+i+j);
    }
    /* New allocation bytes need not start at zero. Keep representable stale
     * records so skipping the original clear is observably incorrect. */
    for (uint32_t i = 0; i < TABLES; i++) for (uint32_t j = 0; j < SLOTS; j++) {
        fixture_store(w, table_address(i)+8U*j, seed+100U+j);
        fixture_store(w, table_address(i)+8U*j+4U, buffer_address(1));
    }
    fixture_store(w, TABLE_GLOBAL, INITIAL_TABLE); fixture_store(w, COUNT_GLOBAL, 1);
    fixture_store(w, INITIAL_TABLE, 8); fixture_store(w, INITIAL_TABLE+4U, INITIAL_BUFFER);
    fixture_store(w, IAT, ERRNO_TARGET); fixture_store(w, OPTIONS, seed%11U); fixture_store(w, OPTIONS+4U, seed*2U);
    for (uint32_t i = 0; i < 8; i++) fixture_store(w, OPTIONS+8U+4U*i, seed+i);
    fixture_store(w, OPTIONS+40U, buffer_address(2)); fixture_store(w, OPTIONS+44U, buffer_address(3));
    for (uint32_t i = 0; i < 3; i++) fixture_store(w, ERRNO+4U*i, seed+17U+i);
    to_objects(w);
}
static void run(struct world *w, uint32_t source, uint32_t index, uint32_t argument, uint32_t seed) {
    w->slot_index = index; w->outcome = 0; w->result = 0; w->event_count = 0;
#if HELLO_REAL_GROWTH
    uint32_t handler = source ? spx_service_handler_begin() : 0;
#endif
    if (setjmp(w->terminal)) {
#if HELLO_REAL_GROWTH
        /* Only allocator failures interrupt a generated service scope. Other
         * fixture terminal outcomes occur outside the selected growth unit. */
        if (source && w->outcome == 2) spx_service_handler_catch(handler,"nomem");
        if (source) spx_service_handler_end(handler);
#endif
        return;
    }
    if (source) {
        const spx_quote_slots_services_v5 services = {.context = w, .errno_cell = source_errno,
            .grow_slots = source_grow, .clear_slots = source_clear, .quote_buffer = source_quote,
            .release_buffer = source_release, .allocate_buffer = source_allocate, .invalid_slot = source_abort};
        spx_quote_slots_context_v5 context = {.services = &services, .state = {.slots = &w->state}};
        to_objects(w);
        w->result = buffer_id(quote_slots(&context, index, buffer(w, argument), UINT32_MAX, &w->options));
        to_memory(w);
    } else {
        spx_runtime runtime = {.context = w, .image_base = BASE, .read = memory_read, .write = memory_write};
        spx_machine_state state = {.eax = index, .edx = argument, .ecx = UINT32_MAX,
            .esp = STACK, .ebx = seed+23U, .ebp = seed+29U, .esi = seed+31U, .edi = seed+37U};
        fixture_store(w, STACK, RETURN_WORD); fixture_store(w, STACK+4U, OPTIONS);
        spx_step_result result = spx_sub_00004eb3(&runtime, &state, 0x4eb3);
        require(result.kind == SPX_RETURN && result.value == RETURN_WORD && state.esp == STACK+4U,
                "complete quoting return and stack");
        require(state.ebx == seed+23U && state.ebp == seed+29U && state.esi == seed+31U && state.edi == seed+37U,
                "quoting preserved registers");
        w->result = state.eax;
    }
#if HELLO_REAL_GROWTH
    if (source) spx_service_handler_end(handler);
#endif
}
static int compare(struct world *a, struct world *b, uint32_t scenario, uint32_t invocation) {
    const char *failure = NULL;
    if (a->outcome != b->outcome || a->result != b->result) failure = "outcome/result";
    else if (a->event_count != b->event_count || memcmp(a->events, b->events, a->event_count*sizeof a->events[0])) failure = "service trace/state";
    else if (memcmp(a->memory, b->memory, STACK-BASE-256U)) failure = "public bytes";
    else if (memcmp(a->alive,b->alive,sizeof a->alive) || memcmp(a->generation,b->generation,sizeof a->generation)
             || memcmp(a->table_alive,b->table_alive,sizeof a->table_alive)) failure = "object lifetime";
    if (failure) {
        fprintf(stderr,"scenario %u invocation %u differs: %s; outcomes %u/%u results %x/%x events %u/%u\n",
            scenario,invocation,failure,a->outcome,b->outcome,a->result,b->result,a->event_count,b->event_count);
        for (uint32_t i=0;i<a->event_count || i<b->event_count;i++) {
            struct event *x=&a->events[i],*y=&b->events[i];
            if (memcmp(x,y,sizeof *x)) {
                fprintf(stderr,"event %u kind %u/%u\n",i,x->kind,y->kind);
                for(uint32_t j=0;j<10;j++) fprintf(stderr," arg%u=%x/%x",j,x->arguments[j],y->arguments[j]);
                for(uint32_t j=0;j<8;j++) fprintf(stderr," state%u=%x/%x",j,x->observed[j],y->observed[j]);
                fputc('\n',stderr); break;
            }
        }
        return 1;
    }
    return 0;
}
static void configure(struct world *w, uint32_t scenario, uint32_t step, uint32_t source) {
    uint32_t index = step == 0 ? 0 : step == 1 ? 3 : step == 2 ? 7 : 3;
#if HELLO_REAL_GROWTH
    if (step == 2) index = 15;
#endif
    w->needed = step == 0 ? (scenario&1U ? 8U : 2U) : step == 3 ? 19U : 11U;
    if (scenario >= 112U && scenario < 128U && step == 0) index = scenario&1U ? UINT32_MAX : INT32_MAX;
    if (scenario >= 96U && scenario < 104U) w->needed = UINT32_MAX;
    w->extra=(scenario>>1U)&1U; w->relocate=(scenario>>2U)&1U;
    w->alternate_errno=(scenario>>3U)&1U; w->mutate_options=(scenario>>4U)&1U; w->free_errno=(scenario>>5U)&1U;
    w->fail_grow=scenario>=104U && scenario<108U && step==1;
    w->fail_allocate=scenario>=108U && scenario<112U;
#if HELLO_REAL_GROWTH
    if (scenario>=128U && scenario<136U && step==2) w->fail_grow=1;
    if (scenario>=136U && step==3) w->fail_allocate=1;
#endif
    uint32_t argument = scenario&64U ? fixture_load(w, INITIAL_TABLE+4U) : buffer_address(1);
    run(w,source,index,argument,scenario+step*100U);
}
static void print_words(const uint32_t *words, uint32_t count) {
    putchar('['); for (uint32_t i=0;i<count;i++) printf("%s%" PRIu32,i?",":"",words[i]); putchar(']');
}
static void print_bytes(struct world *w, uint32_t address, uint32_t count) {
    for (uint32_t i=0;i<count;i++) printf("%02x",w->memory[address-BASE+i]);
}
static void observe(struct world *w) {
    printf("{\"outcome\":%u,\"result\":%u,\"storage\":\"",w->outcome,w->result);
    print_bytes(w,TABLE_GLOBAL,16); print_bytes(w,ERRNO,12); print_bytes(w,OPTIONS,48);
    for(uint32_t i=0;i<TABLES;i++) print_bytes(w,table_address(i),8U*SLOTS);
    for(uint32_t i=0;i<BUFFERS;i++) print_bytes(w,buffer_address(i),BUFFER_SIZE);
    printf("\",\"alive\":");print_words(w->alive,BUFFERS);
    printf(",\"generations\":");print_words(w->generation,BUFFERS);
    printf(",\"tables_alive\":");print_words(w->table_alive,TABLES);
#if HELLO_REAL_GROWTH
    printf(",\"table_sizes\":");print_words(w->table_sizes,TABLES);
#endif
    printf(",\"events\":[");
    for(uint32_t i=0;i<w->event_count;i++) {
        struct event *e=&w->events[i]; printf("%s{\"kind\":%u,\"arguments\":",i?",":"",e->kind);
        print_words(e->arguments,10);printf(",\"state\":");print_words(e->observed,8);putchar('}');
    }
    printf("]}");
}
int main(int argc, char **argv) {
    if (argc == 3) {
        require(!strcmp(argv[1],"original") || !strcmp(argv[1],"source"),"comparison side");
        char *end=NULL; unsigned long scenario=strtoul(argv[2],&end,10);
        require(end != argv[2] && *end == '\0' && scenario<HELLO_SCENARIOS,"scenario number");
        struct world *w=malloc(sizeof *w);require(w != NULL,"fixture allocation");initialize(w,(uint32_t)scenario);
        printf("{\"invocations\":[");
        for(uint32_t step=0;step<4;step++) {
            configure(w,(uint32_t)scenario,step,!strcmp(argv[1],"source"));
            if(step) putchar(',');
            observe(w);if(w->outcome) break;
        }
        printf("]}\n");free(w);return 0;
    }
    require(argc == 1,"expected original/source and a scenario");
    struct world *original = malloc(sizeof *original), *source = malloc(sizeof *source);
    require(original && source, "fixture allocation");
    uint32_t cases=0, covered[16]={0};
    for (uint32_t scenario=0;scenario<HELLO_SCENARIOS;scenario++) {
        initialize(original,scenario); initialize(source,scenario);
        for (uint32_t step=0;step<4;step++) {
            configure(original,scenario,step,0); configure(source,scenario,step,1);
            if(compare(original,source,scenario,step)) return 1;
            for(uint32_t i=0;i<16;i++) covered[i] |= original->sites[i] != 0;
            cases++; if(original->outcome) break;
        }
    }
    printf("{\"status\":\"finite comparisons matched\",\"cases\":%u,\"parent_call_sites\":[",cases);
    for(uint32_t i=0;i<10;i++) printf("%s%u",i?",":"",covered[i]);
    printf("],\"free_call_sites\":[");
    for(uint32_t i=10;i<16;i++) printf("%s%u",i>10?",":"",covered[i]);
    printf("],\"logical_slot_bytes\":%zu,\"logical_options_bytes\":%zu,\"activation_authorized\":false}\n",
           sizeof(Slot),sizeof(struct spx_opaque_quote_options_v5));
    free(original);free(source);return 0;
}
