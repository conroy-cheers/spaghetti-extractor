#include "bochs.h"
#include "cpu/cpu.h"
#include "cpu/decoder/fetchdecode.h"
#include "gui/siminterface.h"
#include "memory/memory-bochs.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "protocol.h"

extern bxIAOpcodeTable BxOpcodesTable[];
extern int fetchDecode32(const Bit8u *iptr, bool is_32,
                         bxInstruction_c *instruction,
                         unsigned remaining_in_page);

namespace {

struct memory_region_t {
  Bit32u address;
  Bit32u length;
  Bit32u data_offset;
  bool writable;
};

struct x87_state_t {
  Bit16u control_word;
  Bit16u status_word;
  Bit16u tag_word;
  Bit16u last_opcode;
  Bit32u instruction_pointer;
  Bit32u data_pointer;
  Bit8u registers[8][10];
};

struct request_t {
  Bit32u sequence;
  Bit8u bytes[BC_INSTRUCTION_SLOT_BYTES];
  unsigned length;
  Bit32u eip;
  Bit32u eflags;
  Bit32u eax;
  Bit32u ebx;
  Bit32u ecx;
  Bit32u edx;
  Bit32u esi;
  Bit32u edi;
  Bit32u ebp;
  Bit32u esp;
  Bit32u requirements;
  Bit16u fs_selector;
  Bit32u fs_base;
  Bit16u ia_opcode;
  unsigned memory_region_count;
  unsigned memory_bytes_count;
  memory_region_t memory_regions[BC_MAX_MEMORY_REGIONS];
  Bit8u memory_bytes[BC_MAX_MEMORY_BYTES];
  x87_state_t x87;
};

FILE *input_file = NULL;
FILE *output_file = NULL;
request_t pending_request;
bool pending = false;
bool active = false;
bool saw_io = false;
bool saw_system = false;
bool saw_branch = false;
const char *memory_violation = NULL;
const char *observed_control = "fallthrough";
bool input_ended = false;
Bit32u resume_eip = 0;
Bit32u next_sequence = 0;
bx_segment_reg_t saved_segments[6];
bool case_segments_active = false;

void private_fatal(const char *detail)
{
  if (output_file != NULL) {
    fprintf(output_file, "FATAL\t%s\n", detail);
    fflush(output_file);
  }
  fprintf(stderr, "bochs-conformance: %s\n", detail);
  BX_EXIT(2);
  abort();
}

bool parse_hex_digit(char value, unsigned *digit)
{
  if (value >= '0' && value <= '9') {
    *digit = unsigned(value - '0');
    return true;
  }
  if (value >= 'a' && value <= 'f') {
    *digit = unsigned(value - 'a') + 10;
    return true;
  }
  return false;
}

bool parse_hex32(const std::string &text, Bit32u *result)
{
  if (text.size() != 8) return false;
  Bit32u value = 0;
  for (size_t index = 0; index < text.size(); ++index) {
    unsigned digit;
    if (!parse_hex_digit(text[index], &digit)) return false;
    value = (value << 4) | digit;
  }
  *result = value;
  return true;
}

bool parse_hex16(const std::string &text, Bit16u *result)
{
  if (text.size() != 4) return false;
  Bit16u value = 0;
  for (size_t index = 0; index < text.size(); ++index) {
    unsigned digit;
    if (!parse_hex_digit(text[index], &digit)) return false;
    value = Bit16u((value << 4) | digit);
  }
  *result = value;
  return true;
}

bool parse_fixed_bytes(const std::string &text, Bit8u *result, unsigned length)
{
  if (text.size() != length * 2) return false;
  for (unsigned index = 0; index < length; ++index) {
    unsigned high, low;
    if (!parse_hex_digit(text[index * 2], &high) ||
        !parse_hex_digit(text[index * 2 + 1], &low)) {
      return false;
    }
    result[index] = Bit8u((high << 4) | low);
  }
  return true;
}

bool parse_bytes(const std::string &text, request_t *request)
{
  if (text.empty() ||
      text.size() > BC_INSTRUCTION_SLOT_BYTES * 2 ||
      (text.size() & 1) != 0) return false;
  request->length = unsigned(text.size() / 2);
  for (unsigned index = 0; index < request->length; ++index) {
    unsigned high, low;
    if (!parse_hex_digit(text[index * 2], &high) ||
        !parse_hex_digit(text[index * 2 + 1], &low)) {
      return false;
    }
    request->bytes[index] = Bit8u((high << 4) | low);
  }
  return true;
}

bool parse_x87(const std::string &text, x87_state_t *state)
{
  std::vector<std::string> fields;
  size_t start = 0;
  for (;;) {
    const size_t end = text.find(':', start);
    fields.push_back(text.substr(start, end - start));
    if (end == std::string::npos) break;
    start = end + 1;
  }
  if (fields.size() != 14 ||
      !parse_hex16(fields[0], &state->control_word) ||
      !parse_hex16(fields[1], &state->status_word) ||
      !parse_hex16(fields[2], &state->tag_word) ||
      !parse_hex16(fields[3], &state->last_opcode) ||
      !parse_hex32(fields[4], &state->instruction_pointer) ||
      !parse_hex32(fields[5], &state->data_pointer) ||
      state->last_opcode > 0x07ff) {
    return false;
  }
  for (unsigned index = 0; index < 8; ++index) {
    if (!parse_fixed_bytes(fields[6 + index], state->registers[index], 10))
      return false;
  }
  return true;
}

bool parse_memory_permissions(const std::string &text, bool *writable)
{
  if (text == "r" || text == "rx") {
    *writable = false;
    return true;
  }
  if (text == "rw" || text == "rwx") {
    *writable = true;
    return true;
  }
  return false;
}

bool parse_memory(const std::string &text, request_t *request)
{
  request->memory_region_count = 0;
  request->memory_bytes_count = 0;
  if (text == "-") return true;
  size_t start = 0;
  for (;;) {
    const size_t end = text.find(',', start);
    const std::string token = text.substr(start, end - start);
    const size_t first_colon = token.find(':');
    const size_t second_colon =
      first_colon == std::string::npos
        ? std::string::npos
        : token.find(':', first_colon + 1);
    if (first_colon == std::string::npos ||
        second_colon == std::string::npos ||
        token.find(':', second_colon + 1) != std::string::npos ||
        request->memory_region_count >= BC_MAX_MEMORY_REGIONS) {
      return false;
    }
    Bit32u address;
    bool writable;
    const std::string encoded = token.substr(second_colon + 1);
    if (!parse_hex32(token.substr(0, first_colon), &address) ||
        !parse_memory_permissions(
          token.substr(first_colon + 1, second_colon - first_colon - 1),
          &writable) ||
        encoded.empty() || (encoded.size() & 1) != 0) {
      return false;
    }
    const unsigned length = unsigned(encoded.size() / 2);
    if (length > BC_MAX_MEMORY_BYTES - request->memory_bytes_count ||
        address < BC_TEST_ADDRESS_MIN ||
        Bit64u(address) + length > BC_GUEST_RAM_END) {
      return false;
    }
    memory_region_t &region =
      request->memory_regions[request->memory_region_count++];
    region.address = address;
    region.length = length;
    region.data_offset = request->memory_bytes_count;
    region.writable = writable;
    for (unsigned index = 0; index < length; ++index) {
      unsigned high, low;
      if (!parse_hex_digit(encoded[index * 2], &high) ||
          !parse_hex_digit(encoded[index * 2 + 1], &low)) {
        return false;
      }
      request->memory_bytes[request->memory_bytes_count++] =
        Bit8u((high << 4) | low);
    }
    if (end == std::string::npos) break;
    start = end + 1;
    if (start == text.size()) return false;
  }
  for (unsigned left = 0; left < request->memory_region_count; ++left) {
    const memory_region_t &a = request->memory_regions[left];
    for (unsigned right = left + 1;
         right < request->memory_region_count; ++right) {
      const memory_region_t &b = request->memory_regions[right];
      if (a.address < Bit64u(b.address) + b.length &&
          b.address < Bit64u(a.address) + a.length) {
        return false;
      }
    }
  }
  return true;
}

std::vector<std::string> split_tabs(const std::string &line)
{
  std::vector<std::string> fields;
  size_t start = 0;
  for (;;) {
    size_t end = line.find('\t', start);
    fields.push_back(line.substr(start, end - start));
    if (end == std::string::npos) return fields;
    start = end + 1;
  }
}

const char *segment_override_scope(const request_t &request)
{
  for (unsigned index = 0; index < request.length; ++index) {
    switch (request.bytes[index]) {
      case 0x64:
        continue;
      case 0x26: case 0x2e: case 0x36: case 0x3e: case 0x65:
        return "segment_state_not_implemented";
      case 0x66: case 0x67: case 0xf0: case 0xf2: case 0xf3:
        continue;
      default:
        return NULL;
    }
  }
  return NULL;
}

const char *operand_scope(const bxIAOpcodeTable &opcode,
                          const bxInstruction_c &instruction)
{
  for (unsigned index = 0; index < 4; ++index) {
    const unsigned descriptor = opcode.src[index];
    const unsigned origin = BX_DISASM_SRC_ORIGIN(descriptor);
    const unsigned type = BX_DISASM_SRC_TYPE(descriptor);
    if (origin == BX_SRC_NONE) continue;
    if (origin == BX_SRC_BRANCH_OFFSET) continue;
    if (origin == BX_SRC_IMM && type == BX_DIRECT_PTR)
      return "far_control_not_implemented";
    if (origin == BX_SRC_VSIB) return "vector_memory_not_implemented";
    if (origin == BX_SRC_IMM && type >= BX_DIRECT_MEMREF_B &&
        type <= BX_DIRECT_MEMREF_Q) continue;
    if (origin == BX_SRC_IMPLICIT && type >= BX_RSIREF_B &&
        type <= BX_VEC_RDIREF) continue;
    if (type == BX_FPU_REG) continue;
    if (origin == BX_SRC_RM && !instruction.modC0() &&
        type == BX_NO_REGISTER) continue;
    if (origin == BX_SRC_RM && !instruction.modC0() &&
        (type == BX_GPR8 || type == BX_GPR16 ||
         type == BX_GPR32 || type == BX_GPR64)) continue;
    if (type == BX_SEGREG) return "segment_state_not_implemented";
    if (type == BX_CREG || type == BX_DREG) return "system_not_implemented";
    if (origin == BX_SRC_EAX || origin == BX_SRC_NNN || origin == BX_SRC_RM ||
        origin == BX_SRC_VVV) {
      if (type != BX_GPR8 && type != BX_GPR16 && type != BX_GPR32) {
        return "register_class_not_implemented";
      }
      continue;
    }
    if (origin == BX_SRC_IMM) continue;
    if (origin == BX_SRC_IMPLICIT && type == BX_USECL) continue;
    return "instruction_scope_not_implemented";
  }
  return NULL;
}

const char *review_instruction(request_t *request)
{
  bxInstruction_c instruction;
  memset(&instruction, 0, sizeof(instruction));
  if (fetchDecode32(request->bytes, true, &instruction, request->length) != 0 ||
      instruction.ilen() != request->length ||
      instruction.getIaOpcode() == BX_IA_ERROR) {
    return "instruction_not_implemented";
  }
  request->ia_opcode = instruction.getIaOpcode();
  const char *segment_scope = segment_override_scope(*request);
  if (segment_scope != NULL) return segment_scope;

  const bxIAOpcodeTable &opcode_info = BxOpcodesTable[request->ia_opcode];
  if ((opcode_info.opflags &
       (BX_PREPARE_MMX | BX_PREPARE_SSE | BX_PREPARE_AVX |
        BX_PREPARE_OPMASK | BX_PREPARE_EVEX | BX_PREPARE_AMX)) != 0) {
    return "register_class_not_implemented";
  }
  const char *scope = operand_scope(opcode_info, instruction);
  if (scope != NULL) return scope;
  return NULL;
}

bool read_request(request_t *request)
{
  static char buffer[BC_MAX_MEMORY_BYTES * 2 + 4096];
  if (fgets(buffer, sizeof(buffer), input_file) == NULL) {
    if (ferror(input_file)) private_fatal("private_input_read_failed");
    return false;
  }
  size_t length = strlen(buffer);
  if (length == 0) private_fatal("private_input_empty_read");
  if (buffer[length - 1] != '\n') {
    private_fatal("private_input_line_too_long_or_unterminated");
  }
  --length;
  buffer[length] = '\0';
  if (length != 0 && buffer[length - 1] == '\r') {
    private_fatal("private_input_contains_carriage_return");
  }
  std::vector<std::string> fields = split_tabs(buffer);
  if (fields.size() != 19 || fields[0] != "CASE" || fields[1] != "5") {
    fprintf(stderr,
      "bochs-conformance: private_input_schema_observed "
      "fields=%zu tag=%s version=%s\n",
      fields.size(),
      fields.empty() ? "<missing>" : fields[0].c_str(),
      fields.size() < 2 ? "<missing>" : fields[1].c_str());
    private_fatal("private_input_schema_mismatch");
  }
  if (!parse_hex32(fields[2], &request->sequence) ||
      !parse_bytes(fields[3], request) ||
      !parse_hex32(fields[4], &request->eip) ||
      !parse_hex32(fields[5], &request->eflags) ||
      !parse_hex32(fields[6], &request->eax) ||
      !parse_hex32(fields[7], &request->ebx) ||
      !parse_hex32(fields[8], &request->ecx) ||
      !parse_hex32(fields[9], &request->edx) ||
      !parse_hex32(fields[10], &request->esi) ||
      !parse_hex32(fields[11], &request->edi) ||
      !parse_hex32(fields[12], &request->ebp) ||
      !parse_hex32(fields[13], &request->esp) ||
      !parse_hex32(fields[14], &request->requirements) ||
      !parse_hex16(fields[15], &request->fs_selector) ||
      !parse_hex32(fields[16], &request->fs_base) ||
      !parse_memory(fields[17], request) ||
      !parse_x87(fields[18], &request->x87)) {
    private_fatal("private_input_value_invalid");
  }
  if (request->sequence != next_sequence++) {
    private_fatal("private_input_sequence_invalid");
  }
  return true;
}

void write_physical(Bit32u address, const void *data, unsigned length)
{
  const Bit8u *bytes = static_cast<const Bit8u *>(data);
  for (unsigned index = 0; index < length; ++index) {
    Bit8u value = bytes[index];
    BX_MEM(0)->writePhysicalPage(BX_CPU(0), address + index, 1, &value);
  }
}

void read_physical(Bit32u address, void *data, unsigned length)
{
  BX_MEM(0)->readPhysicalPage(BX_CPU(0), address, length, data);
}

void read_mailbox(struct bc_mailbox *mailbox)
{
  BX_MEM(0)->readPhysicalPage(
    BX_CPU(0), BC_MAILBOX_ADDRESS, sizeof(*mailbox), mailbox);
}

void write_mailbox(const request_t *request, Bit32u status)
{
  struct bc_mailbox mailbox;
  memset(&mailbox, 0, sizeof(mailbox));
  mailbox.resume_eip = resume_eip;
  mailbox.status = status;
  if (request != NULL) {
    mailbox.eip = request->eip;
    mailbox.eflags = request->eflags;
    mailbox.eax = request->eax;
    mailbox.ebx = request->ebx;
    mailbox.ecx = request->ecx;
    mailbox.edx = request->edx;
    mailbox.esi = request->esi;
    mailbox.edi = request->edi;
    mailbox.ebp = request->ebp;
    mailbox.esp = request->esp;
    mailbox.length = Bit8u(request->length);
  }
  write_physical(BC_MAILBOX_ADDRESS, &mailbox, sizeof(mailbox));
}

Bit64u read_little_u64(const Bit8u *bytes)
{
  Bit64u value = 0;
  for (unsigned index = 0; index < 8; ++index)
    value |= Bit64u(bytes[index]) << (index * 8);
  return value;
}

Bit16u read_little_u16(const Bit8u *bytes)
{
  return Bit16u(bytes[0]) | (Bit16u(bytes[1]) << 8);
}

void write_little_u64(Bit8u *bytes, Bit64u value)
{
  for (unsigned index = 0; index < 8; ++index)
    bytes[index] = Bit8u(value >> (index * 8));
}

void write_little_u16(Bit8u *bytes, Bit16u value)
{
  bytes[0] = Bit8u(value);
  bytes[1] = Bit8u(value >> 8);
}

void set_x87_state(BX_CPU_C *processor, const x87_state_t &state)
{
  i387_t &fpu = processor->the_i387;
  fpu.cwd = state.control_word;
  fpu.swd = state.status_word & ~Bit16u(0x3800);
  fpu.tos = Bit8u((state.status_word >> 11) & 7);
  fpu.twd = state.tag_word;
  fpu.foo = state.last_opcode;
  fpu.fip = state.instruction_pointer;
  fpu.fdp = state.data_pointer;

  // FCS/FDS are not represented by the corpus schema. Keep them deterministic;
  // forms whose result depends on either selector need a richer schema.
  fpu.fcs = 0;
  fpu.fds = 0;
  for (unsigned logical = 0; logical < 8; ++logical) {
    const unsigned physical = (fpu.tos + logical) & 7;
    fpu.st_space[physical].signif =
      read_little_u64(state.registers[logical]);
    fpu.st_space[physical].signExp =
      read_little_u16(state.registers[logical] + 8);
  }
}

void get_x87_state(BX_CPU_C *processor, x87_state_t *state)
{
  const i387_t &fpu = processor->the_i387;
  state->control_word = fpu.get_control_word();
  state->status_word = fpu.get_status_word();
  state->tag_word = fpu.get_tag_word();
  state->last_opcode = fpu.foo;
  state->instruction_pointer = Bit32u(fpu.fip);
  state->data_pointer = Bit32u(fpu.fdp);
  for (unsigned logical = 0; logical < 8; ++logical) {
    const unsigned physical = (fpu.tos + logical) & 7;
    write_little_u64(
      state->registers[logical], fpu.st_space[physical].signif);
    write_little_u16(
      state->registers[logical] + 8, fpu.st_space[physical].signExp);
  }
}

bool x87_state_equal(const x87_state_t &left, const x87_state_t &right)
{
  return left.control_word == right.control_word &&
         left.status_word == right.status_word &&
         left.tag_word == right.tag_word &&
         left.last_opcode == right.last_opcode &&
         left.instruction_pointer == right.instruction_pointer &&
         left.data_pointer == right.data_pointer &&
         memcmp(left.registers, right.registers, sizeof(left.registers)) == 0;
}

void emit_x87(unsigned cpu)
{
  x87_state_t state;
  get_x87_state(BX_CPU(cpu), &state);
  fprintf(output_file, "%04x:%04x:%04x:%04x:%08x:%08x",
    state.control_word,
    state.status_word,
    state.tag_word,
    state.last_opcode,
    state.instruction_pointer,
    state.data_pointer);
  for (unsigned reg = 0; reg < 8; ++reg) {
    fputc(':', output_file);
    for (unsigned byte = 0; byte < 10; ++byte)
      fprintf(output_file, "%02x", state.registers[reg][byte]);
  }
}

void emit_unsupported(Bit32u sequence, const char *detail)
{
  fprintf(output_file, "OBS\t%08x\tunsupported\t%s\n", sequence, detail);
  fflush(output_file);
}

void emit_error(Bit32u sequence, const char *detail)
{
  fprintf(output_file, "OBS\t%08x\terror\t%s\n", sequence, detail);
  fflush(output_file);
}

void emit_complete(unsigned cpu, Bit32u final_eip,
                   const char *control, const char *fault)
{
  BX_CPU_C *processor = BX_CPU(cpu);
  fprintf(output_file,
    "OBS\t%08x\tcomplete\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x"
    "\t%08x\t%08x\t%08x\t%08x\t%s\t%s\t",
    pending_request.sequence,
    processor->gen_reg[0].dword.erx,
    processor->gen_reg[3].dword.erx,
    processor->gen_reg[1].dword.erx,
    processor->gen_reg[2].dword.erx,
    processor->gen_reg[6].dword.erx,
    processor->gen_reg[7].dword.erx,
    processor->gen_reg[5].dword.erx,
    processor->gen_reg[4].dword.erx,
    final_eip,
    processor->read_eflags(),
    control,
    fault);
  if (pending_request.memory_region_count == 0) {
    fputc('-', output_file);
  }
  else {
    Bit8u snapshot[BC_MAX_MEMORY_BYTES];
    for (unsigned region_index = 0;
         region_index < pending_request.memory_region_count; ++region_index) {
      const memory_region_t &region =
        pending_request.memory_regions[region_index];
      if (region_index != 0) fputc(',', output_file);
      fprintf(output_file, "%08x:", region.address);
      read_physical(region.address, snapshot, region.length);
      for (unsigned byte_index = 0; byte_index < region.length; ++byte_index) {
        fprintf(output_file, "%02x", snapshot[byte_index]);
      }
    }
  }
  fputc('\t', output_file);
  emit_x87(cpu);
  fputc('\n', output_file);
  fflush(output_file);
}

void set_selector(bx_segment_reg_t *segment, Bit16u value)
{
  segment->selector.value = value;
  segment->selector.index = value >> 3;
  segment->selector.ti = Bit8u((value >> 2) & 1);
  segment->selector.rpl = Bit8u(value & 3);
}

bool request_fs_state_valid(const request_t &request)
{
  if (request.fs_selector == 0) return request.fs_base == 0;
  return (request.fs_selector & 7) == 3;
}

void prepare_case_segment_state(unsigned cpu_id)
{
  if (case_segments_active) private_fatal("case_segments_already_active");
  BX_CPU_C *cpu = BX_CPU(cpu_id);
  memcpy(saved_segments, cpu->sregs, sizeof(saved_segments));

  if (pending_request.fs_selector == 0) {
    cpu->sregs[BX_SEG_REG_FS] = saved_segments[BX_SEG_REG_FS];
  }
  else {
    cpu->sregs[BX_SEG_REG_FS] = cpu->sregs[BX_SEG_REG_DS];
    set_selector(
      &cpu->sregs[BX_SEG_REG_FS], pending_request.fs_selector);
    cpu->sregs[BX_SEG_REG_FS].cache.u.segment.base =
      pending_request.fs_base;
    cpu->sregs[BX_SEG_REG_FS].cache.dpl = 3;
    cpu->sregs[BX_SEG_REG_FS].cache.valid &=
      ~(SegAccessROK4G | SegAccessWOK4G);
  }
  cpu->updateFetchModeMask();
  case_segments_active = true;

  if (cpu->sregs[BX_SEG_REG_FS].selector.value !=
        pending_request.fs_selector ||
      cpu->sregs[BX_SEG_REG_FS].cache.u.segment.base !=
        pending_request.fs_base) {
    private_fatal("case_segment_injection_not_exact");
  }
}

void enter_case_execution_state(unsigned cpu_id)
{
  if (!case_segments_active) private_fatal("case_segments_not_prepared");
  BX_CPU_C *cpu = BX_CPU(cpu_id);
  const unsigned ordinary[] = {
    BX_SEG_REG_CS, BX_SEG_REG_SS, BX_SEG_REG_DS, BX_SEG_REG_ES
  };
  for (unsigned index = 0; index < sizeof(ordinary) / sizeof(ordinary[0]);
       ++index) {
    bx_segment_reg_t *segment = &cpu->sregs[ordinary[index]];
    set_selector(segment, Bit16u((segment->selector.value & 0xfffc) | 3));
    segment->cache.dpl = 3;
  }
  cpu->updateFetchModeMask();

  if (cpu->get_cpl() != 3 ||
      cpu->sregs[BX_SEG_REG_FS].selector.value !=
        pending_request.fs_selector ||
      cpu->sregs[BX_SEG_REG_FS].cache.u.segment.base !=
        pending_request.fs_base) {
    private_fatal("case_execution_state_not_exact");
  }
}

bool case_fs_state_unchanged(unsigned cpu_id)
{
  BX_CPU_C *cpu = BX_CPU(cpu_id);
  return case_segments_active &&
         cpu->sregs[BX_SEG_REG_FS].selector.value ==
           pending_request.fs_selector &&
         cpu->sregs[BX_SEG_REG_FS].cache.u.segment.base ==
           pending_request.fs_base;
}

void restore_harness_execution_state(unsigned cpu_id)
{
  if (!case_segments_active) return;
  BX_CPU_C *cpu = BX_CPU(cpu_id);
  memcpy(cpu->sregs, saved_segments, sizeof(saved_segments));
  cpu->updateFetchModeMask();
  cpu->setEFlags(0x2);
  case_segments_active = false;
}

void redirect_to_harness(unsigned cpu_id)
{
  BX_CPU_C *cpu = BX_CPU(cpu_id);
  cpu->gen_reg[BX_32BIT_REG_EIP].dword.erx = resume_eip;
  cpu->prev_rip = resume_eip;
  cpu->invalidate_prefetch_q();
  cpu->async_event |= BX_ASYNC_EVENT_STOP_TRACE;
}

void recover_from_active_exception(unsigned cpu_id)
{
  BX_CPU_C *cpu = BX_CPU(cpu_id);
  cpu->speculative_rsp = false;
  cpu->last_exception_type = 0;
  redirect_to_harness(cpu_id);

  // The exception callback runs before Bochs restores the fault EIP or enters
  // the guest IDT. Jump directly to the decode loop so exception delivery
  // cannot mutate the captured architectural state or the harness stack.
  longjmp(BX_CPU_C::jmp_buf_env, 1);
}

void service_request(void)
{
  if (active || pending) private_fatal("guest_requested_while_case_active");
  if (resume_eip == 0) {
    struct bc_mailbox mailbox;
    read_mailbox(&mailbox);
    resume_eip = mailbox.resume_eip;
    if (resume_eip < 0x1000 || resume_eip >= BC_TEST_ADDRESS_MIN) {
      private_fatal("guest_resume_address_invalid");
    }
  }

  request_t request;
  memset(&request, 0, sizeof(request));
  if (!read_request(&request)) {
    fprintf(output_file, "DONE\t%08x\n", next_sequence);
    fflush(output_file);
    input_ended = true;
    write_mailbox(NULL, BC_MAILBOX_END);
    return;
  }
  if ((request.requirements & ~BC_REQUIRE_KNOWN_MASK) != 0) {
    private_fatal("private_input_requirements_invalid");
  }
  if ((request.requirements & BC_REQUIRE_INSTRUCTION) != 0) {
    emit_unsupported(request.sequence, "instruction_not_implemented");
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }
  const Bit32u supported_requirements =
    BC_REQUIRE_MEMORY | BC_REQUIRE_FAULT | BC_REQUIRE_X87 |
    BC_REQUIRE_SEGMENT_STATE | BC_REQUIRE_BRANCH;
  if ((request.requirements & ~supported_requirements) != 0) {
    const char *detail = "capability_not_implemented";
    if ((request.requirements & BC_REQUIRE_MEMORY_BOUNDS) != 0)
      detail = "memory_bounds_not_implemented";
    else if ((request.requirements & BC_REQUIRE_SEGMENT_STATE) != 0)
      detail = "segment_state_not_implemented";
    else if ((request.requirements & BC_REQUIRE_PROFILE) != 0)
      detail = "profile_not_implemented";
    emit_unsupported(request.sequence, detail);
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }
  if (((request.requirements & BC_REQUIRE_MEMORY) != 0) !=
      (request.memory_region_count != 0)) {
    private_fatal("private_input_memory_requirement_mismatch");
  }
  if (request.eip < BC_TEST_ADDRESS_MIN || request.eip > BC_TEST_ADDRESS_MAX) {
    emit_error(request.sequence, "eip_outside_phase1_guest_ram");
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }
  if ((request.eflags & ~BC_SAFE_EFLAGS_MASK) != 0 ||
      (request.eflags & 0x2) == 0) {
    emit_unsupported(request.sequence, "eflags_not_safe_for_phase1_harness");
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }
  if (!request_fs_state_valid(request)) {
    emit_unsupported(request.sequence, "segment_state_invalid");
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }
  const char *instruction_detail = review_instruction(&request);
  if (instruction_detail != NULL) {
    emit_unsupported(request.sequence, instruction_detail);
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }
  for (unsigned index = 0; index < request.memory_region_count; ++index) {
    const memory_region_t &region = request.memory_regions[index];
    if (region.address < Bit64u(request.eip) + BC_INSTRUCTION_SLOT_BYTES &&
        request.eip < Bit64u(region.address) + region.length) {
      emit_error(request.sequence, "memory_overlaps_instruction");
      write_mailbox(NULL, BC_MAILBOX_SKIP);
      return;
    }
    write_physical(
      region.address,
      request.memory_bytes + region.data_offset,
      region.length);
  }

  Bit8u code[BC_INSTRUCTION_SLOT_BYTES];
  memset(code, 0xcc, sizeof(code));
  memcpy(code, request.bytes, request.length);
  write_physical(request.eip, code, sizeof(code));
  flushICaches();
  BX_CPU(0)->invalidate_prefetch_q();
  set_x87_state(BX_CPU(0), request.x87);
  x87_state_t observed_x87;
  get_x87_state(BX_CPU(0), &observed_x87);
  if (!x87_state_equal(request.x87, observed_x87)) {
    emit_unsupported(request.sequence, "x87_state_injection_not_exact");
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }
  pending_request = request;
  prepare_case_segment_state(0);
  pending = true;
  write_mailbox(&request, BC_MAILBOX_EXECUTE);
}

}  // namespace

void bx_instr_init_env(void)
{
  const char *input_path = getenv("BOCHS_CONFORMANCE_PRIVATE_INPUT");
  const char *output_path = getenv("BOCHS_CONFORMANCE_PRIVATE_OUTPUT");
  if (input_path == NULL || output_path == NULL) {
    fprintf(stderr, "bochs-conformance: private protocol paths are required\n");
    exit(2);
  }
  input_file = fopen(input_path, "rb");
  output_file = fopen(output_path, "wb");
  if (input_file == NULL || output_file == NULL) {
    fprintf(stderr, "bochs-conformance: cannot open private protocol files: %s\n",
            strerror(errno));
    exit(2);
  }
}

void bx_instr_exit_env(void)
{
  if (input_file != NULL) fclose(input_file);
  if (output_file != NULL) fclose(output_file);
  input_file = output_file = NULL;
}

void bx_instr_initialize(unsigned cpu) { if (cpu != 0) private_fatal("smp_unsupported"); }
void bx_instr_exit(unsigned cpu) { (void) cpu; }
void bx_instr_reset(unsigned cpu, unsigned type) { (void) cpu; (void) type; }

void bx_instr_before_execution(unsigned cpu, bxInstruction_c *instruction)
{
  if (!pending || active || BX_CPU(cpu)->get_eip() != pending_request.eip) return;
  x87_state_t observed_x87;
  get_x87_state(BX_CPU(cpu), &observed_x87);
  if (!BX_CPU(cpu)->sregs[BX_SEG_REG_CS].cache.u.segment.d_b ||
      BX_CPU(cpu)->long64_mode() ||
      instruction->ilen() != pending_request.length ||
      instruction->getIaOpcode() != pending_request.ia_opcode ||
      memcmp(instruction->get_opcode_bytes(), pending_request.bytes,
             pending_request.length) != 0 ||
      !x87_state_equal(pending_request.x87, observed_x87) ||
      !case_segments_active ||
      BX_CPU(cpu)->get_cpl() != 3) {
    private_fatal("executed_instruction_mismatch");
  }
  active = true;
  saw_io = saw_system = saw_branch = false;
  memory_violation = NULL;
  observed_control = "fallthrough";
}

void bx_instr_after_execution(unsigned cpu, bxInstruction_c *instruction)
{
  (void) instruction;
  if (!active) return;
  BX_CPU_C *processor = BX_CPU(cpu);
  Bit32u final_eip = processor->get_eip();
  if (memory_violation != NULL) {
    emit_unsupported(pending_request.sequence, memory_violation);
  }
  else if (saw_io) {
    emit_unsupported(pending_request.sequence, "io_not_implemented");
  }
  else if (saw_system) {
    emit_unsupported(pending_request.sequence, "instruction_scope_not_implemented");
  }
  else if (!case_fs_state_unchanged(cpu)) {
    emit_unsupported(pending_request.sequence, "segment_state_changed");
  }
  else if (!saw_branch &&
           final_eip != pending_request.eip + pending_request.length) {
    emit_unsupported(pending_request.sequence, "unclassified_control_flow");
  }
  else {
    emit_complete(cpu, final_eip, observed_control, "none");
  }
  active = pending = false;
  restore_harness_execution_state(cpu);
  redirect_to_harness(cpu);
}

void bx_instr_exception(unsigned cpu, unsigned vector, unsigned error_code)
{
  if (!active) return;

  BX_CPU_C *processor = BX_CPU(cpu);
  if (vector == BX_DE_EXCEPTION &&
      error_code == 0 &&
      memory_violation == NULL &&
      !saw_io &&
      !saw_system &&
      processor->prev_rip == pending_request.eip) {
    emit_complete(cpu, Bit32u(processor->prev_rip), "fault", "divide_error");
  }
  else {
    char detail[64];
    if (memory_violation != NULL) {
      emit_unsupported(pending_request.sequence, memory_violation);
    }
    else {
      snprintf(detail, sizeof(detail),
               "fault_not_implemented_vector_%u", vector);
      emit_unsupported(pending_request.sequence, detail);
    }
  }
  active = pending = false;
  restore_harness_execution_state(cpu);
  recover_from_active_exception(cpu);
}

void bx_instr_hlt(unsigned cpu)
{
  if (active) {
    emit_unsupported(pending_request.sequence, "halt_not_implemented");
    active = pending = false;
    restore_harness_execution_state(cpu);
    redirect_to_harness(cpu);
    return;
  }
  if (input_ended) BX_EXIT(0);
}

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_address phy,
                         unsigned len, unsigned memtype, unsigned rw)
{
  (void) cpu;
  (void) memtype;
  if (!active) return;
  if (memory_violation != NULL) return;
  if (lin != phy) {
    memory_violation = "non_identity_memory_translation";
    return;
  }
  if (len == 0 || Bit64u(lin) + len > BC_GUEST_RAM_END) {
    memory_violation = "memory_access_out_of_bounds";
    return;
  }
  const memory_region_t *covering = NULL;
  for (unsigned index = 0;
       index < pending_request.memory_region_count; ++index) {
    const memory_region_t &region = pending_request.memory_regions[index];
    if (region.address <= lin &&
        Bit64u(lin) + len <= Bit64u(region.address) + region.length) {
      covering = &region;
      break;
    }
  }
  if (covering == NULL) {
    memory_violation = "undeclared_memory_access";
    return;
  }
  if ((rw == BX_WRITE || rw == BX_RW) && !covering->writable) {
    memory_violation = "write_to_read_only_memory";
    return;
  }
  if (rw != BX_READ && rw != BX_WRITE && rw != BX_RW) {
    memory_violation = "memory_access_kind_not_implemented";
  }
}

void bx_instr_inp(Bit16u addr, unsigned len)
{ (void) addr; (void) len; if (active) saw_io = true; }
void bx_instr_inp2(Bit16u addr, unsigned len, unsigned value)
{ (void) addr; (void) len; (void) value; if (active) saw_io = true; }

void bx_instr_outp(Bit16u addr, unsigned len, unsigned value)
{
  if (active) { saw_io = true; return; }
  if (addr == BC_CONTROL_PORT && len == 4 && value == BC_SIGNAL_READY) {
    service_request();
  }
}

void bx_instr_interrupt(unsigned cpu, unsigned vector)
{ (void) cpu; (void) vector; if (active) saw_system = true; }
void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs,
                          bx_address eip)
{ (void) cpu; (void) vector; (void) cs; (void) eip; if (active) saw_system = true; }
void bx_instr_mwait(unsigned cpu, bx_phy_address addr, unsigned len, Bit32u flags)
{ (void) cpu; (void) addr; (void) len; (void) flags; if (active) saw_system = true; }
void bx_instr_tlb_cntrl(unsigned cpu, unsigned what, bx_phy_address value)
{ (void) cpu; (void) what; (void) value; if (active) saw_system = true; }
void bx_instr_cache_cntrl(unsigned cpu, unsigned what)
{ (void) cpu; (void) what; if (active) saw_system = true; }
void bx_instr_clflush(unsigned cpu, bx_address lin, bx_phy_address phy)
{ (void) cpu; (void) lin; (void) phy; if (active) saw_system = true; }
void bx_instr_wrmsr(unsigned cpu, unsigned addr, Bit64u value)
{ (void) cpu; (void) addr; (void) value; if (active) saw_system = true; }
void bx_instr_vmexit(unsigned cpu, Bit32u reason, Bit64u qualification)
{ (void) cpu; (void) reason; (void) qualification; if (active) saw_system = true; }

void bx_instr_debug_promt(void) {}
void bx_instr_debug_cmd(const char *cmd) { (void) cmd; }
void bx_instr_cnear_branch_taken(unsigned cpu, bx_address old_eip,
                                 bx_address new_eip)
{
  (void) old_eip;
  if (pending && !active && new_eip == pending_request.eip) {
    enter_case_execution_state(cpu);
    return;
  }
  if (active) { saw_branch = true; observed_control = "direct_branch"; }
}
void bx_instr_cnear_branch_not_taken(unsigned cpu, bx_address old_eip)
{
  (void) cpu; (void) old_eip;
  if (active) { saw_branch = true; observed_control = "direct_branch"; }
}
void bx_instr_ucnear_branch(unsigned cpu, unsigned what, bx_address old_eip,
                            bx_address new_eip)
{
  (void) what; (void) old_eip;
  if (pending && !active && new_eip == pending_request.eip) {
    enter_case_execution_state(cpu);
    return;
  }
  if (!active) return;
  saw_branch = true;
  switch (what) {
    case BX_INSTR_IS_JMP:
      observed_control = "direct_branch";
      break;
    case BX_INSTR_IS_JMP_INDIRECT:
      observed_control = "indirect_branch";
      break;
    case BX_INSTR_IS_CALL:
      observed_control = "direct_call";
      break;
    case BX_INSTR_IS_CALL_INDIRECT:
      observed_control = "indirect_call";
      break;
    case BX_INSTR_IS_RET:
      observed_control = "return";
      break;
    default:
      saw_system = true;
      break;
  }
}
void bx_instr_far_branch(unsigned cpu, unsigned what, Bit16u old_cs,
                         bx_address old_eip, Bit16u new_cs, bx_address new_eip)
{
  (void) cpu; (void) what; (void) old_cs; (void) old_eip;
  (void) new_cs; (void) new_eip;
  if (active) { saw_branch = true; saw_system = true; }
}
void bx_instr_opcode(unsigned cpu, bxInstruction_c *instruction,
                     const Bit8u *opcode, unsigned len, bool is32, bool is64)
{ (void) cpu; (void) instruction; (void) opcode; (void) len; (void) is32; (void) is64; }
void bx_instr_prefetch_hint(unsigned cpu, unsigned what, unsigned seg,
                            bx_address offset)
{ (void) cpu; (void) what; (void) seg; (void) offset; }
void bx_instr_repeat_iteration(unsigned cpu, bxInstruction_c *instruction)
{ (void) cpu; (void) instruction; }
void bx_instr_phy_access(unsigned cpu, bx_address phy, unsigned len,
                         unsigned memtype, unsigned rw)
{ (void) cpu; (void) phy; (void) len; (void) memtype; (void) rw; }
