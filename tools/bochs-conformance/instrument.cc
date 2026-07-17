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

struct request_t {
  Bit32u sequence;
  Bit8u bytes[15];
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
  Bit16u ia_opcode;
};

FILE *input_file = NULL;
FILE *output_file = NULL;
request_t pending_request;
bool pending = false;
bool active = false;
bool saw_memory = false;
bool saw_io = false;
bool saw_system = false;
bool saw_branch = false;
bool input_ended = false;
Bit32u resume_eip = 0;
Bit32u next_sequence = 0;

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

bool parse_bytes(const std::string &text, request_t *request)
{
  if (text.empty() || text.size() > 30 || (text.size() & 1) != 0) return false;
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

bool starts_with(const char *value, const char *prefix)
{
  return strncmp(value, prefix, strlen(prefix)) == 0;
}

bool mnemonic_is(const char *opcode, const char *mnemonic)
{
  const size_t length = strlen(mnemonic);
  return strncmp(opcode, mnemonic, length) == 0 &&
         (opcode[length] == '\0' || opcode[length] == '_');
}

bool has_segment_override(const request_t &request)
{
  for (unsigned index = 0; index < request.length; ++index) {
    switch (request.bytes[index]) {
      case 0x26: case 0x2e: case 0x36:
      case 0x3e: case 0x64: case 0x65:
        return true;
      case 0x66: case 0x67: case 0xf0: case 0xf2: case 0xf3:
        continue;
      default:
        return false;
    }
  }
  return false;
}

bool control_instruction(const char *opcode)
{
  return opcode[0] == 'J' || mnemonic_is(opcode, "CALL") ||
         mnemonic_is(opcode, "CALLF") || mnemonic_is(opcode, "IRET") ||
         mnemonic_is(opcode, "LOOP") || mnemonic_is(opcode, "LOOPE") ||
         mnemonic_is(opcode, "LOOPNE") || mnemonic_is(opcode, "RET") ||
         mnemonic_is(opcode, "RETF") || mnemonic_is(opcode, "XABORT") ||
         mnemonic_is(opcode, "XBEGIN");
}

bool io_instruction(const char *opcode)
{
  return mnemonic_is(opcode, "IN") || mnemonic_is(opcode, "INSB") ||
         mnemonic_is(opcode, "INSD") || mnemonic_is(opcode, "INSW") ||
         mnemonic_is(opcode, "OUT") || mnemonic_is(opcode, "OUTSB") ||
         mnemonic_is(opcode, "OUTSD") || mnemonic_is(opcode, "OUTSW") ||
         starts_with(opcode, "REP_INS") || starts_with(opcode, "REP_OUTS");
}

bool implicit_stack_instruction(const char *opcode)
{
  return mnemonic_is(opcode, "ENTER") || mnemonic_is(opcode, "LEAVE") ||
         mnemonic_is(opcode, "POPA") || starts_with(opcode, "POPF_") ||
         starts_with(opcode, "POP_") || mnemonic_is(opcode, "PUSHA") ||
         starts_with(opcode, "PUSHF_") || starts_with(opcode, "PUSH_");
}

bool reviewed_integer_instruction(const char *opcode)
{
  // New mnemonics must be reviewed here; operand and side-effect checks remain
  // authoritative for each concrete encoding.
  static const char *const reviewed[] = {
    "AAA", "AAD", "AAM", "AAS", "ADC", "ADCX", "ADD", "ADOX",
    "AND", "ANDN", "BEXTR", "BLSI", "BLSMSK", "BLSR", "BSF",
    "BSR", "BSWAP", "BT", "BTC", "BTR", "BTS", "BZHI", "CBW",
    "CDQ", "CLC", "CLD", "CMC", "CMP", "CMPXCHG", "CWD", "CWDE",
    "DAA", "DAS", "DEC", "DIV", "IDIV", "IMUL", "INC", "LAHF",
    "LZCNT", "MOV", "MOVBE", "MOVSX", "MOVZX", "MUL", "MULX",
    "NEG", "NOP", "NOT", "OR", "PDEP", "PEXT", "POPCNT", "RCL",
    "RCR", "ROL", "ROR", "RORX", "SAHF", "SAR", "SARX", "SBB",
    "SHL", "SHLD", "SHLX", "SHR", "SHRD", "SHRX", "STC", "STD",
    "SUB", "TEST", "TZCNT", "XADD", "XCHG", "XOR"
  };
  if (starts_with(opcode, "CMOV") || starts_with(opcode, "SET")) return true;
  for (size_t index = 0; index < sizeof(reviewed) / sizeof(reviewed[0]); ++index) {
    if (mnemonic_is(opcode, reviewed[index])) return true;
  }
  return false;
}

const char *operand_scope(const bxInstruction_c &instruction,
                          const bxIAOpcodeTable &opcode)
{
  for (unsigned index = 0; index < 4; ++index) {
    const unsigned descriptor = opcode.src[index];
    const unsigned origin = BX_DISASM_SRC_ORIGIN(descriptor);
    const unsigned type = BX_DISASM_SRC_TYPE(descriptor);
    if (origin == BX_SRC_NONE) continue;
    if (origin == BX_SRC_BRANCH_OFFSET ||
        (origin == BX_SRC_IMM && type == BX_DIRECT_PTR)) {
      return "branch_not_implemented";
    }
    if ((origin == BX_SRC_RM || origin == BX_SRC_VECTOR_RM) &&
        !instruction.modC0()) {
      return "memory_not_implemented";
    }
    if (origin == BX_SRC_VSIB ||
        (origin == BX_SRC_IMM && type >= BX_DIRECT_MEMREF_B &&
         type <= BX_DIRECT_MEMREF_Q) ||
        (origin == BX_SRC_IMPLICIT && type >= BX_RSIREF_B &&
         type <= BX_VEC_RDIREF)) {
      return "memory_not_implemented";
    }
    if (type == BX_FPU_REG) return "x87_not_implemented";
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
  const char *opcode = instruction.getIaOpcodeNameShort();
  if (has_segment_override(*request)) return "segment_state_not_implemented";
  if (control_instruction(opcode)) return "branch_not_implemented";
  if (io_instruction(opcode)) return "io_not_implemented";
  if (implicit_stack_instruction(opcode)) return "memory_not_implemented";

  const bxIAOpcodeTable &opcode_info = BxOpcodesTable[request->ia_opcode];
  if ((opcode_info.opflags & BX_PREPARE_FPU) != 0) return "x87_not_implemented";
  if ((opcode_info.opflags &
       (BX_PREPARE_MMX | BX_PREPARE_SSE | BX_PREPARE_AVX |
        BX_PREPARE_OPMASK | BX_PREPARE_EVEX | BX_PREPARE_AMX)) != 0) {
    return "register_class_not_implemented";
  }
  const char *scope = operand_scope(instruction, opcode_info);
  if (scope != NULL) return scope;
  if (!reviewed_integer_instruction(opcode)) {
    return "system_or_unreviewed_instruction_not_implemented";
  }
  return NULL;
}

bool read_request(request_t *request)
{
  char buffer[1024];
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
  if (fields.size() != 15 || fields[0] != "CASE" || fields[1] != "1") {
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
      !parse_hex32(fields[14], &request->requirements)) {
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

void redirect_to_harness(unsigned cpu_id)
{
  BX_CPU_C *cpu = BX_CPU(cpu_id);
  cpu->gen_reg[BX_32BIT_REG_EIP].dword.erx = resume_eip;
  cpu->prev_rip = resume_eip;
  cpu->invalidate_prefetch_q();
  cpu->async_event |= BX_ASYNC_EVENT_STOP_TRACE;
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
  if (request.requirements != 0) {
    const char *detail = "phase1_capability_not_implemented";
    if (request.requirements == BC_REQUIRE_MEMORY) detail = "memory_not_implemented";
    if (request.requirements == BC_REQUIRE_FAULT) detail = "fault_not_implemented";
    if (request.requirements == BC_REQUIRE_X87) detail = "x87_not_implemented";
    if (request.requirements == BC_REQUIRE_SEGMENT_STATE) detail = "segment_state_not_implemented";
    if (request.requirements == BC_REQUIRE_BRANCH) detail = "branch_not_implemented";
    if (request.requirements == BC_REQUIRE_PROFILE) detail = "profile_not_implemented";
    emit_unsupported(request.sequence, detail);
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
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
  const char *instruction_detail = review_instruction(&request);
  if (instruction_detail != NULL) {
    emit_unsupported(request.sequence, instruction_detail);
    write_mailbox(NULL, BC_MAILBOX_SKIP);
    return;
  }

  Bit8u code[15];
  memset(code, 0xcc, sizeof(code));
  memcpy(code, request.bytes, request.length);
  write_physical(request.eip, code, sizeof(code));
  flushICaches();
  BX_CPU(0)->invalidate_prefetch_q();
  pending_request = request;
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
  if (!BX_CPU(cpu)->sregs[BX_SEG_REG_CS].cache.u.segment.d_b ||
      BX_CPU(cpu)->long64_mode() ||
      instruction->ilen() != pending_request.length ||
      instruction->getIaOpcode() != pending_request.ia_opcode ||
      memcmp(instruction->get_opcode_bytes(), pending_request.bytes,
             pending_request.length) != 0) {
    private_fatal("executed_instruction_mismatch");
  }
  active = true;
  saw_memory = saw_io = saw_system = saw_branch = false;
}

void bx_instr_after_execution(unsigned cpu, bxInstruction_c *instruction)
{
  (void) instruction;
  if (!active) return;
  BX_CPU_C *processor = BX_CPU(cpu);
  Bit32u final_eip = processor->get_eip();
  if (saw_memory) {
    emit_unsupported(pending_request.sequence, "memory_not_implemented");
  }
  else if (saw_io) {
    emit_unsupported(pending_request.sequence, "io_not_implemented");
  }
  else if (saw_system) {
    emit_unsupported(pending_request.sequence, "instruction_scope_not_implemented");
  }
  else if (saw_branch) {
    emit_unsupported(pending_request.sequence, "branch_not_implemented");
  }
  else if (final_eip != pending_request.eip + pending_request.length) {
    emit_unsupported(pending_request.sequence, "branch_not_implemented");
  }
  else if ((processor->read_eflags() & ~BC_SAFE_EFLAGS_MASK) != 0 ||
           (processor->read_eflags() & 0x2) == 0) {
    emit_unsupported(pending_request.sequence, "eflags_left_safe_profile");
  }
  else {
    fprintf(output_file,
      "OBS\t%08x\tcomplete\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x"
      "\t%08x\t%08x\t%08x\t%08x\n",
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
      processor->read_eflags());
    fflush(output_file);
  }
  active = pending = false;
  redirect_to_harness(cpu);
}

void bx_instr_exception(unsigned cpu, unsigned vector, unsigned error_code)
{
  (void) cpu;
  (void) error_code;
  if (!active) return;
  char detail[64];
  snprintf(detail, sizeof(detail), "fault_not_implemented_vector_%u", vector);
  emit_unsupported(pending_request.sequence, detail);
  active = pending = false;
}

void bx_instr_hlt(unsigned cpu)
{
  if (active) {
    emit_unsupported(pending_request.sequence, "halt_not_implemented");
    active = pending = false;
    redirect_to_harness(cpu);
    return;
  }
  if (input_ended) BX_EXIT(0);
}

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_address phy,
                         unsigned len, unsigned memtype, unsigned rw)
{
  (void) cpu; (void) lin; (void) phy; (void) len; (void) memtype; (void) rw;
  if (active) saw_memory = true;
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
{ (void) cpu; (void) old_eip; (void) new_eip; if (active) saw_branch = true; }
void bx_instr_cnear_branch_not_taken(unsigned cpu, bx_address old_eip)
{ (void) cpu; (void) old_eip; if (active) saw_branch = true; }
void bx_instr_ucnear_branch(unsigned cpu, unsigned what, bx_address old_eip,
                            bx_address new_eip)
{ (void) cpu; (void) what; (void) old_eip; (void) new_eip; if (active) saw_branch = true; }
void bx_instr_far_branch(unsigned cpu, unsigned what, Bit16u old_cs,
                         bx_address old_eip, Bit16u new_cs, bx_address new_eip)
{
  (void) cpu; (void) what; (void) old_cs; (void) old_eip;
  (void) new_cs; (void) new_eip; if (active) saw_branch = true;
}
void bx_instr_opcode(unsigned cpu, bxInstruction_c *instruction,
                     const Bit8u *opcode, unsigned len, bool is32, bool is64)
{ (void) cpu; (void) instruction; (void) opcode; (void) len; (void) is32; (void) is64; }
void bx_instr_prefetch_hint(unsigned cpu, unsigned what, unsigned seg,
                            bx_address offset)
{ (void) cpu; (void) what; (void) seg; (void) offset; }
void bx_instr_repeat_iteration(unsigned cpu, bxInstruction_c *instruction)
{ (void) cpu; (void) instruction; if (active) saw_system = true; }
void bx_instr_phy_access(unsigned cpu, bx_address phy, unsigned len,
                         unsigned memtype, unsigned rw)
{ (void) cpu; (void) phy; (void) len; (void) memtype; (void) rw; }
