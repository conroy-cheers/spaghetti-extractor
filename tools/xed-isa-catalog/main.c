#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <xed/xed-interface.h>
#include <xed/xed-gen-table-defs.h>

static void json_string(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;

    putchar('"');
    while (*cursor != 0) {
        switch (*cursor) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\b':
            fputs("\\b", stdout);
            break;
        case '\f':
            fputs("\\f", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (*cursor < 0x20) {
                printf("\\u%04x", (unsigned int)*cursor);
            } else {
                putchar(*cursor);
            }
        }
        cursor++;
    }
    putchar('"');
}

static void json_key_string(const char *key, const char *value) {
    json_string(key);
    putchar(':');
    json_string(value);
}

static void emit_attributes(const xed_inst_t *inst) {
    unsigned int index;
    int first = 1;

    fputs("\"attributes\":[", stdout);
    for (index = 0; index < xed_attribute_max(); index++) {
        xed_attribute_enum_t attribute = xed_attribute(index);
        if (!xed_inst_get_attribute(inst, attribute)) {
            continue;
        }
        if (!first) {
            putchar(',');
        }
        json_string(xed_attribute_enum_t2str(attribute));
        first = 0;
    }
    putchar(']');
}

static void emit_operand(const xed_operand_t *operand) {
    xed_operand_type_enum_t type = xed_operand_type(operand);
    xed_nonterminal_enum_t nonterminal =
        xed_operand_nonterminal_name(operand);
    xed_reg_enum_t reg = xed_operand_reg(operand);

    putchar('{');
    json_key_string(
        "name", xed_operand_enum_t2str(xed_operand_name(operand)));
    putchar(',');
    json_key_string(
        "visibility",
        xed_operand_visibility_enum_t2str(
            xed_operand_operand_visibility(operand)));
    putchar(',');
    json_key_string(
        "action", xed_operand_action_enum_t2str(xed_operand_rw(operand)));
    putchar(',');
    json_key_string(
        "width", xed_operand_width_enum_t2str(xed_operand_width(operand)));
    putchar(',');
    json_key_string(
        "xtype", xed_operand_element_xtype_enum_t2str(xed_operand_xtype(operand)));
    putchar(',');
    json_key_string("type", xed_operand_type_enum_t2str(type));
    putchar(',');
    json_key_string(
        "nonterminal",
        nonterminal == XED_NONTERMINAL_INVALID
            ? ""
            : xed_nonterminal_enum_t2str(nonterminal));
    putchar(',');
    json_key_string(
        "register", reg == XED_REG_INVALID ? "" : xed_reg_enum_t2str(reg));
    fputs(",\"immediate\":", stdout);
    if (type == XED_OPERAND_TYPE_IMM_CONST) {
        printf("%u", (unsigned int)xed_operand_imm(operand));
    } else {
        fputs("null", stdout);
    }
    putchar('}');
}

static void emit_template(const xed_inst_t *inst, unsigned int table_index) {
    xed_iform_enum_t iform = xed_inst_iform_enum(inst);
    unsigned int operand_index;

    putchar('{');
    printf("\"table_index\":%u,", table_index);
    json_key_string("iform", xed_iform_enum_t2str(iform));
    putchar(',');
    json_key_string(
        "iclass", xed_iclass_enum_t2str(xed_inst_iclass(inst)));
    putchar(',');
    json_key_string(
        "category", xed_category_enum_t2str(xed_inst_category(inst)));
    putchar(',');
    json_key_string(
        "extension", xed_extension_enum_t2str(xed_inst_extension(inst)));
    putchar(',');
    json_key_string(
        "isa_set", xed_isa_set_enum_t2str(xed_inst_isa_set(inst)));
    printf(",\"cpl\":%u", xed_inst_cpl(inst));
    putchar(',');
    json_key_string(
        "exception", xed_exception_enum_t2str(xed_inst_exception(inst)));
    printf(
        ",\"flag_info_index\":%u,\"flag_complex\":%s,",
        (unsigned int)xed_inst_flag_info_index(inst),
        inst->_flag_complex ? "true" : "false");
    emit_attributes(inst);
    fputs(",\"operands\":[", stdout);
    for (operand_index = 0;
         operand_index < xed_inst_noperands(inst);
         operand_index++) {
        if (operand_index != 0) {
            putchar(',');
        }
        emit_operand(xed_inst_operand(inst, operand_index));
    }
    fputs("]}", stdout);
}

int main(void) {
    const xed_inst_t *table;
    unsigned int table_index;
    int first = 1;

    xed_tables_init();
    table = xed_inst_table_base();

    fputs("{\"format\":\"spaghetti-extractor-xed-inst-catalog-v1\",", stdout);
    fputs("\"generator\":{", stdout);
    json_key_string("name", "xed-isa-catalog");
    putchar(',');
    json_key_string("xed_version", xed_get_version());
    fputs("},\"profile\":{", stdout);
    json_key_string("id", "pe32-i686-v1");
    putchar(',');
    json_key_string("chip", "PENTIUMPRO");
    putchar(',');
    json_key_string("machine_mode", "LEGACY_32");
    fputs(",\"stack_address_width\":32,\"privilege\":\"ring3\"", stdout);
    fputs("},\"templates\":[", stdout);

    for (table_index = 0;
         table_index < XED_MAX_INST_TABLE_NODES;
         table_index++) {
        const xed_inst_t *inst = &table[table_index];
        xed_iform_enum_t iform = xed_inst_iform_enum(inst);
        xed_isa_set_enum_t isa_set;

        if (iform == XED_IFORM_INVALID || iform >= XED_IFORM_LAST) {
            continue;
        }
        isa_set = xed_inst_isa_set(inst);
        if (!xed_isa_set_is_valid_for_chip(isa_set, XED_CHIP_PENTIUMPRO)) {
            continue;
        }
        if (xed_inst_cpl(inst) != 3) {
            continue;
        }
        if (!first) {
            putchar(',');
        }
        emit_template(inst, table_index);
        first = 0;
    }
    fputs("]}\n", stdout);

    if (ferror(stdout)) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
