/* Source-assisted from jq 1.8.1 jv.c; see COPYING. */
#include <assert.h>
#include <float.h>
#include <math.h>
#include <string.h>
#include "number-inputs.h"
#include "jv_alloc.h"
#include "jv_dtoa.h"
#include "jv_dtoa_tsd.h"
#include "number-renames.h"
#define USE_DECNUM 1
#define DECNUMDIGITS 1
#include "decNumber.h"
/* The context belongs to the shared decimal runtime, including its thread
 * lifetime and sticky status. All number users retain that same context. */
decContext *spx_decimal_context(void);
#define DEC_CONTEXT() spx_decimal_context()
typedef struct jv_refcnt { int count; } jv_refcnt;
static const jv_refcnt JV_REFCNT_INIT = {1};
static const jv JV_INVALID = {JV_KIND_INVALID,0,0,0,{0}};
static int jvp_refcnt_dec(jv_refcnt *ref) { return --ref->count == 0; }
#define JVP_HAS_KIND(value, kind) (((value).kind_flags & 0xf) == (kind))
#define JVP_HAS_FLAGS(value, flags) ((value).kind_flags == (flags))
#define JVP_FLAGS_NUMBER_NATIVE JV_KIND_NUMBER
#define JVP_FLAGS_NUMBER_LITERAL (JV_KIND_NUMBER | 0x90)
#define DEC_NUMBER_DOUBLE_PRECISION 17
#define DEC_NUMBER_STRING_GUARD 14
#define DEC_NUMBER_DOUBLE_EXTRA_UNITS ((DEC_NUMBER_DOUBLE_PRECISION - DECNUMDIGITS + DECDPUN - 1) / DECDPUN)
#ifdef USE_DECNUM
typedef struct {
  jv_refcnt refcnt;
  double num_double;
  char * literal_data;
  decNumber num_decimal; // must be the last field in the structure for memory management
} jvp_literal_number;

typedef struct {
  decNumber number;
  decNumberUnit units[DEC_NUMBER_DOUBLE_EXTRA_UNITS];
} decNumberDoublePrecision;


static jvp_literal_number* jvp_literal_number_ptr(jv j) {
  assert(JVP_HAS_FLAGS(j, JVP_FLAGS_NUMBER_LITERAL));
  return (jvp_literal_number*)j.u.ptr;
}

static decNumber* jvp_dec_number_ptr(jv j) {
  assert(JVP_HAS_FLAGS(j, JVP_FLAGS_NUMBER_LITERAL));
  return &(((jvp_literal_number*)j.u.ptr)->num_decimal);
}

static jvp_literal_number* jvp_literal_number_alloc(unsigned literal_length) {
  /* The number of units needed is ceil(DECNUMDIGITS/DECDPUN)         */
  int units = ((literal_length+DECDPUN-1)/DECDPUN);

  jvp_literal_number* n = jv_mem_alloc(
    sizeof(jvp_literal_number)
    + sizeof(decNumberUnit) * units
  );

  n->refcnt = JV_REFCNT_INIT;
  n->num_double = NAN;
  n->literal_data = NULL;
  return n;
}

static jv jvp_literal_number_new(const char * literal) {
  jvp_literal_number* n = jvp_literal_number_alloc(strlen(literal));

  decContext *ctx = DEC_CONTEXT();
  decContextClearStatus(ctx, DEC_Conversion_syntax);
  decNumberFromString(&n->num_decimal, literal, ctx);

  if (ctx->status & DEC_Conversion_syntax) {
    jv_mem_free(n);
    return JV_INVALID;
  }
  if (decNumberIsNaN(&n->num_decimal)) {
    // Reject NaN with payload.
    if (n->num_decimal.digits > 1 || *n->num_decimal.lsu != 0) {
      jv_mem_free(n);
      return JV_INVALID;
    }
    jv_mem_free(n);
    return jv_number(NAN);
  }

  jv r = {JVP_FLAGS_NUMBER_LITERAL, 0, 0, 0, {&n->refcnt}};
  return r;
}

static double jvp_literal_number_to_double(jv j) {
  assert(JVP_HAS_FLAGS(j, JVP_FLAGS_NUMBER_LITERAL));
  decContext dblCtx;

  // init as decimal64 but change digits to allow conversion to binary64 (double)
  decContextDefault(&dblCtx, DEC_INIT_DECIMAL64);
  dblCtx.digits = DEC_NUMBER_DOUBLE_PRECISION;

  decNumber *p_dec_number = jvp_dec_number_ptr(j);
  decNumberDoublePrecision dec_double;
  char literal[DEC_NUMBER_DOUBLE_PRECISION + DEC_NUMBER_STRING_GUARD + 1];

  // reduce the number to the shortest possible form
  // that fits into the 64 bit floating point representation
  decNumberReduce(&dec_double.number, p_dec_number, &dblCtx);

  decNumberToString(&dec_double.number, literal);

  char *end;
  return jvp_strtod(tsd_dtoa_context_get(), literal, &end);
}

static const char* jvp_literal_number_literal(jv n) {
  assert(JVP_HAS_FLAGS(n, JVP_FLAGS_NUMBER_LITERAL));
  decNumber *pdec = jvp_dec_number_ptr(n);
  jvp_literal_number* plit = jvp_literal_number_ptr(n);

  if (decNumberIsNaN(pdec)) {
    return "null";
  }

  if (decNumberIsInfinite(pdec)) {
    // We cannot preserve the literal data of numbers outside the limited
    // range of exponent. Since `decNumberToString` returns "Infinity"
    // (or "-Infinity"), and to reduce stack allocations as possible, we
    // normalize infinities in the callers instead of printing the maximum
    // (or minimum) double here.
    return NULL;
  }

  if (plit->literal_data == NULL) {
    int len = jvp_dec_number_ptr(n)->digits + 15 /* 14 + NUL */;
    plit->literal_data = jv_mem_alloc(len);

    // Preserve the actual precision as we have parsed it
    // don't do decNumberTrim(pdec);

    decNumberToString(pdec, plit->literal_data);
  }

  return plit->literal_data;
}

int jv_number_has_literal(jv n) {
  assert(JVP_HAS_KIND(n, JV_KIND_NUMBER));
  return JVP_HAS_FLAGS(n, JVP_FLAGS_NUMBER_LITERAL);
}

const char* jv_number_get_literal(jv n) {
  assert(JVP_HAS_KIND(n, JV_KIND_NUMBER));

  if (JVP_HAS_FLAGS(n, JVP_FLAGS_NUMBER_LITERAL)) {
    return jvp_literal_number_literal(n);
  } else {
    return NULL;
  }
}

jv jv_number_with_literal(const char * literal) {
  return jvp_literal_number_new(literal);
}
#endif /* USE_DECNUM */

jv jv_number(double x) {
  (void)&jv_is_valid;
  jv j = {
#ifdef USE_DECNUM
    JVP_FLAGS_NUMBER_NATIVE,
#else
    JV_KIND_NUMBER,
#endif
    0, 0, 0, {.number = x}
  };
  return j;
}

void jvp_number_free(jv j) {
  assert(JVP_HAS_KIND(j, JV_KIND_NUMBER));
#ifdef USE_DECNUM
  if (JVP_HAS_FLAGS(j, JVP_FLAGS_NUMBER_LITERAL) && jvp_refcnt_dec(j.u.ptr)) {
    jvp_literal_number* n = jvp_literal_number_ptr(j);
    if (n->literal_data) {
      jv_mem_free(n->literal_data);
    }
    jv_mem_free(n);
  }
#endif
}

double jv_number_value(jv j) {
  assert(JVP_HAS_KIND(j, JV_KIND_NUMBER));
#ifdef USE_DECNUM
  if (JVP_HAS_FLAGS(j, JVP_FLAGS_NUMBER_LITERAL)) {
    jvp_literal_number* n = jvp_literal_number_ptr(j);

    if (isnan(n->num_double)) {
      n->num_double = jvp_literal_number_to_double(j);
    }

    return n->num_double;
  }
#endif
  return j.u.number;
}

int jv_is_integer(jv j){
  if (!JVP_HAS_KIND(j, JV_KIND_NUMBER)){
    return 0;
  }

  double x = jv_number_value(j);

  double ipart;
  double fpart = modf(x, &ipart);

  return fabs(fpart) < DBL_EPSILON;
}

int jvp_number_is_nan(jv n) {
  assert(JVP_HAS_KIND(n, JV_KIND_NUMBER));

#ifdef USE_DECNUM
  if (JVP_HAS_FLAGS(n, JVP_FLAGS_NUMBER_LITERAL)) {
    decNumber *pdec = jvp_dec_number_ptr(n);
    return decNumberIsNaN(pdec);
  }
#endif
  return isnan(n.u.number);
}

jv jv_number_abs(jv n) {
  assert(JVP_HAS_KIND(n, JV_KIND_NUMBER));

#ifdef USE_DECNUM
  if (JVP_HAS_FLAGS(n, JVP_FLAGS_NUMBER_LITERAL)) {
    jvp_literal_number* m = jvp_literal_number_alloc(jvp_dec_number_ptr(n)->digits);

    decNumberAbs(&m->num_decimal, jvp_dec_number_ptr(n), DEC_CONTEXT());
    jv r = {JVP_FLAGS_NUMBER_LITERAL, 0, 0, 0, {&m->refcnt}};
    return r;
  }
#endif
  return jv_number(fabs(jv_number_value(n)));
}

jv jv_number_negate(jv n) {
  assert(JVP_HAS_KIND(n, JV_KIND_NUMBER));

#ifdef USE_DECNUM
  if (JVP_HAS_FLAGS(n, JVP_FLAGS_NUMBER_LITERAL)) {
    jvp_literal_number* m = jvp_literal_number_alloc(jvp_dec_number_ptr(n)->digits);

    decNumberMinus(&m->num_decimal, jvp_dec_number_ptr(n), DEC_CONTEXT());
    jv r = {JVP_FLAGS_NUMBER_LITERAL, 0, 0, 0, {&m->refcnt}};
    return r;
  }
#endif
  return jv_number(-jv_number_value(n));
}

int jvp_number_cmp(jv a, jv b) {
  assert(JVP_HAS_KIND(a, JV_KIND_NUMBER));
  assert(JVP_HAS_KIND(b, JV_KIND_NUMBER));

#ifdef USE_DECNUM
  if (JVP_HAS_FLAGS(a, JVP_FLAGS_NUMBER_LITERAL) && JVP_HAS_FLAGS(b, JVP_FLAGS_NUMBER_LITERAL)) {
    struct {
      decNumber number;
      decNumberUnit units[1];
    } res;

    decNumberCompare(&res.number,
                     jvp_dec_number_ptr(a),
                     jvp_dec_number_ptr(b),
                     DEC_CONTEXT()
                     );
    if (decNumberIsZero(&res.number)) {
      return 0;
    } else if (decNumberIsNegative(&res.number)) {
      return -1;
    } else {
      return 1;
    }
  }
#endif
  double da = jv_number_value(a), db = jv_number_value(b);
  if (da < db) {
    return -1;
  } else if (da == db) {
    return 0;
  } else {
    return 1;
  }
}
