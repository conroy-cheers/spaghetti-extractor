#include "jv.h"
#include "portable-component-implementation.h"
#include "value-transport.h"
#include "value-runtime-impl.h"
int spx_value_valid(spx_jv_value_v2 value) { return jv_is_valid(spx_value_borrow(value)); }
