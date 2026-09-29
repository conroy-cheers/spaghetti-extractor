/* Shared private value boundary for the selected concat/append replacement group.
 * Each pack owns one jv reference. take transfers it exactly once; borrow is only
 * valid while that owned value remains live. Both implementations obey this API.
 * Include jv.h and the generated component interface before this header.
 */
#ifndef SPX_FIXTURE_VALUE_TRANSPORT_H
#define SPX_FIXTURE_VALUE_TRANSPORT_H
spx_jv_value_v2 spx_value_pack(jv value);
jv spx_value_take(spx_jv_value_v2 value);
jv spx_value_borrow(spx_jv_value_v2 value);
int spx_value_valid(spx_jv_value_v2 value);
void spx_values_finish(void);
#endif
