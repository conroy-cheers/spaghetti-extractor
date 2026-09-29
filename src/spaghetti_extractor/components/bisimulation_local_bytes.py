"""Checked bridge from scoped C byte views to the existing paired object rule.

Bindings are generated C expressions owned by the enclosing checker. A public
declaration must be lowered from typed relations before it reaches this module.
Neither this bridge nor a live pointer discharges a supplier's no-escape rule.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class LocalBytesBinding:
    type_id: str
    address: str
    extent: str
    permissions: int


def source_local_bytes_runtime():
    return r'''
static struct spx_paired_object spx_source_local_bytes(
    const spx_view_v5 *view, uint32_t address, uint64_t extent, uint32_t permissions) {
  __CPROVER_assert(__CPROVER_r_ok(view,sizeof(*view)),"spx-source-local-view-live");
  __CPROVER_assume(__CPROVER_r_ok(view,sizeof(*view)));
  const spx_local_bytes_v5 *owner=view->access_context;
  __CPROVER_assert(__CPROVER_r_ok(owner,sizeof(*owner)),"spx-source-local-owner-live");
  __CPROVER_assume(__CPROVER_r_ok(owner,sizeof(*owner)));
  uint32_t shape=view->context==0 && view->read_u8==0 && view->write_u8==0 &&
    view->element_width==1U && view->extent==extent &&
    view->read==((view->base.permissions&1U)?spx_local_bytes_read:0) &&
    view->write==((view->base.permissions&2U)?spx_local_bytes_write:0) &&
    owner->live==1U && owner->generation!=0U && owner->extent<=UINT32_MAX &&
    view->base.domain==UINT64_MAX && view->base.object==spx_local_bytes_identity(owner) &&
    view->base.generation==owner->generation && view->base.extent==owner->extent &&
    permissions>=1U && permissions<=3U &&
    (view->base.permissions&permissions)==permissions &&
    (view->base.permissions&owner->permissions)==view->base.permissions &&
    view->base.offset<=owner->extent && extent<=owner->extent-view->base.offset &&
    extent<=UINT64_C(4294967296)-(uint64_t)address;
  __CPROVER_assert(shape,"spx-source-local-view-correspondence");
  __CPROVER_assume(shape);
  __CPROVER_assert(__CPROVER_r_ok(owner->bytes,owner->extent),"spx-source-local-bytes-live");
  __CPROVER_assume(__CPROVER_r_ok(owner->bytes,owner->extent));
  if(permissions&2U)
    __CPROVER_assert(__CPROVER_w_ok(owner->bytes+view->base.offset,extent),"spx-source-local-bytes-writable");
  return (struct spx_paired_object){address,permissions,1U,extent,owner->bytes+view->base.offset};
}
static uint32_t spx_source_local_owner_equal(
    const spx_local_bytes_v5 *owner,const spx_local_bytes_v5 *snapshot) {
  return owner->bytes==snapshot->bytes && owner->extent==snapshot->extent &&
    owner->generation==snapshot->generation && owner->permissions==snapshot->permissions &&
    owner->live==snapshot->live;
}
'''
