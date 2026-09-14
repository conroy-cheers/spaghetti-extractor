"""Canonical transfers shared by reader qualification and its real caller."""

from spaghetti_extractor.transfer.model import _Action, _Node, _Transfer

DOMAIN_TRAP_ESP = 0x410000 + 1020


def reader_transfers(*, private_write=False, domain_trap=False, clobber_ecx=False, clobber_before_cut=False,
                    write_buffer=False, restored_outside_write=False, frame_base_offset=None):
    assert not (private_write and domain_trap)
    ids = ["semantic-transfer:original-cutpoint-00001000-00001001",
           "semantic-transfer:original-cutpoint-00001001-00001002"]
    nodes = (_Node("reg", aux=1), _Node("load", (0,), aux=1), _Node("reg", aux=7),
             _Node("load", (2,), aux=4), _Node("const", immediate=4), _Node("add32", (2, 4)))
    stores, result = (), 1
    if private_write:
        if frame_base_offset is None:
            nodes += (_Node("const", immediate=8), _Node("sub32", (2, 6)), _Node("const", immediate=77))
            stores = (_Action("memory_write", (7, 8), aux=1),)
        else:
            nodes += (_Node("reg", aux=6), _Node("const", immediate=8),
                      _Node("sub32", (6, 7)), _Node("const", immediate=77))
            stores = (_Action("memory_write", (8, 9), aux=1),)
    if domain_trap:
        nodes += (_Node("const", immediate=DOMAIN_TRAP_ESP), _Node("eq", (2, 6)),
                  _Node("const", immediate=1), _Node("add32", (1, 8)), _Node("ite", (7, 9, 1)))
        result = 10
    if clobber_ecx:
        nodes += (_Node("const", immediate=77),)
        stores += (_Action("set_reg", (len(nodes) - 1,), aux=2),)
    if write_buffer:
        nodes += (_Node("const", immediate=77),)
        stores += (_Action("memory_write", (0, len(nodes) - 1), aux=1),)
    if restored_outside_write:
        assert write_buffer
        index = len(nodes)
        nodes += (_Node("const", immediate=4), _Node("add32", (0, index)),
                  _Node("load", (index + 1,), aux=1), _Node("const", immediate=77))
        stores += (_Action("memory_write", (index + 1, index + 3), aux=1),
                   _Action("memory_write", (index + 1, index + 2), aux=1))
    first_nodes = (_Node("const", immediate=77),) if clobber_before_cut else ()
    first_actions = (_Action("eval_word", (0,)), _Action("set_reg", (0,), aux=2)) if clobber_before_cut else ()
    if frame_base_offset is not None:
        index = len(first_nodes)
        first_nodes += (_Node("reg", aux=7), _Node("const", immediate=frame_base_offset),
                        _Node("add32", (index, index + 1)))
        first_actions += tuple(_Action("eval_word", (i,)) for i in range(index, index + 3))
        first_actions += (_Action("set_reg", (index + 2,), aux=6),)
    return [
        _Transfer(ids[0], "a" * 64, "b" * 64, 4096, first_nodes, (),
            (*first_actions, _Action("outcome_jump", (4097,))), (), ()),
        _Transfer(ids[1], "a" * 64, "b" * 64, 4097, nodes, (),
            (*( _Action("eval_word", (i,)) for i in range(len(nodes))),
             *stores, _Action("set_reg", (result,), aux=0), _Action("set_reg", (5,), aux=7),
             _Action("outcome_return", (3,))), (), ())]
