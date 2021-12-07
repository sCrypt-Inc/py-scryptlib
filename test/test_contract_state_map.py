import pytest

from bitcoinx import TxOutput

import scryptlib
from scryptlib.types import *

contract = './test/res/stateMap.scrypt'
compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

StateMap = scryptlib.build_contract_class(desc)
MapEntry = scryptlib.contract.build_type_classes(desc)['MapEntry']

# Initialize with empty bytes.
state_map = StateMap(Bytes(b''))

hm = HashedMap(Int, Int)


def get_context(hashed_map):
    new_ls = state_map.get_state_script({'_mpData': Bytes(hashed_map.hex)})

    context = scryptlib.create_dummy_input_context()
    context.utxo.script_pubkey = state_map.locking_script

    tx_out = TxOutput(value=0, script_pubkey=new_ls)
    context.tx.outputs.append(tx_out)

    return context


def test_verify_insert():
    kv_pairs = [(Int(3), Int(1)),
                (Int(5), Int(6)),
                (Int(0), Int(11)),
                (Int(1), Int(5))]

    for key, val in kv_pairs:
        hm.set(key, val)
        context = get_context(hm)
        preimage = scryptlib.get_preimage_from_input_context(context)

        map_entry = MapEntry({
            'key': key,
            'val': val,
            'keyIndex': hm.key_index(key)})
        verfiy_result = state_map.insert(map_entry, SigHashPreimage(preimage)).verify(context)
        assert verfiy_result == True

        state_map._mpData = Bytes(hm.hex)


def test_verify_update():
    kv_pairs = [(Int(1), Int(6)),
                (Int(1), Int(8)),
                (Int(0), Int(1))]

    for key, val in kv_pairs:
        hm.set(key, val)
        context = get_context(hm)
        preimage = scryptlib.get_preimage_from_input_context(context)

        map_entry = MapEntry({
            'key': key,
            'val': val,
            'keyIndex': hm.key_index(key)})
        verfiy_result = state_map.update(map_entry, SigHashPreimage(preimage)).verify(context)
        assert verfiy_result == True

        state_map._mpData = Bytes(hm.hex)


def test_verify_delete():
    keys = [1, 5, 3, 0]

    for key in keys:
        key_index = hm.key_index(key)
        hm.delete(key)

        context = get_context(hm)
        preimage = scryptlib.get_preimage_from_input_context(context)

        verfiy_result = state_map.delete(key, key_index, SigHashPreimage(preimage)).verify(context)
        assert verfiy_result == True

        state_map._mpData = Bytes(hm.hex)

