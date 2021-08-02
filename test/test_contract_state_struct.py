import pytest

import scryptlib.utils
import scryptlib.contract
import scryptlib.serializer
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, sha256


contract = './test/res/stateStruct.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Counter = scryptlib.contract.build_contract_class(desc)
counter = Counter()

out_sats = 222222


def test_verify_correct():

    # Intial state
    state = {
            'counter': 11,
            'buf': b'\x12\x34',
            'flag': True
            }

    counter.set_data_part(state)

    # Alter state
    state['counter'] += 1
    state['buf'] += b'\xff\xff'
    state['flag'] = False

    serialized_state = scryptlib.serializer.serialize_state(state)
    new_locking_script = Script(counter.code_part.to_bytes() + serialized_state)

    # Deserialize state from new locking script
    new_state = scryptlib.serializer.deserialize_state(new_locking_script, state)
    assert new_state['counter'] == 12
    assert new_state['buf'] == b'\x12\x34\xff\xff'
    assert new_state['flag'] == False


    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = counter.locking_script

    tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)
    
    preimage = scryptlib.utils.get_preimage_from_input_context(context)

    verfiy_result = counter.mutate(SigHashPreimage(preimage), out_sats).verify(context)
    assert verfiy_result == True



