import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int, Bool

from bitcoinx import SigHash, TxOutput


COUNTER_INITIAL_VAL = 0

contract = './test/res/statecounter.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

StateCounter = scryptlib.contract.build_contract_class(desc)
counter_obj = StateCounter(COUNTER_INITIAL_VAL)


def test_verify_correct_constructor():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = counter_obj.locking_script

    new_locking_script = counter_obj.get_state_script({
        "counter": COUNTER_INITIAL_VAL + 1
        })

    tx_out = TxOutput(value=0, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    new_output_satoshis = 0
    verify_result = counter_obj.unlock(SigHashPreimage(preimage), Int(new_output_satoshis)).verify(context)
    assert verify_result == True


def test_verify_correct_member_var():
    counter_obj.counter = 1

    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = counter_obj.locking_script

    new_locking_script = counter_obj.get_state_script({
        "counter": counter_obj.counter + 1
        })

    tx_out = TxOutput(value=0, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    new_output_satoshis = 0
    verify_result = counter_obj.unlock(SigHashPreimage(preimage), Int(new_output_satoshis)).verify(context)
    assert verify_result == True


def test_verify_wrong_type():
    counter_obj.counter = Bool(False)
    with pytest.raises(Exception):
        counter_obj.locking_script
