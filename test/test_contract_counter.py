import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int

import bitcoinx
from bitcoinx import SigHash, TxOutput, Script


COUNTER_INITIAL_VAL = 0

contract = './test/res/counter.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Counter = scryptlib.contract.build_contract_class(desc)
counter_obj = Counter()

# Set initial coutner value as OP_RETURN data in the locking script.
counter_obj.set_data_part(scryptlib.utils.get_push_int(COUNTER_INITIAL_VAL))


def test_verify_correct():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = counter_obj.locking_script

    subsequent_counter_val_bytes = scryptlib.utils.get_push_int(COUNTER_INITIAL_VAL + 1)
    new_locking_script = counter_obj.code_part << Script(subsequent_counter_val_bytes)
    tx_out = TxOutput(value=0, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    new_output_satoshis = 0
    verify_result = counter_obj.increment(SigHashPreimage(preimage), Int(new_output_satoshis)).verify(context)
    assert verify_result == True


def test_verify_incorrect_increment():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = counter_obj.locking_script

    subsequent_counter_val_bytes = scryptlib.utils.get_push_int(COUNTER_INITIAL_VAL + 2)
    new_locking_script = counter_obj.code_part << Script(subsequent_counter_val_bytes)
    tx_out = TxOutput(value=0, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    new_output_satoshis = 0
    verify_result = counter_obj.increment(SigHashPreimage(preimage), Int(new_output_satoshis)).verify(context)
    assert verify_result == False


def test_verify_incorrect_sat_amount():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = counter_obj.locking_script

    subsequent_counter_val_bytes = scryptlib.utils.get_push_int(COUNTER_INITIAL_VAL + 1)
    new_locking_script = counter_obj.code_part << Script(subsequent_counter_val_bytes)
    tx_out = TxOutput(value=0, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    new_output_satoshis = 100
    verify_result = counter_obj.increment(SigHashPreimage(preimage), Int(new_output_satoshis)).verify(context)
    assert verify_result == False

