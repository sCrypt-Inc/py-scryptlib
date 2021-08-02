import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int, Ripemd160

import bitcoinx
from bitcoinx import SigHash, TxOutput, Script, PrivateKey, P2PKH_Address, Bitcoin


COUNTER_INITIAL_VAL = 0
out_sats = 22222
change_sats = 11111

key_priv_0 = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub_0 = key_priv_0.public_key
pkh_0 = key_pub_0.hash160()

contract = './test/res/advancedCounter.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Counter = scryptlib.contract.build_contract_class(desc)
counter = Counter()

counter.set_data_part(scryptlib.utils.get_push_int(COUNTER_INITIAL_VAL))

context = scryptlib.utils.create_dummy_input_context()
context.utxo.script_pubkey = counter.locking_script

subsequent_counter_val_bytes = scryptlib.utils.get_push_int(COUNTER_INITIAL_VAL + 1)
new_locking_script = counter.code_part << Script(subsequent_counter_val_bytes)

# Counter output
tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
context.tx.outputs.append(tx_out)

# Change output
pkh_0_out = TxOutput(change_sats, P2PKH_Address(pkh_0, Bitcoin).to_script())
context.tx.outputs.append(pkh_0_out)

sighash_flag = SigHash(SigHash.ANYONE_CAN_PAY | SigHash.ALL | SigHash.FORKID)
preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

def test_verify_correct():
    verify_result = counter.increment(SigHashPreimage(preimage), out_sats, Ripemd160(pkh_0), change_sats).verify(context)
    assert verify_result == True


def test_verify_wrong_sats():
    verify_result = counter.increment(SigHashPreimage(preimage), out_sats + 1, Ripemd160(pkh_0), change_sats).verify(context)
    assert verify_result == False


def test_verify_wrong_sats2():
    verify_result = counter.increment(SigHashPreimage(preimage), out_sats, Ripemd160(pkh_0), change_sats - 1).verify(context)
    assert verify_result == False


def test_verify_wrong_nextval():
    subsequent_counter_val_bytes = scryptlib.utils.get_push_int(COUNTER_INITIAL_VAL + 2)
    new_locking_script = counter.code_part << Script(subsequent_counter_val_bytes)
    tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
    context.tx.outputs[0] = tx_out
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

    verify_result = counter.increment(SigHashPreimage(preimage), out_sats, Ripemd160(pkh_0), change_sats - 1).verify(context)
    assert verify_result == False

