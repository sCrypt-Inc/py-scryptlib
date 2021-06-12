import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160

import bitcoinx
from bitcoinx import SigHash, PrivateKey, pack_byte, TxOutput

COUNTER_INITIAL_VAL = 1

contract = './test/res/counter.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Counter = scryptlib.contract.build_contract_class(desc)
counter_obj = Counter()

# Set initial coutner value as OP_RETURN data in the locking script.
counter_obj.set_data_part(COUNTER_INITIAL_VAL.to_bytes(length=1, byteorder='little'))


# For validation we need to set the correct output for the subsequent transaction (which "unclocks" our contract).
context = scryptlib.utils.create_dummy_input_context()
subsequent_counter_val = 2
new_locking_script = counter_obj.code_part << subsequent_counter_val.to_bytes(1, 'little')
tx_out = TxOutput(value=0, script_pubkey=new_locking_script)
context.tx.outputs = [tx_out]
#preimage = scryptlib.utils.get_preimage(
#
#
#def test_verify_correct():
#    verify_result = counter_obj.unlock(preimage).verify(context)
#    assert verify_result == True


