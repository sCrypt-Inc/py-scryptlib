import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160, SigHashPreimage

import bitcoinx
from bitcoinx import SigHash, TxOutput


contract = './test/res/clone.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Clone = scryptlib.contract.build_contract_class(desc)
clone = Clone()

context = scryptlib.utils.create_dummy_input_context()
context.utxo.script_pubkey = clone.locking_script

new_locking_script = clone.locking_script
tx_out = TxOutput(value=0, script_pubkey=new_locking_script)
context.tx.outputs.append(tx_out)

sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)


def test_verify_correct():
    verify_result = clone.unlock(SigHashPreimage(preimage)).verify(context)
    assert verify_result == True


