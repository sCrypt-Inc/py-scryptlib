import pytest
import hashlib

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script


input_sats = 100000
MSB_THRESHOLD = 0x7E

contract = './test/res/optimalPushtx.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

OPTX = scryptlib.contract.build_contract_class(desc)
optx = OPTX()

context = scryptlib.utils.create_dummy_input_context()
context.utxo.script_pubkey = optx.locking_script
context.utxo.value = input_sats


def test_verify_correct():
    i = 0
    while True:
        context.tx.locktime = i
        preimage = scryptlib.utils.get_preimage_from_input_context(context)
        dh = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
        if dh[0] < MSB_THRESHOLD:
            break
        i += 1
    
    verify_result = optx.validate(SigHashPreimage(preimage)).verify(context)
    assert verify_result == True
