import pytest
import hashlib

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Ripemd160, Bytes

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, ripemd160


input_sats = 100000

contract = './test/res/p2sh.scrypt'
compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()
P2SH = scryptlib.contract.build_contract_class(desc)

contract = './test/res/counter.scrypt'
compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()
DemoContract = scryptlib.contract.build_contract_class(desc)

demo_contract = DemoContract()
script_hash_sha256 = hashlib.sha256(demo_contract.code_part.to_bytes()).digest()
script_hash = ripemd160(script_hash_sha256)

p2sh = P2SH(Ripemd160(script_hash))


def test_verify_correct():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = p2sh.locking_script
    context.utxo.value = input_sats

    tx_out = TxOutput(value=input_sats, script_pubkey=demo_contract.code_part)
    context.tx.outputs.append(tx_out)

    preimage = scryptlib.utils.get_preimage_from_input_context(context)

    verify_result = p2sh.redeem(Bytes(demo_contract.code_part.to_bytes()),
            SigHashPreimage(preimage)).verify(context)
    assert verify_result == True

