import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int

import bitcoinx
from bitcoinx import SigHash, TxOutput, Script


out_amount = 222222

contract = './test/res/conwaygol.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

GameOfLife = scryptlib.contract.build_contract_class(desc)
gol = GameOfLife()

# Intial GOL board.
b0 = []
b0.append('00000000000000')
b0.append('00000000000000')
b0.append('00010101000000')
b0.append('00000001000000')
b0.append('00010101000000')
b0.append('00000000000000')
b0.append('00000000000000')
b0 = bytes.fromhex(''.join(b0))

gol.set_data_part(b0)

# Correct next GOL board.
b1 = []
b1.append('00000000000000')
b1.append('00000100000000')
b1.append('00000101000000')
b1.append('00000000010000')
b1.append('00000101000000')
b1.append('00000100000000')
b1.append('00000000000000')
b1 = bytes.fromhex(''.join(b1))

# Wrong next GOL board.
wb1 = []
wb1.append('00000000001000')
wb1.append('00000100000000')
wb1.append('00000101000000')
wb1.append('00000000000000')
wb1.append('00000101000000')
wb1.append('00000100000000')
wb1.append('00000000010000')
wb1 = bytes.fromhex(''.join(wb1))


def test_verify_correct():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = gol.locking_script

    new_locking_script = Script(gol.code_part.to_bytes() + b1)
    tx_out = TxOutput(value=out_amount, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

    verify_result = gol.play(out_amount, SigHashPreimage(preimage)).verify(context)
    assert verify_result == True


def test_verify_wrong_output():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = gol.locking_script

    new_locking_script = Script(gol.code_part.to_bytes() + wb1)
    tx_out = TxOutput(value=out_amount, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

    verify_result = gol.play(out_amount, SigHashPreimage(preimage)).verify(context)
    assert verify_result == False
