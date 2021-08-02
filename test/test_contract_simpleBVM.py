import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Bytes

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, sha256


input_script = '525593569357936094539354935894'

contract = './test/res/simpleBVM.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

SimpleBVM = scryptlib.contract.build_contract_class(desc)
simple_BVM = SimpleBVM(3)


def test_verify_correct():
    verify_result = simple_BVM.unlock(Bytes(input_script)).verify()
    assert verify_result == True


def test_verify_incorrect():
    with pytest.raises(bitcoinx.VerifyFailed):
        simple_BVM.unlock(Bytes(input_script + '52')).verify()
