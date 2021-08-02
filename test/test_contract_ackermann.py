import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160

import bitcoinx
from bitcoinx import SigHash, PrivateKey, pack_byte


contract = './test/res/ackermann.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Ackermann = scryptlib.contract.build_contract_class(desc)
ackermann = Ackermann(2, 1)


def test_verify_correct():
    verify_result = ackermann.unlock(5).verify()
    assert verify_result == True


def test_verify_wrong_1():
    verify_result = ackermann.unlock(6).verify()
    assert verify_result == False


def test_verify_wrong_2():
    verify_result = ackermann.unlock(-1).verify()
    assert verify_result == False
