import pytest
import random
import os

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Bool, Bytes

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, sha256


contract = './test/res/serializer.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Demo = scryptlib.contract.build_contract_class(desc)
demo = Demo()

def test_verify_bool():
    verify_result = demo.testBool(True).verify()
    assert verify_result == True

    verify_result = demo.testBool(False).verify()
    assert verify_result == True

    verify_result = demo.testBool(Bool(True)).verify()
    assert verify_result == True

    verify_result = demo.testBool(Bool(False)).verify()
    assert verify_result == True


def test_verify_special_int():
    verify_result = demo.testInt(0).verify()
    assert verify_result == True

    verify_result = demo.testInt(-1).verify()
    assert verify_result == True


def test_verify_normal_int():
    for num in [1, 0x0a, 100, -1000, 12983128039190833298]:
        verify_result = demo.testInt(num).verify()
        assert verify_result == True

    for num in [1, 0x0a, 100, -1000, 12983128039190833298]:
        verify_result = demo.testInt(Int(num)).verify()
        assert verify_result == True


def test_verify_bytes():
    verify_result = demo.testBytes(Bytes('1100')).verify()
    assert verify_result == True

    verify_result = demo.testBytes(Bytes('1100ffff')).verify()
    assert verify_result == True


def test_verify_pushdata_1():
    verify_result = demo.testBytes(Bytes(b'\x11' * 76)).verify()
    assert verify_result == True

    verify_result = demo.testBytes(Bytes(b'\xff' * (0x100 - 1))).verify()
    assert verify_result == True


def test_verify_pushdata_2():
    verify_result = demo.testBytes(Bytes(b'\x11' * (2**8))).verify()
    assert verify_result == True


#def test_verify_pushdata_4():
#    verify_result = demo.testBytes(Bytes(b'\x11' * (2**16))).verify()
#    assert verify_result == True


def test_verify_main():
    bounds = [0x0, 0xfc, 0xffff]
    for i, bound in enumerate(bounds[:-1]):
        for j in range(0, 10):
            n = random.randint(0, 2**32)
            m = random.randint(bound, bounds[i+1])
            #h = random.randbytes(m)
            h = os.urandom(m)

            verify_result = demo.main(n % 2 == 0, Bytes(h), n).verify()
            assert verify_result == True

