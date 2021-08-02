import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int

import bitcoinx
from bitcoinx import SigHash, TxOutput, Script


contract = './test/res/dynamicArrayDemo.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Demo = scryptlib.contract.build_contract_class(desc)
demo = Demo()


def test_verify_correct():
    verify_result = demo.test(0).verify()
    assert verify_result == True

