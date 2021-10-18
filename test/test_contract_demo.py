import pytest

import scryptlib.utils
import scryptlib.contract


contract = './test/res/demo.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Demo = scryptlib.contract.build_contract_class(desc)
demo = Demo(7, 4)


def test_verify_correct():
    verify_result = demo.add(7 + 4).verify()
    assert verify_result == True


def test_verify_wrong():
    verify_result = demo.add(7 - 4).verify()
    assert verify_result == False

