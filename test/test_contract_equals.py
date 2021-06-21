import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int


EQUAL_VAL = 1232326327186381

contract = './test/res/equals.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Equals = scryptlib.contract.build_contract_class(desc)
contract_obj = Equals(Int(EQUAL_VAL))


def test_verify_correct():
    verify_result = contract_obj.equals(Int(EQUAL_VAL)).verify()
    assert verify_result == True


def test_verify_incorrect0():
    verify_result = contract_obj.equals(Int(342768423)).verify()
    assert verify_result == False


def test_verify_incorrect1():
    verify_result = contract_obj.equals(Int(-1232326327186381)).verify()
    assert verify_result == False

