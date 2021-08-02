import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int

import bitcoinx


contract = './test/res/matrix.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Matrix = scryptlib.contract.build_contract_class(desc)

matrix = Matrix()


def test_verify_main_correct():
    verify_result = matrix.main([
                [10, 10, 10, 10],
                [20, 20, 20, 20],
                [30, 30, 30, 30],
                [40, 40, 40, 40]
            ]).verify()
    assert verify_result == True


def test_verify_main_correct_mixed_types():
    verify_result = matrix.main([
                [10, 10, 10, Int(10)],
                [20, 20, 20, 20],
                [30, Int(30), 30, 30],
                [40, Int(40), Int(40), 40]
            ]).verify()
    assert verify_result == True


def test_verify_main_wrong_val():
    verify_result = matrix.main([
                [10, 10, 10, Int(10)],
                [20, 20, 20, 10],
                [30, Int(30), 30, 30],
                [40, Int(40), Int(40), 40]
            ]).verify()
    assert verify_result == False


def test_verify_main_wrong_param_format():
    with pytest.raises(Exception):
        verify_result = matrix.main([
                    [10, 10, 10, Int(10)],
                    [20, 20, 20],
                    [30, Int(30), 30, 30]
                ]).verify()
