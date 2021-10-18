import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Bytes


contract = './test/res/alias.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Alias = scryptlib.contract.build_contract_class(desc)

type_classes = scryptlib.contract.build_type_classes(desc)
Male = type_classes['Male']
Female = type_classes['Female']
Integer = type_classes['Integer']
Name = type_classes['Name']
Token = type_classes['Token']
Tokens = type_classes['Tokens']
Coinbase = type_classes['Coinbase']
Time = type_classes['Time']
Height = type_classes['Height']
MaleAAA = type_classes['MaleAAA']
Person = type_classes['Person']
Block = type_classes['Block']


bob = MaleAAA({
        'age': 8,
        'name': Bytes(str.encode('Bob', encoding='utf-8')),
        'token': 80
        })
alice = Female({
        'age': 7,
        'name': Bytes(str.encode('Alice', encoding='utf-8')),
        'token': 150
        })

alias = Alias(alice)


def test_array_unlock_correct():
    verify_result =  alias.unlock(bob).verify()
    assert verify_result == True


def test_unlock_wrong():
    charlie = MaleAAA({
            'age': 2,
            'name': Bytes(str.encode('Charlie', encoding='utf-8')),
            'token': 10
            })
    verify_result =  alias.unlock(charlie).verify()
    assert verify_result == False


def test_set_token_correct():
    verify_result = alias.setToken([10, 20, 25]).verify()
    assert verify_result == True

def test_set_token_incorrect_val():
    verify_result = alias.setToken([11, 20, 25]).verify()
    assert verify_result == False

def test_set_token_wrong_array_len():
    with pytest.raises(Exception):
        alias.setToken([11, 20, 25, 23]).verify()
