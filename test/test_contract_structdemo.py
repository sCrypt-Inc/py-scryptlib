import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Bytes

import bitcoinx


contract = './test/res/structdemo.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

StructDemo = scryptlib.contract.build_contract_class(desc)
type_classes = scryptlib.contract.build_type_classes(desc)

Person = type_classes['Person']
Female = type_classes['Female']

struct_demo = StructDemo(Person({
      'name': Bytes(bytes.fromhex('7361746f736869206e616b616d6f746f')),
      'leftHanded': False,
      'age': 33,
      'addr': Bytes(bytes.fromhex('68656c6c6f20776f726c6421'))
    }))

def test_correct():
    verify_result = struct_demo.main(Person({
          'name': Bytes(bytes.fromhex('7361746f736869206e616b616d6f746f')),
          'leftHanded': False,
          'age': 33,
          'addr': Bytes(bytes.fromhex('68656c6c6f20776f726c6421'))
        })).verify()
    assert verify_result == True

def test_wrong_value():
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = struct_demo.main(Person({
              'name': Bytes(bytes.fromhex('7361746f736869206e616b616d6f746f')),
              'leftHanded': True,
              'age': 33,
              'addr': Bytes(bytes.fromhex('68656c6c6f20776f726c6421'))
            })).verify()

def test_wrong_value2():
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = struct_demo.main(Person({
              'name': Bytes(bytes.fromhex('7361746f736869206e616b616d6f746f')),
              'leftHanded': True,
              'age': 34,
              'addr': Bytes(bytes.fromhex('68656c6c6f20776f726c6421'))
            })).verify()

def test_wrong_value3():
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = struct_demo.main(Person({
              'name': Bytes(bytes.fromhex('7361746c736869206e616b616d6f746f')),
              'leftHanded': False,
              'age': 33,
              'addr': Bytes(bytes.fromhex('68656c6c6f20776f726c6421'))
            })).verify()

def test_type_alias():
    verify_result = struct_demo.main(Female({
          'name': Bytes(bytes.fromhex('7361746f736869206e616b616d6f746f')),
          'leftHanded': False,
          'age': 33,
          'addr': Bytes(bytes.fromhex('68656c6c6f20776f726c6421'))
        })).verify()
    assert verify_result == True

