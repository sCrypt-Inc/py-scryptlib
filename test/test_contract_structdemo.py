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
Pet = type_classes['Pet']
Female = type_classes['Female']

struct_demo = StructDemo(Person({
      'name': Bytes('satoshi nakamoto'.encode('ascii')),
      'leftHanded': False,
      'age': 33,
      'addr': Bytes('hello, world!'.encode('ascii')),
      'pets': [
            Pet(
                {'name': Bytes('kala'.encode('ascii')),
                 'species': Bytes('dog'.encode('ascii'))}
                 ),
            Pet(
                {'name': Bytes('pufi'.encode('ascii')),
                 'species': Bytes('cat'.encode('ascii'))}
                 )
            ]
    }))

def test_correct():
    verify_result = struct_demo.main(Person({
          'name': Bytes('satoshi nakamoto'.encode('ascii')),
          'leftHanded': False,
          'age': 33,
          'addr': Bytes('hello, world!'.encode('ascii')),
          'pets': [
                Pet(
                    {'name': Bytes('kala'.encode('ascii')),
                     'species': Bytes('dog'.encode('ascii'))}
                     ),
                Pet(
                    {'name': Bytes('pufi'.encode('ascii')),
                     'species': Bytes('cat'.encode('ascii'))}
                     )
                ]
        })).verify()
    assert verify_result == True

def test_wrong_value():
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = struct_demo.main(Person({
              'name': Bytes('satoshi nakamoto'.encode('ascii')),
              'leftHanded': True,
              'age': 33,
              'addr': Bytes('hello, world!'.encode('ascii')),
              'pets': [
                    Pet(
                        {'name': Bytes('kala'.encode('ascii')),
                         'species': Bytes('dog'.encode('ascii'))}
                         ),
                    Pet(
                        {'name': Bytes('pufi'.encode('ascii')),
                         'species': Bytes('cat'.encode('ascii'))}
                         )
                    ]
            })).verify()

def test_wrong_value2():
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = struct_demo.main(Person({
              'name': Bytes('satoshi nakamoto'.encode('ascii')),
              'leftHanded': True,
              'age': 34,
              'addr': Bytes('hello, world!'.encode('ascii')),
              'pets': [
                    Pet(
                        {'name': Bytes('kala'.encode('ascii')),
                         'species': Bytes('dog'.encode('ascii'))}
                         ),
                    Pet(
                        {'name': Bytes('pufi'.encode('ascii')),
                         'species': Bytes('cat'.encode('ascii'))}
                         )
                    ]
            })).verify()

def test_wrong_value3():
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = struct_demo.main(Person({
              'name': Bytes('satoshi nakamoto'.encode('ascii')),
              'leftHanded': False,
              'age': 33,
              'addr': Bytes('hellou, world!'.encode('ascii')),
              'pets': [
                    Pet(
                        {'name': Bytes('kala'.encode('ascii')),
                         'species': Bytes('dog'.encode('ascii'))}
                         ),
                    Pet(
                        {'name': Bytes('pufi'.encode('ascii')),
                         'species': Bytes('cat'.encode('ascii'))}
                         )
                    ]
            })).verify()

def test_wrong_value4():
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = struct_demo.main(Person({
              'name': Bytes('satoshi nakamoto'.encode('ascii')),
              'leftHanded': False,
              'age': 33,
              'addr': Bytes('hello, world!'.encode('ascii')),
              'pets': [
                    Pet(
                        {'name': Bytes('kuki'.encode('ascii')),
                         'species': Bytes('dog'.encode('ascii'))}
                         ),
                    Pet(
                        {'name': Bytes('pufi'.encode('ascii')),
                         'species': Bytes('cat'.encode('ascii'))}
                         )
                    ]
            })).verify()

def test_type_alias():
    verify_result = struct_demo.main(Female({
          'name': Bytes('satoshi nakamoto'.encode('ascii')),
          'leftHanded': False,
          'age': 33,
          'addr': Bytes('hello, world!'.encode('ascii')),
          'pets': [
                Pet(
                    {'name': Bytes('kala'.encode('ascii')),
                     'species': Bytes('dog'.encode('ascii'))}
                     ),
                Pet(
                    {'name': Bytes('pufi'.encode('ascii')),
                     'species': Bytes('cat'.encode('ascii'))}
                     )
                ]
        })).verify()
    assert verify_result == True

