import pytest

import scryptlib.utils
import scryptlib.contract


contract = './test/res/structdemo.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

type_classes = scryptlib.contract.build_type_classes(desc)

Female = type_classes['Female']
female_obj = Female({
      'name': bytes.fromhex('7361746f736869206e616b616d6f746f'),
      'leftHanded': False,
      'age': 33,
      'addr': bytes.fromhex('68656c6c6f20776f726c6421')
    })

