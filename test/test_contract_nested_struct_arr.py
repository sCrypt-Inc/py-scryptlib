import pytest

import scryptlib
from scryptlib.types import *


contract = '''
        struct Thing {
            int someNumber;
            OtherThing[2] otherThings;
        }

        struct OtherThing {
            bytes someBytes;
            int[3] numbers;
        }

        contract NestedStructs {
            Thing thing;

            public function unlock(int[2][3] numbers, int someNumber, bytes[2] someBytes) {
                loop (2) : i {
                    auto otherThing = this.thing.otherThings[i];
                    require(otherThing.someBytes == someBytes[i]);
                    loop (3) : j {
                        require(otherThing.numbers[j] == numbers[i][j]);
                    }
                }
                require(this.thing.someNumber == someNumber);
            }
        }
        '''

compiler_result = scryptlib.utils.compile_contract(contract, from_string=True)
desc = compiler_result.to_desc()

NestedStructs = scryptlib.build_contract_class(desc)
type_classes = scryptlib.build_type_classes(desc)

Thing = type_classes['Thing']
OtherThing = type_classes['OtherThing']

other_things = []
for i in range(2):
    other_things.append(OtherThing({
        'someBytes': Bytes('000000'),
        'numbers': [Int(0), Int(0), Int(0)],
        }))

thing = Thing({
    'someNumber': Int(123),
    'otherThings': other_things,
    })

nested_structs = NestedStructs(thing)

def test_verify_correct():
    numbers = [[0, 0, 0], [0, 0, 0]]
    some_number = 123
    some_bytes = [b'\x00\x00\x00', b'\x00\x00\x00']

    verify_result = nested_structs.unlock(numbers, some_number, some_bytes).verify()
    assert verify_result == True


def test_verify_wrong():
    numbers = [[0, 2, 0], [0, 0, 0]]
    some_number = 123
    some_bytes = [b'\x00\x00\x00', b'\x00\x00\x00']

    with pytest.raises(bitcoinx.VerifyFailed):
        nested_structs.unlock(numbers, some_number, some_bytes).verify()

    numbers = [[0, 0, 0], [0, 0, 0]]
    some_number = 124
    some_bytes = [b'\x00\x00\x00', b'\x00\x00\x00']

    verify_result = nested_structs.unlock(numbers, some_number, some_bytes).verify()
    assert verify_result == False

    numbers = [[0, 0, 0], [0, 0, 0]]
    some_number = 123
    some_bytes = [b'\x01\x00\x00', b'\x00\x00\x00']

    with pytest.raises(bitcoinx.VerifyFailed):
        nested_structs.unlock(numbers, some_number, some_bytes).verify()
