import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Ripemd160, Bytes, Sig

import bitcoinx


contract = './test/res/arraydemo.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

ArrayDemo = scryptlib.contract.build_contract_class(desc)

type_classes = scryptlib.contract.build_type_classes(desc)
ST1 = type_classes['ST1']
ST2 = type_classes['ST2']
ST3 = type_classes['ST3']
AliasST2 = type_classes['AliasST2']
MDArrayST1 = type_classes['MDArrayST1']

arraydemo = ArrayDemo(33, [
            True,
            False
        ], [
            3311,
            333
        ], [
            Ripemd160('2235c953af7c83cffa6f192477fb431941400162'),
            Ripemd160('0176de27477fb7ffd7c99a7e9b931c22fd125c2b')
        ], [
            [
                [
                    1, 2, 3, 4
                ],
                [
                    5, 6, 7, 8
                ],
                [
                    9, 10, 11, 12
                ]
            ],
            [
                [
                    13, 14, 15, 16
                ],
                [
                    17, 18, 19, 20
                ],
                [
                    21, 22, 23, 24
                ]
            ]
        ],
            [[[ST1({
                'x': False,
                'y': Bytes(bytes.fromhex('aa')),
                'i': 1
            }), ST1({
                'y': Bytes(bytes.fromhex('bb')),
                'x': True,
                'i': 2
            })], [ST1({
                'x': False,
                'y': Bytes(bytes.fromhex('cc')),
                'i': 3
            }), ST1({
                'y': Bytes(bytes.fromhex('dd')),
                'x': True,
                'i': 4
            })]], [[ST1({
                'x': False,
                'y': Bytes(bytes.fromhex('ee')),
                'i': 5
            }), ST1({
                'y': Bytes(bytes.fromhex('ff')),
                'x': True,
                'i': 6
            })], [ST1({
                'x': False,
                'y': Bytes(bytes.fromhex('00')),
                'i': 7
            }), ST1({
                'y': Bytes(bytes.fromhex('11')),
                'x': True,
                'i': 8
            })]]]
        )


def test_array_constructor_correct():
    verify_result =  arraydemo.testArrayConstructor(
            33,
            [
                True,
                False
            ],
            [
                3311,
                333
            ],
            [
                Ripemd160('2235c953af7c83cffa6f192477fb431941400162'),
                Ripemd160('0176de27477fb7ffd7c99a7e9b931c22fd125c2b')
            ]
        ).verify()
    assert verify_result == True


def test_array_constructor_wrong_val():
    with pytest.raises(bitcoinx.VerifyFailed):
        arraydemo.testArrayConstructor(
                33,
                [
                    True,
                    False
                ],
                [
                    3312,
                    333
                ],
                [
                    Ripemd160('2235c953af7c83cffa6f192477fb431941400162'),
                    Ripemd160('0176de27477fb7ffd7c99a7e9b931c22fd125c2b')
                ]
            ).verify()


def test_array_constructor_wrong_params():
    with pytest.raises(Exception):
        arraydemo.testArrayConstructor(
                True,
                [
                    True,
                    False
                ],
                [
                    False
                ],
                [
                    Ripemd160('2235c953af7c83cffa6f192477fb431941400162'),
                    Ripemd160('0176de27477fb7ffd7c99a7e9b931c22fd125c2b')
                ]
            ).verify()


def test_unlock_ST2_correct():
    verify_result = arraydemo.unlockST2(ST2(
            {
                'x': True,
                'y': Bytes('68656c6c6f20776f726c6420'),
                'st3': ST3({
                    'x': True,
                    'y': [4, 5, 6],
                    'st1': ST1({
                        'x': False,
                        'y': Bytes('68656c6c6f20776f726c6420'),
                        'i': 42
                    })
                })
            })
        ).verify()
    assert verify_result == True


def test_array_int_correct():
    verify_result = arraydemo.testArrayInt([0, 1321, 243213, 32132]).verify()
    assert verify_result == True


def test_array_bool_correct():
    verify_result = arraydemo.testArrayBool([True, True, False, True, True]).verify()
    assert verify_result == True


def test_array_ripemd160_correct():
    verify_result = arraydemo.testArrayRipemd160([
        Ripemd160('0176de27477fb7ffd7c99a7e9b931c22fd125c2b'),
        Ripemd160('0176de27477fb7ffd7c99a7e9b931c22fd125c2b')]).verify()
    assert verify_result == True


def test_array_sig_correct():
    verify_result = arraydemo.testArraySig([
        Sig('30440220349eb89c004114bf238ea1b5db996b709675a9446aa33677f2848e839d64dfe2022046af3cf48ef13855594e7cc8c31771c5b159af19ea077b9c986beacf9a43791841'),
        Sig('30440220349eb89c004114bf238ea1b5db996b709675a9446aa33677f2848e839d64dfe2022046af3cf48ef13855594e7cc8c31771c5b159af19ea077b9c986beacf9a437918414444')]).verify()
    assert verify_result == True


def test_unlock_correct():
    verify_result = arraydemo.unlock([
            [
                3, 1, 2
            ],
            [4, 5, 6]
        ],
            [
                1, 32
            ]
        ).verify()
    assert verify_result == True

