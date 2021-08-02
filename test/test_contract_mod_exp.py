import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script


contract = './test/res/modExp.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Demo = scryptlib.contract.build_contract_class(desc)


def test_verify_correct():
    demo = Demo(497)
    verify_result = demo.main(4, 13, 445).verify()
    assert verify_result == True


def test_verify_correct2():
    demo = Demo(10000000000000000000000000000000000000000)
    verify_result = demo.main(
            2988348162058574136915891421498819466320163312926952423791023078876139,
            2351399303373464486466122544523690094744975233415544072992656881240319,
            1527229998585248450016808958343740453059
        ).verify()
    assert verify_result == True


def test_verify_incorrect():
    demo = Demo(498)
    verify_result = demo.main(4, 13, 445).verify()
    assert verify_result == False
