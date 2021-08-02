import pytest
import hashlib

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int, Ripemd160, Sha256, PubKey, Sig, Bytes

import bitcoinx
from bitcoinx import SigHash, TxOutput, Script, PrivateKey, P2PKH_Address, Bitcoin, pack_byte


contract = './test/res/hashpuzzle.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

secret = b'abc'
h_secret = hashlib.sha256(secret).digest()

HashPuzzle = scryptlib.contract.build_contract_class(desc)
hash_puzzle = HashPuzzle(Sha256(h_secret))


def test_verify_correct():
    verify_result = hash_puzzle.verify(Bytes(secret)).verify()
    assert verify_result == True


def test_verify_incorrect():
    verify_result = hash_puzzle.verify(Bytes(secret + b'ff')).verify()
    assert verify_result == False

