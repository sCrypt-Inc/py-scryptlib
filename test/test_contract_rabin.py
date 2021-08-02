import pytest
import rabin

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Bytes

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script


contract = './test/res/rabin.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

RabinSig = scryptlib.contract.build_contract_class(desc)
rabin_obj = RabinSig()


def test_verify_correct():
    seed = b'\xff'
    p, q = rabin.gen_prime_pair(seed)
    n = p * q
    message = bytes.fromhex('00112233445566778899aabbccddeeff')
    sig, pad = rabin.sign_rabin(p, q, message)

    padding_bytes = b'\x00' * pad

    verify_result = rabin_obj.verifySig(
            sig,
            Bytes(message),
            Bytes(padding_bytes),
            n).verify()
    assert verify_result == True


def test_verify_wrong_padding():
    seed = b'\xff'
    p, q = rabin.gen_prime_pair(seed)
    n = p * q
    message = bytes.fromhex('00112233445566778899aabbccddeeff')
    sig, pad = rabin.sign_rabin(p, q, message)

    padding_bytes = b'\x00' * (pad + 1)

    verify_result = rabin_obj.verifySig(
            sig,
            Bytes(message),
            Bytes(padding_bytes),
            n).verify()
    assert verify_result == False


def test_verify_wrong_sig():
    seed = b'\xff'
    p, q = rabin.gen_prime_pair(seed)
    n = p * q
    message = bytes.fromhex('00112233445566778899aabbccddeeff')
    sig, pad = rabin.sign_rabin(p, q, message)

    padding_bytes = b'\x00' * (pad + 1)

    verify_result = rabin_obj.verifySig(
            sig + 1,
            Bytes(message),
            Bytes(padding_bytes),
            n).verify()
    assert verify_result == False

