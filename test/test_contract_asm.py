import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Bytes, Int, Ripemd160

import bitcoinx
from bitcoinx import SigHash, PrivateKey, pack_byte


key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub = key_priv.public_key
pubkey_hash = key_pub.hash160()

contract = './test/res/asm.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Asm = scryptlib.contract.build_contract_class(desc)
asm_vars = {
    'Asm.p2pkh.pkh': Ripemd160(pubkey_hash),
    'Asm.equalImpl.x': Int(11)
}
asm = Asm(asm_vars=asm_vars)


def test_verify_double_correct():
    verify_result = asm.double(222, 111).verify()
    assert verify_result == True


def test_verify_double_wrong():
    verify_result = asm.double(222, 121).verify()
    assert verify_result == False


def test_verify_equal_correct():
    verify_result = asm.equal(11).verify()
    assert verify_result == True


def test_verify_equal_wrong():
    verify_result = asm.equal(10).verify()
    assert verify_result == False


def test_verify_p2pkh_correct():
    context = scryptlib.utils.create_dummy_input_context()
    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    sighash = context.tx.signature_hash(0, context.utxo.value, asm.locking_script, sighash_flag)
    sig = key_priv.sign(sighash, hasher=None)
    sig = sig + pack_byte(sighash_flag)
    verify_result = asm.p2pkh(Sig(sig), PubKey(key_pub)).verify(context)
    assert verify_result == True


def test_verify_checklen_correct():
    verify_result = asm.checkLen(Bytes('1122ffee'), 4).verify()
    assert verify_result == True


def test_verify_checklenfail_correct():
    with pytest.raises(bitcoinx.VerifyFailed):
        asm.checkLenFail(Bytes('1122ffee'), 4).verify()
