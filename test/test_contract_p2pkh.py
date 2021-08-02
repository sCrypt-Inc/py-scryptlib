import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160

import bitcoinx
from bitcoinx import SigHash, PrivateKey, pack_byte


key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub = key_priv.public_key
pubkey_hash = key_pub.hash160()

wrong_key_priv = PrivateKey.from_arbitrary_bytes(b'somethingelse')
wrong_key_pub = wrong_key_priv.public_key

contract = './test/res/p2pkh.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

P2PKH = scryptlib.contract.build_contract_class(desc)
p2pkh_obj = P2PKH(Ripemd160(pubkey_hash))

context = scryptlib.utils.create_dummy_input_context()

sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
input_idx = 0
utxo_satoshis = context.utxo.value
sighash = context.tx.signature_hash(input_idx, utxo_satoshis, p2pkh_obj.locking_script, sighash_flag)


def test_verify_correct_key():
    sig = key_priv.sign(sighash, hasher=None)
    sig = sig + pack_byte(sighash_flag)
    verify_result = p2pkh_obj.unlock(Sig(sig), PubKey(key_pub)).verify(context)
    assert verify_result == True


def test_verify_correct():
    sig = wrong_key_priv.sign(sighash, hasher=None)
    sig = sig + pack_byte(sighash_flag)
    with pytest.raises(bitcoinx.VerifyFailed):
       p2pkh_obj.unlock(Sig(sig), PubKey(wrong_key_pub)).verify(context)

