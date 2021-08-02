import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160

import bitcoinx
from bitcoinx import SigHash, PrivateKey, pack_byte


key_priv_0 = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub_0 = key_priv_0.public_key
pkh_0 = key_pub_0.hash160()

key_priv_1 = PrivateKey.from_arbitrary_bytes(b'123test')
key_pub_1 = key_priv_1.public_key
pkh_1 = key_pub_1.hash160()

key_priv_2 = PrivateKey.from_arbitrary_bytes(b'te123st')
key_pub_2 = key_priv_2.public_key
pkh_2 = key_pub_2.hash160()

contract = './test/res/multiSig.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
input_idx = 0

def test_verify_correct():
    MultiSig = scryptlib.contract.build_contract_class(desc)
    multisig = MultiSig([Ripemd160(pkh_0), Ripemd160(pkh_1), Ripemd160(pkh_2)])

    context = scryptlib.utils.create_dummy_input_context()
    sighash = context.tx.signature_hash(input_idx, context.utxo.value, multisig.locking_script, sighash_flag)

    sig_0 = key_priv_0.sign(sighash, hasher=None) + pack_byte(sighash_flag)
    sig_1 = key_priv_1.sign(sighash, hasher=None) + pack_byte(sighash_flag)
    sig_2 = key_priv_2.sign(sighash, hasher=None) + pack_byte(sighash_flag)

    verify_result = multisig.unlock(
                [PubKey(key_pub_0), PubKey(key_pub_1), PubKey(key_pub_2)],
                [Sig(sig_0), Sig(sig_1), Sig(sig_2)]
            ).verify(context)
    assert verify_result == True


def test_verify_wrong_key():
    MultiSig = scryptlib.contract.build_contract_class(desc)
    multisig = MultiSig([Ripemd160(pkh_0), Ripemd160(pkh_1), Ripemd160(pkh_2)])

    context = scryptlib.utils.create_dummy_input_context()
    sighash = context.tx.signature_hash(input_idx, context.utxo.value, multisig.locking_script, sighash_flag)

    sig_0 = key_priv_0.sign(sighash, hasher=None) + pack_byte(sighash_flag)
    sig_1 = key_priv_1.sign(sighash, hasher=None) + pack_byte(sighash_flag)
    sig_2 = key_priv_1.sign(sighash, hasher=None) + pack_byte(sighash_flag)

    with pytest.raises(bitcoinx.NullFailError):
        verify_result = multisig.unlock(
                    [PubKey(key_pub_0), PubKey(key_pub_2), PubKey(key_pub_2)],
                    [Sig(sig_0), Sig(sig_1), Sig(sig_2)]
                ).verify(context)
