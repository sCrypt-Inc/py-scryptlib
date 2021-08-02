import pytest
import hashlib

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int, Ripemd160, Sha256, PubKey, Sig, Bytes

import bitcoinx
from bitcoinx import SigHash, TxOutput, Script, PrivateKey, P2PKH_Address, Bitcoin, pack_byte


contract = './test/res/escrow.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

key_priv_A = PrivateKey.from_arbitrary_bytes(b'test0')
key_pub_A = key_priv_A.public_key
pkh_A = key_pub_A.hash160()

key_priv_B = PrivateKey.from_arbitrary_bytes(b'test1')
key_pub_B = key_priv_B.public_key
pkh_B = key_pub_B.hash160()

key_priv_E = PrivateKey.from_arbitrary_bytes(b'test2')
key_pub_E = key_priv_E.public_key
pkh_E = key_pub_E.hash160()

secret0 = b'abc'
secret1 = b'def'
h_secret0 = hashlib.sha256(secret0).digest()
h_secret1 = hashlib.sha256(secret1).digest()

fee = 1000
input_sats = 100000

Escrow = scryptlib.contract.build_contract_class(desc)
escrow = Escrow(Ripemd160(pkh_A), Ripemd160(pkh_B), Ripemd160(pkh_E), 
        Sha256(h_secret0), Sha256(h_secret1), fee)


def test_verify_scenario_1():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = escrow.locking_script
    context.utxo.value = input_sats

    change_out = TxOutput(int(input_sats / 2 - fee), P2PKH_Address(pkh_A, Bitcoin).to_script())
    context.tx.outputs.append(change_out)

    change_out = TxOutput(int(input_sats / 2 - fee), P2PKH_Address(pkh_B, Bitcoin).to_script())
    context.tx.outputs.append(change_out)


    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    sighash = context.tx.signature_hash(0, input_sats, escrow.locking_script, sighash_flag)

    sig_A = key_priv_A.sign(sighash, hasher=None)
    sig_A = sig_A + pack_byte(sighash_flag)

    sig_B = key_priv_B.sign(sighash, hasher=None)
    sig_B = sig_B + pack_byte(sighash_flag)

    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    
    verify_result = escrow.unlock(
            SigHashPreimage(preimage),
            PubKey(key_pub_A),
            Sig(sig_A),
            PubKey(key_pub_B),
            Sig(sig_B),
            Bytes(b'00')
        ).verify(context)
    assert verify_result == True

    # Wrong preimage
    with pytest.raises(bitcoinx.NullFailError):
        escrow.unlock(
                SigHashPreimage(preimage + b'ff'),
                PubKey(key_pub_A),
                Sig(sig_A),
                PubKey(key_pub_B),
                Sig(sig_B),
                Bytes(b'00')
            ).verify(context)


def test_verify_scenario_2():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = escrow.locking_script
    context.utxo.value = input_sats

    change_out = TxOutput(int(input_sats - fee), P2PKH_Address(pkh_A, Bitcoin).to_script())
    context.tx.outputs.append(change_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    sighash = context.tx.signature_hash(0, input_sats, escrow.locking_script, sighash_flag)

    sig_A = key_priv_A.sign(sighash, hasher=None)
    sig_A = sig_A + pack_byte(sighash_flag)

    sig_E = key_priv_E.sign(sighash, hasher=None)
    sig_E = sig_E + pack_byte(sighash_flag)

    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    
    verify_result = escrow.unlock(
            SigHashPreimage(preimage),
            PubKey(key_pub_A),
            Sig(sig_A),
            PubKey(key_pub_E),
            Sig(sig_E),
            Bytes(secret0)
        ).verify(context)
    assert verify_result == True

    # Wrong secret
    with pytest.raises(bitcoinx.VerifyFailed):
        verify_result = escrow.unlock(
                SigHashPreimage(preimage),
                PubKey(key_pub_A),
                Sig(sig_A),
                PubKey(key_pub_E),
                Sig(sig_E),
                Bytes(secret1)
            ).verify(context)


def test_verify_scenario_3():
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = escrow.locking_script
    context.utxo.value = input_sats

    change_out = TxOutput(int(input_sats - fee), P2PKH_Address(pkh_B, Bitcoin).to_script())
    context.tx.outputs.append(change_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    sighash = context.tx.signature_hash(0, input_sats, escrow.locking_script, sighash_flag)

    sig_B = key_priv_B.sign(sighash, hasher=None)
    sig_B = sig_B + pack_byte(sighash_flag)

    sig_E = key_priv_E.sign(sighash, hasher=None)
    sig_E = sig_E + pack_byte(sighash_flag)

    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    
    verify_result = escrow.unlock(
            SigHashPreimage(preimage),
            PubKey(key_pub_B),
            Sig(sig_B),
            PubKey(key_pub_E),
            Sig(sig_E),
            Bytes(secret1)
        ).verify(context)
    assert verify_result == True

