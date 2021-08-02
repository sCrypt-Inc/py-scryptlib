import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script


key_priv_0 = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub_0 = key_priv_0.public_key
key_priv_1 = PrivateKey.from_arbitrary_bytes(b'123test')
key_pub_1 = key_priv_1.public_key

contract = './test/res/token.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Token = scryptlib.contract.build_contract_class(desc)

token = Token()
token.set_data_part(key_pub_0.to_bytes() + scryptlib.utils.get_push_int(100)[1:]
        + key_pub_1.to_bytes() + scryptlib.utils.get_push_int(0)[1:])

# Create context and set prev locking script. 
context = scryptlib.utils.create_dummy_input_context()
context.utxo.script_pubkey = token.locking_script

# Create new locking script.
new_data_part = key_pub_0.to_bytes() + scryptlib.utils.get_push_int(60)[1:] \
        + key_pub_1.to_bytes() + scryptlib.utils.get_push_int(40)[1:]
new_locking_script = Script(token.code_part.to_bytes() + new_data_part) 
tx_out = TxOutput(value=222222, script_pubkey=new_locking_script)
context.tx.outputs.append(tx_out)

# Create signature.
sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
input_idx = 0
utxo_satoshis = context.utxo.value
sighash = context.tx.signature_hash(input_idx, utxo_satoshis, token.locking_script, sighash_flag)
sig = key_priv_0.sign(sighash, hasher=None)
sig = sig + pack_byte(sighash_flag)

preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)


def test_verify_correct():
    verify_result = token.transfer(PubKey(key_pub_0), 
            Sig(sig),
            PubKey(key_pub_1),
            40,
            SigHashPreimage(preimage),
            222222).verify(context)
    assert verify_result == True


def test_verify_wrong_val():
    verify_result = token.transfer(PubKey(key_pub_0), 
            Sig(sig),
            PubKey(key_pub_1),
            40,
            SigHashPreimage(preimage),
            221222).verify(context)
    assert verify_result == False


def test_verify_wrong_val_2():
    verify_result = token.transfer(PubKey(key_pub_0), 
            Sig(sig),
            PubKey(key_pub_1),
            43,
            SigHashPreimage(preimage),
            222222).verify(context)
    assert verify_result == False
