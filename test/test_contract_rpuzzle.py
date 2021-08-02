import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Ripemd160

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, sha256, PublicKey, int_to_be_bytes, hash160, TxInputContext, Tx, TxInput


secret = b'This is a secret message!'
h_secret = sha256(secret)
k = h_secret

secret_wrong = b'This is the wrong secret message!'
h_secret_wrong = sha256(secret_wrong)
k_wrong = h_secret

G = PublicKey.from_hex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
Q = G.multiply(k)
r, _ = Q.to_point()
r = int_to_be_bytes(r)
if r[0] & 0x80:
    r0 = pack_byte(0) + r
else:
    r0 = r
r_hash = hash160(r0)

# Ephermal key to generate the r signature
key_priv_R = PrivateKey.from_arbitrary_bytes(b'123test')
key_pub_R = key_priv_R.public_key

contract = './test/res/rpuzzle.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

RPuzzle = scryptlib.contract.build_contract_class(desc)
r_puzzle = RPuzzle(Ripemd160(r_hash))

#------------------
context = scryptlib.utils.create_dummy_input_context()
context.utxo.script_pubkey = r_puzzle.locking_script

sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
input_idx = 0
utxo_satoshis = 100000
sighash = context.tx.signature_hash(input_idx, utxo_satoshis, r_puzzle.locking_script, sighash_flag)

sig_r = PrivateKey(k).sign(sighash, hasher=None)
sig_r = sig_r + pack_byte(sighash_flag)

test_pk = PrivateKey.from_int(5857758586230883379411850857264874577248669710025714828420588574261808836891)
test = test_pk.sign(bytes.fromhex('94e539906a7868ac2bfef041069cb0ef6534dc0b2b32e85b755e578dda461411'), hasher=None)
test = test + pack_byte(sighash_flag)

sig = key_priv_R.sign(sighash, hasher=None)
sig = sig + pack_byte(sighash_flag)


#def test_verify_correct():
#    verify_result = r_puzzle.unlock(Sig(sig), PubKey(key_pub_R), Sig(sig_r)).verify(context)
#    assert verify_result == True




