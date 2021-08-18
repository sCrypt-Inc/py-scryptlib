import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Ripemd160

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, sha256, PublicKey, int_to_be_bytes, hash160, TxInputContext, Tx, TxInput

import ecdsa
from hashlib import sha256 as sha256_hashlib



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

utxo_satoshis = 100004
context = scryptlib.utils.create_dummy_input_context()
context.utxo.script_pubkey = r_puzzle.locking_script
context.utxo.value = utxo_satoshis


sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
input_idx = 0
sighash = context.tx.signature_hash(input_idx, utxo_satoshis, r_puzzle.locking_script, sighash_flag)

class MockHashFunc:
    def __init__(self, data):
        self.data = data
    def digest(self, ):
        return self.data

sk = ecdsa.SigningKey.from_secret_exponent(key_priv_R.to_int(), curve=ecdsa.SECP256k1, hashfunc=MockHashFunc)
sig_r = sk.sign(sighash, k=int.from_bytes(k, 'big'), sigencode=ecdsa.util.sigencode_der)
sig_r = sig_r + pack_byte(sighash_flag)

sig = key_priv_R.sign(sighash, hasher=None)
sig = sig + pack_byte(sighash_flag)


def test_verify_correct():
    verify_result = r_puzzle.unlock(Sig(sig), PubKey(key_pub_R), Sig(sig_r)).verify(context)
    assert verify_result == True

