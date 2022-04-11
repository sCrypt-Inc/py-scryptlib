import gzip
import json

from bitcoinx import PrivateKey, double_sha256, Signature
from scryptlib import (
        build_contract_class, build_type_classes
        )


key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub = key_priv.public_key

# Point addition
to_add = PrivateKey.from_arbitrary_bytes(b'bla')
point_sum = key_pub.add(to_add._secret)
assert point_sum.to_hex(compressed=True) == '0210665ad464f2b7a382841d7f764044877db2c988240149a2b1c0e330df5c6f26'

# Point doubling
point_doubled = key_pub.add(key_priv._secret)
assert point_doubled.to_hex(compressed=True) == '02d955f9f2eb090bcda5f0f158d569880dbe307cfac6a982b674116f7cf013b875'

# Scalar multiplication
scalar = PrivateKey.from_arbitrary_bytes(b'123test123')
point_scaled = key_pub.multiply(scalar._secret)
assert point_scaled.to_hex(compressed=True) == '022253ec8426dbfe9e844166aa630eb2b654eaac6f3d5d0cfdd90d475ccc026c24'

# Signature verification
msg = 'Hello, World!'
msg_bytes = str.encode(msg, encoding='ASCII')
sig = key_priv.sign(msg_bytes, hasher=double_sha256)
assert key_pub.verify_der_signature(sig, msg_bytes, hasher=double_sha256)

r = Signature.r_value(sig)
s = Signature.s_value(sig)


############################
#################### sCrypt

contract = './test/res/secp256k1.scrypt' 

#compiler_result = compile_contract(contract, debug=False)
#desc = compiler_result.to_desc()

# Load desc instead:
with gzip.open('./test/res/desc/secp256k1_desc.json.gz', 'r') as f:
    desc = json.load(f)

type_classes = build_type_classes(desc)
Point = type_classes['Point']
Signature = type_classes['Signature']

CheckSig = build_contract_class(desc)
checkSig = CheckSig()

ax, ay = key_pub.to_point()
bx, by = to_add.public_key.to_point()
sumx, sumy = point_sum.to_point()
dx, dy = point_doubled.to_point()
prodx, prody = point_scaled.to_point()

# Point addition
def test_add_on_chain_correct():
    assert checkSig.testAdd(
                Point({ 'x': ax, 'y': ay}), 
                Point({ 'x': bx, 'y': by}), 
                Point({ 'x': sumx, 'y': sumy}), 
            ).verify()

# Point doubling
def test_double_on_chain_correct():
    assert checkSig.testDouble(
                Point({ 'x': ax, 'y': ay}), 
                Point({ 'x': dx, 'y': dy}), 
            ).verify()

# Point doubling, point at inf
def test_double_inf_on_chain_correct():
    assert checkSig.testDouble(
                Point({ 'x': 0, 'y': 0}), 
                Point({ 'x': 0, 'y': 0}), 
            ).verify()


# Point addition, same point
def test_add_same_p_on_chain_correct():
    assert checkSig.testAdd(
                Point({ 'x': ax, 'y': ay}), 
                Point({ 'x': ax, 'y': ay}), 
                Point({ 'x': dx, 'y': dy}), 
            ).verify()

# Point addition, point at inf
def test_add_inf_on_chain_correct():
    assert checkSig.testAdd(
                Point({ 'x': 0, 'y': 0}), 
                Point({ 'x': bx, 'y': by}), 
                Point({ 'x': bx, 'y': by}), 
            ).verify()
    assert checkSig.testAdd(
                Point({ 'x': ax, 'y': ay}), 
                Point({ 'x': 0, 'y': 0}), 
                Point({ 'x': ax, 'y': ay}), 
            ).verify()

# Scalar multiplication
def test_mult_on_chain_correct():
    assert checkSig.testMultByScalar(
                Point({ 'x': ax, 'y': ay}), 
                scalar.to_int(), 
                Point({ 'x': prodx, 'y': prody}), 
            ).verify()

# Signature verification
def test_sig_verify_chain_correct():
    assert checkSig.testVerifySig(
                msg_bytes,
                Signature({ 'r': r, 's': s}), 
                Point({ 'x': ax, 'y': ay}), 
            ).verify()

