import pytest

import gzip
import json

from bitcoinx import PublicKey, PrivateKey, sha256, SigHash, NullFailError
from scryptlib import (
        compile_contract, build_contract_class, build_type_classes,
        create_dummy_input_context, get_preimage_from_input_context,
        SigHashPreimage
        )


p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
#key_priv = PrivateKey.from_random()
key_pub = key_priv.public_key

contract = './test/res/P2GenericECDSAPubKey.scrypt' 

# Compile the contract. Takes a long time!
#compiler_result = compile_contract(contract, debug=False)
#desc = compiler_result.to_desc()

# Load desc instead:
with gzip.open('./test/res/desc/P2GenericECDSAPubKey_desc.json.gz', 'r') as f:
    desc = json.load(f)

type_classes = build_type_classes(desc)
Point = type_classes['Point']

P2PK = build_contract_class(desc)
x, y = key_pub.to_point()
p2pk = P2PK(Point({'x': x, 'y': y}))

context = create_dummy_input_context()
context.utxo.script_pubkey = p2pk.locking_script
sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
preimage = get_preimage_from_input_context(context, sighash_flag)

### Derive proof:
r = PrivateKey.from_arbitrary_bytes(b'123test321')
#r = PrivateKey.from_random()

A = r.public_key
G = PrivateKey.from_int(1).public_key
st = G.to_bytes(compressed=False) + key_pub.to_bytes(compressed=False)
e = int.from_bytes(sha256(preimage + st + A.to_bytes(compressed=False)), 
        byteorder='little') % 2**128
e = PrivateKey.from_int(e)
z = key_priv.multiply(e._secret).add(r._secret)


# Verify proof off-chain:
def test_verfy_off_chain_correct():
    zG = z.public_key
    ePK = key_pub.multiply(e._secret)
    ePKx, ePKy = ePK.to_point()
    ePK_neg = PublicKey.from_point(ePKx, (ePKy * -1) % p)
    A = PublicKey.combine_keys([zG, ePK_neg])

    st = G.to_bytes(compressed=False) + key_pub.to_bytes(compressed=False)
    bA = A.to_bytes(compressed=False)
    _e = int.from_bytes(sha256(preimage + st + bA), byteorder='little') % 2**128
    assert(_e == e.to_int())


# Verify proof on-chain:
def test_verfy_on_chain_correct():
    assert p2pk.unlock(e.to_int(), z.to_int(), SigHashPreimage(preimage)).verify(context)

def test_verfy_on_chain_wrong():
    with pytest.raises(NullFailError):
        assert p2pk.unlock(e.to_int() - 1, z.to_int(), SigHashPreimage(preimage)).verify(context)


