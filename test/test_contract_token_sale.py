import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, sha256


n_tokens = 21
token_price_sats = 100

in_sats = 100000

key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub = key_priv.public_key
pubkey_hash = key_pub.hash160()

contract = './test/res/tokenSale.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

TokenSale = scryptlib.contract.build_contract_class(desc)
token_sale = TokenSale(token_price_sats)

# Create context and set prev locking script. 
context = scryptlib.utils.create_dummy_input_context()
context.utxo.script_pubkey = token_sale.locking_script
context.utxo.value = in_sats

def get_preimage_after_purchase(key_pub):
    new_locking_script = Script(token_sale.locking_script.to_bytes() + 
            key_pub.to_bytes() + scryptlib.utils.get_push_int(n_tokens)[1:])
    tx_out = TxOutput(value=in_sats + n_tokens * token_price_sats, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    return scryptlib.utils.get_preimage_from_input_context(context)


def test_verify_correct():
    preimage = get_preimage_after_purchase(key_pub)

    verify_result = token_sale.buy(PubKey(key_pub), n_tokens, SigHashPreimage(preimage)).verify(context)
    assert verify_result == True
