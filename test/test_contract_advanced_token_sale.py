import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160, SigHashPreimage, Bytes

import bitcoinx
from bitcoinx import SigHash, PrivateKey, P2PKH_Address, TxOutput, Bitcoin, Tx, TxInput, TxInputContext, Script, PublicKey



SATS_PER_TOKEN = 1000
input_sats = 100000
sighash_flag = SigHash(SigHash.ANYONE_CAN_PAY | SigHash.ALL | SigHash.FORKID)


priv_keys = []
for i in range(0, 5):
    priv_keys.append(PrivateKey.from_random())

pub_keys = []
for priv_key in priv_keys:
    pub_keys.append(priv_key.public_key)

pkhs = []
for pub_key in pub_keys:
    pkhs.append(pub_key.hash160())


contract = './test/res/advancedTokenSale.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

AdvancedTokenSale = scryptlib.contract.build_contract_class(desc)
ats = AdvancedTokenSale(SATS_PER_TOKEN)

# Add "empty" public key
empt_pub_key = scryptlib.utils.get_push_item(bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000'))
ats.set_data_part(empt_pub_key)


def sale(n_bought, pkh, pub_key):
    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = ats.locking_script
    context.utxo.value = input_sats

    new_data_part = ats.data_part << pub_key.to_bytes() + scryptlib.utils.get_push_int(n_bought)[1:]
    new_locking_script = Script(ats.code_part.to_bytes() + new_data_part.to_bytes()) 

    change_sats = input_sats - n_bought * SATS_PER_TOKEN
    out_sats = input_sats + n_bought * SATS_PER_TOKEN

    # Counter output
    tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out)

    # Change output
    change_out = TxOutput(change_sats, P2PKH_Address(pub_key.hash160(), Bitcoin).to_script())
    context.tx.outputs.append(change_out)

    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

    verify_result = ats.buy(SigHashPreimage(preimage), Ripemd160(pkh), change_sats, Bytes(pub_key.to_bytes()), n_bought).verify(context)
    assert verify_result == True

    return new_data_part


def test_verify_correct_sales():
    new_data_part = sale(1, pkhs[0], pub_keys[0])

    ats.set_data_part(new_data_part.to_bytes())
    new_data_part = sale(3, pkhs[1], pub_keys[1])

    ats.set_data_part(new_data_part.to_bytes())
    new_data_part = sale(10, pkhs[2], pub_keys[2])

    ats.set_data_part(new_data_part.to_bytes())
    new_data_part = sale(2, pkhs[3], pub_keys[3])

    

