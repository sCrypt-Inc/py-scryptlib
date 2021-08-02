import pytest
import hashlib

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Ripemd160, Bytes

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, TxInput, P2PKH_Address, Bitcoin


key_priv = PrivateKey.from_arbitrary_bytes(b'test0')
key_pub = key_priv.public_key
pkh = key_pub.hash160()
payout_addr = pkh
change_addr = pkh

contract = './test/res/merkleToken.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

input_sats = 100000
sat_price = 100
Token = scryptlib.contract.build_contract_class(desc)
token = Token(sat_price)

change_sats = 100

sighash_flag = SigHash(SigHash.ANYONE_CAN_PAY | SigHash.ALL | SigHash.FORKID)


#def test_verify_buy_token():
#    amount = 1
#    new_entry = payout_addr + scryptlib.utils.get_push_int(amount)[1:]
#    last_entry = b'\x00' * 20 + b'\x01'
#
#    last_entry_hash = hashlib.sha256(last_entry).digest()
#    new_entry_hash = hashlib.sha256(new_entry).digest()
#
#    mixhash = hashlib.sha256(last_entry_hash + new_entry_hash).digest()
#    new_locking_script = token.code_part << Script(b'\x23' + scryptlib.utils.get_push_item(mixhash))
#    last_merkle_path = Bytes(last_entry_hash + b'\x01')
#
#    last_entry_double_hash = hashlib.sha256(last_entry_hash * 2).digest()
#    token.set_data_part(scryptlib.utils.get_push_item(last_entry_double_hash))
#
#    context = scryptlib.utils.create_dummy_input_context()
#    context.utxo.script_pubkey = token.locking_script
#    context.utxo.value = input_sats
#
#    #dummy_prev_hash = bytes.fromhex('a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458')
#    #context.tx.inputs.append(TxInput(dummy_prev_hash, 0, Script(), 0xffffffff))
#
#    # Token output
#    change_out = TxOutput(input_sats + sat_price * amount, new_locking_script)
#    context.tx.outputs.append(change_out)
#
#    # Change output
#    change_out = TxOutput(change_sats, P2PKH_Address(change_addr, Bitcoin).to_script())
#    context.tx.outputs.append(change_out)
#
#    sighash_flag = SigHash(SigHash.ANYONE_CAN_PAY | SigHash.ALL | SigHash.FORKID)
#    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
#
#    verify_result = token.buy(SigHashPreimage(preimage),
#            amount,
#            Ripemd160(change_addr),
#            Ripemd160(payout_addr),
#            change_sats,
#            Bytes(last_entry),
#            last_merkle_path
#        ).verify(context)
#    assert verify_result == True


