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

curr_token_id = 42
issuer = key_pub_0
sender = key_pub_0

action_issue = b'\x00'
action_transfer = b'\x01'

input_sats = 100000
out_sats = 22222

contract = './test/res/nonFungibleToken.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Token = scryptlib.contract.build_contract_class(desc)
token = Token()


def test_verify_token_issue():
    tok_id_data = scryptlib.utils.get_push_int(curr_token_id)[1:]
    issuer_data = scryptlib.utils.get_push_item(issuer.to_bytes())[1:]

    token.set_data_part(scryptlib.utils.get_push_item(tok_id_data + issuer_data + action_issue))

    
    def test_issue(priv_key, receiver, new_issuer=issuer, next_tok_id=curr_token_id + 1, 
                                            issued_tok_id=curr_token_id):
        context = scryptlib.utils.create_dummy_input_context()
        context.utxo.script_pubkey = token.locking_script
        context.utxo.value = input_sats

        new_data_part = b'\x23' + scryptlib.utils.get_push_int(next_tok_id)[1:] + \
                        new_issuer.to_bytes() + action_issue
        new_locking_script = Script(token.code_part.to_bytes() + new_data_part) 
        tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
        context.tx.outputs.append(tx_out)

        new_data_part = b'\x23' + scryptlib.utils.get_push_int(issued_tok_id)[1:] + \
                        receiver.to_bytes() + action_transfer
        new_locking_script = Script(token.code_part.to_bytes() + new_data_part) 
        tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
        context.tx.outputs.append(tx_out)

        sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
        sighash = context.tx.signature_hash(0, input_sats, token.locking_script, sighash_flag)
        sig = priv_key.sign(sighash, hasher=None)
        sig = sig + pack_byte(sighash_flag)

        preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

        return token.issue(
                    Sig(sig),
                    PubKey(receiver),
                    out_sats,
                    out_sats,
                    SigHashPreimage(preimage)
                ).verify(context)


    verify_result = test_issue(key_priv_0, key_pub_1, key_pub_0, curr_token_id + 1, curr_token_id)
    assert verify_result == True

    # Issuer must not change
    verify_result = test_issue(key_priv_0, key_pub_1, key_pub_1, curr_token_id + 1, curr_token_id)
    assert verify_result == False
    
    # Unauthorized key
    with pytest.raises(bitcoinx.NullFailError):
        test_issue(key_priv_1, key_pub_1, key_pub_0, curr_token_id + 1, curr_token_id)

    # Missmatched next token ID
    verify_result = test_issue(key_priv_0, key_pub_1, key_pub_1, curr_token_id + 2, curr_token_id)
    assert verify_result == False

    # Missmatched issued token ID
    verify_result = test_issue(key_priv_0, key_pub_1, key_pub_1, curr_token_id + 1, curr_token_id - 1)
    assert verify_result == False


def test_verify_transfer():
    tok_id_data = scryptlib.utils.get_push_int(curr_token_id)[1:]
    sender_data = scryptlib.utils.get_push_item(sender.to_bytes())[1:]

    token.set_data_part(scryptlib.utils.get_push_item(tok_id_data + sender_data + action_transfer))

    def test_transfer(priv_key, receiver, received_tok_id=curr_token_id):
        context = scryptlib.utils.create_dummy_input_context()
        context.utxo.script_pubkey = token.locking_script
        context.utxo.value = input_sats

        new_data_part = b'\x23' + scryptlib.utils.get_push_int(received_tok_id)[1:] + \
                        receiver.to_bytes() + action_transfer
        new_locking_script = Script(token.code_part.to_bytes() + new_data_part) 
        tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
        context.tx.outputs.append(tx_out)

        sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
        sighash = context.tx.signature_hash(0, input_sats, token.locking_script, sighash_flag)
        sig = priv_key.sign(sighash, hasher=None)
        sig = sig + pack_byte(sighash_flag)

        preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

        return token.transfer(
                    Sig(sig),
                    PubKey(receiver),
                    out_sats,
                    SigHashPreimage(preimage)
                ).verify(context)

    verify_result = test_transfer(key_priv_0, key_pub_1, curr_token_id)
    assert verify_result == True
    
    # Unauthorized key
    with pytest.raises(bitcoinx.NullFailError):
        test_transfer(key_priv_1, key_pub_1, curr_token_id)
