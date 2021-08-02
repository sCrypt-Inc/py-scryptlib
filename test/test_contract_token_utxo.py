import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Bytes

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, sha256, TxInput


key_priv_0 = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub_0 = key_priv_0.public_key
key_priv_1 = PrivateKey.from_arbitrary_bytes(b'123test')
key_pub_1 = key_priv_1.public_key
key_priv_2 = PrivateKey.from_arbitrary_bytes(b'te123st')
key_pub_2 = key_priv_2.public_key

in_sats = 100000
out_sats = 22222

contract = './test/res/tokenUtxo.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

Token = scryptlib.contract.build_contract_class(desc)
token = Token()


def test_verify_split_in_two():
    data_part = scryptlib.utils.get_push_item(key_pub_0.to_bytes() + scryptlib.utils.get_push_int(10)[1:] + scryptlib.utils.get_push_int(90)[1:])
    token.set_data_part(data_part)

    def test_split(key_priv, balance0, balance1, balance_input0=None, balance_input1=None):
        if not balance_input0:
            balance_input0 = balance0
        if not balance_input1:
            balance_input1 = balance1

        context = scryptlib.utils.create_dummy_input_context()
        context.utxo.script_pubkey = token.locking_script
        context.utxo.value = in_sats
            
        new_locking_script = Script(token.code_part.to_bytes() + b'\x23' +
                key_pub_1.to_bytes() + b'\x00' + scryptlib.utils.get_push_int(balance0)[1:])
        tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
        context.tx.outputs.append(tx_out)

        if balance1 > 0:
            new_locking_script = Script(token.code_part.to_bytes() + b'\x23' + 
                    key_pub_2.to_bytes() + b'\x00' + scryptlib.utils.get_push_int(balance1)[1:])
            tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
            context.tx.outputs.append(tx_out)

        sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
        preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

        input_idx = 0
        utxo_satoshis = context.utxo.value
        sighash = context.tx.signature_hash(input_idx, utxo_satoshis, token.locking_script, sighash_flag)
        sig = key_priv.sign(sighash, hasher=None)
        sig = sig + pack_byte(sighash_flag)

        return token.split(
                    Sig(sig),
                    PubKey(key_pub_1),
                    balance_input0,
                    out_sats,
                    PubKey(key_pub_2),
                    balance_input1,
                    out_sats,
                    SigHashPreimage(preimage)
                ).verify(context)

    verify_result = test_split(key_priv_0, 60, 40)
    assert verify_result == True

    verify_result = test_split(key_priv_0, 100, 0)
    assert verify_result == True
       
    with pytest.raises(bitcoinx.VerifyFailed):
        test_split(key_priv_0, 0, 100)
    
    with pytest.raises(bitcoinx.VerifyFailed):
        test_split(key_priv_1, 0, 100)

    # Missmatches with preimage
    with pytest.raises(bitcoinx.VerifyFailed):
        test_split(key_priv_0, 60, 40, 60 - 1, 40)
    with pytest.raises(bitcoinx.VerifyFailed):
        test_split(key_priv_0, 60, 40, 60, 40 + 1)

    # Token imbalance after splitting
    with pytest.raises(bitcoinx.VerifyFailed):
        test_split(key_priv_0, 60 + 1, 40)
    with pytest.raises(bitcoinx.VerifyFailed):
        test_split(key_priv_0, 60, 40 - 1)


def test_verify_merge():
    x0 = 10
    x1 = 50
    expcted_balance0 = x0 + x1
    data_part_0 = key_pub_0.to_bytes() + scryptlib.utils.get_push_int(x0)[1:] + scryptlib.utils.get_push_int(x1)[1:]
    locking_script_0 = Script(token.code_part.to_bytes() + b'\x23' + data_part_0)

    y0 = 13
    y1 = 27
    expcted_balance1 = y0 + y1
    data_part_1 = key_pub_1.to_bytes() + scryptlib.utils.get_push_int(y0)[1:] + scryptlib.utils.get_push_int(y1)[1:]
    locking_script_1 = Script(token.code_part.to_bytes() + b'\x23' + data_part_1)

    
    def test_merge(input_idx, balance0, balance1):
        context = scryptlib.utils.create_dummy_input_context()
        context.utxo.value = in_sats
        context.input_index = input_idx

        tx_in = TxInput(context.tx.inputs[0].prev_hash, 1, Script(), 0xffffffff)
        context.tx.inputs.append(tx_in)

        prev_txid = context.tx.inputs[0].prev_hash
        prevouts = prev_txid + b'\x00\x00\x00\x00' + prev_txid + b'\x01\x00\x00\x00'

        new_locking_script = Script(token.code_part.to_bytes() + b'\x23' +
                key_pub_2.to_bytes() + scryptlib.utils.get_push_int(balance0)[1:] + scryptlib.utils.get_push_int(balance1)[1:])
        tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
        context.tx.outputs.append(tx_out)

        if input_idx == 0:
            balance = balance1
            context.utxo.script_pubkey = locking_script_0
            key_to_sign = key_priv_0
            token.set_data_part(b'\x23' + data_part_0)
        else:
            balance = balance0
            context.utxo.script_pubkey = locking_script_1
            key_to_sign = key_priv_1
            token.set_data_part(b'\x23' + data_part_1)

        sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
        #preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
        if input_idx == 0:
            preimage = scryptlib.utils.get_preimage(context.tx, input_idx, in_sats, locking_script_0, sighash_flag=sighash_flag)
        else:
            preimage = scryptlib.utils.get_preimage(context.tx, input_idx, in_sats, locking_script_1, sighash_flag=sighash_flag)

        if input_idx == 0:
            sighash = context.tx.signature_hash(input_idx, in_sats, locking_script_0, sighash_flag)
        else:
            sighash = context.tx.signature_hash(input_idx, in_sats, locking_script_1, sighash_flag)
        sig = key_to_sign.sign(sighash, hasher=None)
        sig = sig + pack_byte(sighash_flag)


        return token.merge(
                    Sig(sig),
                    PubKey(key_pub_2),
                    Bytes(prevouts),
                    balance,
                    out_sats,
                    SigHashPreimage(preimage)
                ).verify(context)


    verify_result = test_merge(0, expcted_balance0, expcted_balance1 + 1)
    assert verify_result == True

    

