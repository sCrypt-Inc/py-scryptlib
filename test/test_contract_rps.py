import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, PubKey, Sig, SigHashPreimage, Ripemd160, Bytes

import bitcoinx
from bitcoinx import PrivateKey, TxOutput, SigHash, pack_byte, Script, hash160, P2PKH_Address, Bitcoin


key_priv_A = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub_A = key_priv_A.public_key
pkh_A = key_pub_A.hash160()
key_priv_B = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub_B = key_priv_B.public_key
pkh_B = key_pub_B.hash160()

player_A_data = hash160(b'\x01' + key_pub_A.to_bytes())

sighash_flag = SigHash(SigHash.ANYONE_CAN_PAY | SigHash.ALL | SigHash.FORKID)

pub_key_hashlen = 20

action_INIT = 0
action_ROCK = 1
action_PAPER = 2
action_SCISSORS = 3

contract = './test/res/rps.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

RPS = scryptlib.contract.build_contract_class(desc)
rps = RPS()


def test_verify_player_B_follow():
    def test_follow(pkh_B, action, init_sats, input_sats, out_sats, change_sats):
        rps.set_data_part(player_A_data + b'\x00' * pub_key_hashlen + scryptlib.utils.get_push_int(action_INIT)[1:])

        context = scryptlib.utils.create_dummy_input_context()
        context.utxo.script_pubkey = rps.locking_script
        context.utxo.value = init_sats

        new_data_part = player_A_data + pkh_B + scryptlib.utils.get_push_int(action)[1:]
        new_locking_script = Script(rps.code_part.to_bytes() + new_data_part) 
        tx_out = TxOutput(value=out_sats, script_pubkey=new_locking_script)
        context.tx.outputs.append(tx_out)

        change_out = TxOutput(change_sats, P2PKH_Address(pkh_B, Bitcoin).to_script())
        context.tx.outputs.append(change_out)

        preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

        return rps.follow(SigHashPreimage(preimage), action, Ripemd160(pkh_B), change_sats).verify(context)
    
    init_sats = 100000
    input_sats = 60000
    out_sats = 150000
    change_sats = 10000

    verify_result = test_follow(pkh_B, action_PAPER, init_sats, input_sats, out_sats, change_sats)
    assert verify_result == True


def test_verify_player_A_finish():
    def test_finish(key_priv, pkh_B, action_A, action_B, total_sats, input_sats, out_sats, change_sats):
        rps.set_data_part(player_A_data + pkh_B + scryptlib.utils.get_push_int(action_B)[1:])

        context = scryptlib.utils.create_dummy_input_context()
        context.utxo.script_pubkey = rps.locking_script
        context.utxo.value = total_sats

        change_out = TxOutput(change_sats, P2PKH_Address(pkh_A, Bitcoin).to_script())
        context.tx.outputs.append(change_out)

        if out_sats > 0:
            pay_out = TxOutput(out_sats, P2PKH_Address(pkh_B, Bitcoin).to_script())
            context.tx.outputs.append(pay_out)

        preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

        input_idx = 0
        utxo_satoshis = context.utxo.value
        sighash = context.tx.signature_hash(input_idx, utxo_satoshis, rps.locking_script, sighash_flag)
        sig = key_priv.sign(sighash, hasher=None)
        sig = sig + pack_byte(sighash_flag)

        return rps.finish(SigHashPreimage(preimage), action_A,
                    Sig(sig), PubKey(key_pub_A), change_sats).verify(context)
    
    total_sats = 150000
    input_sats = 10000
    out_sats = 100000
    change_sats = 60000

    verify_result = test_finish(key_priv_A, pkh_B, action_ROCK, action_PAPER, total_sats,
                                    input_sats, out_sats, change_sats)
    assert verify_result == True

    with pytest.raises(bitcoinx.VerifyFailed):
        test_finish(key_priv_A, pkh_B, action_PAPER, action_PAPER, total_sats,
                                    input_sats, out_sats, change_sats)

    total_sats = 150000
    input_sats = 10000
    out_sats = 0
    change_sats = 160000

    verify_result = test_finish(key_priv_A, pkh_B, action_ROCK, action_SCISSORS, total_sats,
                                    input_sats, out_sats, change_sats)
    assert verify_result == True

    total_sats = 150000
    input_sats = 10000
    out_sats = 50000
    change_sats = 110000

    verify_result = test_finish(key_priv_A, pkh_B, action_ROCK, action_ROCK, total_sats,
                                    input_sats, out_sats, change_sats)
    assert verify_result == True
