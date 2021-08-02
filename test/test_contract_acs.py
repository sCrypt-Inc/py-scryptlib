import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160, SigHashPreimage

import bitcoinx
from bitcoinx import SigHash, PrivateKey, P2PKH_Address, TxOutput, Bitcoin, Tx, TxInput, TxInputContext, Script


def create_input_context(utxo_satoshis, utxo_locking_script, new_out):
    tx_version = 2
    tx_locktime = 0x00000000

    utxo = TxOutput(utxo_satoshis, utxo_locking_script)
    prev_tx = Tx(tx_version, [], [utxo], tx_locktime)
    prev_txid = prev_tx.hash()

    utxo_idx = 0
    n_sequence = 0xffffffff
    unlocking_script = Script()
    curr_in = TxInput(prev_txid, utxo_idx, unlocking_script, n_sequence)
    curr_tx = Tx(tx_version, [curr_in], [new_out], tx_locktime)

    input_idx = 0
    return TxInputContext(curr_tx, input_idx, utxo, is_utxo_after_genesis=True)


in_sats = 1200
miner_fee = 546

key_priv_0 = PrivateKey.from_arbitrary_bytes(b'test123')
key_pub_0 = key_priv_0.public_key
pkh_0 = key_pub_0.hash160()

contract = './test/res/acs.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

AnyoneCanSpend = scryptlib.contract.build_contract_class(desc)
acs = AnyoneCanSpend(Ripemd160(pkh_0))

pkh_0_out = TxOutput(in_sats - miner_fee, P2PKH_Address(pkh_0, Bitcoin).to_script())
context = create_input_context(in_sats, acs.locking_script, pkh_0_out)

sighash_flag = SigHash(SigHash.ANYONE_CAN_PAY | SigHash.ALL | SigHash.FORKID)
preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)


def test_verify_correct():
    verify_result = acs.unlock(SigHashPreimage(preimage)).verify(context)
    assert verify_result == True


def test_verify_wrong_addr():
    key_priv = PrivateKey.from_arbitrary_bytes(b'123test')
    key_pub = key_priv.public_key
    pkh = key_pub.hash160()
    pkh_0_out_wrong = TxOutput(in_sats - miner_fee, P2PKH_Address(pkh, Bitcoin).to_script())
    context = create_input_context(in_sats, acs.locking_script, pkh_0_out_wrong)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    verify_result = acs.unlock(SigHashPreimage(preimage)).verify(context)
    assert verify_result == False


def test_verify_wrong_out_amount():
    pkh_0_out_wrong = TxOutput(in_sats - miner_fee + 123, P2PKH_Address(pkh_0, Bitcoin).to_script())
    context = create_input_context(in_sats, acs.locking_script, pkh_0_out_wrong)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)
    verify_result = acs.unlock(SigHashPreimage(preimage)).verify(context)
    assert verify_result == False



