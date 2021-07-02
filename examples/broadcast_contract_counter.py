import json
import requests

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int, SigHashPreimage

import bitcoinx
from bitcoinx import SigHash, PrivateKey, Tx, TxInput, TxOutput, Script, pack_byte, JSONFlags, \
        Bitcoin, hex_str_to_hash, P2PKH_Address

from bitcoinx import TxInputContext, MinerPolicy, InterpreterLimits


def initialize_counter(counter_obj, counter_initial_val, funding_txid, funding_out_idx, \
        unlock_key_priv, miner_fee, contract_out_sats, change_addr):
    counter_obj.set_data_part(scryptlib.utils.get_push_int(counter_initial_val))

    # Funding TX
    funding_tx_hash = hex_str_to_hash(funding_txid)
    unlock_key_pub = unlock_key_priv.public_key

    r = requests.get('https://api.whatsonchain.com/v1/bsv/main/tx/{}'.format(funding_txid)).json()
    funding_locking_script = Script.from_hex(r['vout'][funding_out_idx]['scriptPubKey']['hex'])
    unlocked_satoshis = int(r['vout'][funding_out_idx]['value'] * 10**8)
    n_sequence = 0xffffffff
    tx_input = TxInput(funding_tx_hash, funding_out_idx, None, n_sequence)

    # Output with counter script code
    contract_out = TxOutput(contract_out_sats, counter_obj.locking_script)

    # Change output
    tx_output_script = P2PKH_Address.from_string(change_addr, Bitcoin).to_script()
    change_out = TxOutput(unlocked_satoshis - miner_fee - contract_out_sats, tx_output_script)

    tx = Tx(2, [tx_input], [contract_out, change_out], 0x00000000)

    # Create signature for input
    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    sighash = tx.signature_hash(0, unlocked_satoshis, funding_locking_script, sighash_flag)
    sig = unlock_key_priv.sign(sighash, hasher=None)
    sig = sig + pack_byte(sighash_flag)

    # Set script for input
    unlock_script = Script() << sig << unlock_key_pub.to_bytes()
    tx.inputs[0].script_sig = unlock_script

    broadcast_tx(tx)


def increment_counter(counter_obj, prev_txid, prev_out_idx, funding_txid, funding_out_idx,
        unlock_key_priv, miner_fee):
    # Get data from previous counter tx
    r = requests.get('https://api.whatsonchain.com/v1/bsv/main/tx/{}'.format(prev_txid)).json()
    prev_locking_script = Script.from_hex(r['vout'][prev_out_idx]['scriptPubKey']['hex'])
    prev_counter_bytes = list(prev_locking_script.ops())[-1]
    prev_counter_val = int.from_bytes(prev_counter_bytes, 'little')
    unlocked_satoshis_counter = int(r['vout'][prev_out_idx]['value'] * 10**8)

    # Get data from funding tx
    r = requests.get('https://api.whatsonchain.com/v1/bsv/main/tx/{}'.format(funding_txid)).json()
    funding_locking_script = Script.from_hex(r['vout'][funding_out_idx]['scriptPubKey']['hex'])
    unlocked_satoshis_funding = int(r['vout'][funding_out_idx]['value'] * 10**8)

    # Set data for next iteration
    counter_obj.set_data_part(scryptlib.utils.get_push_int(prev_counter_val + 1))

    ## Construct tx
    n_sequence = 0xffffffff

    # Counter input and output
    prev_tx_hash = hex_str_to_hash(prev_txid)
    counter_in = TxInput(prev_tx_hash, prev_out_idx, None, n_sequence)
    out_satoshis = unlocked_satoshis_counter + unlocked_satoshis_funding - miner_fee
    contract_out = TxOutput(out_satoshis, counter_obj.locking_script)

    # Funding input
    funding_tx_hash = hex_str_to_hash(funding_txid)
    funding_in = TxInput(funding_tx_hash, funding_out_idx, None, n_sequence)

    tx = Tx(2, [counter_in, funding_in], [contract_out], 0x00000000)

    # Set input script to unlock previous counter
    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage(tx, 0, unlocked_satoshis_counter, prev_locking_script, sighash_flag)
    increment_func_call = counter_obj.increment(SigHashPreimage(preimage), Int(out_satoshis))
    tx.inputs[0].script_sig = increment_func_call.script

    # Set input script to unlock funding output
    unlock_key_pub = unlock_key_priv.public_key
    sighash = tx.signature_hash(1, unlocked_satoshis_funding, funding_locking_script, sighash_flag)
    sig = unlock_key_priv.sign(sighash, hasher=None)
    sig = sig + pack_byte(sighash_flag)
    unlock_script = Script() << sig << unlock_key_pub.to_bytes()
    tx.inputs[1].script_sig = unlock_script

    broadcast_tx(tx)


def broadcast_tx(tx):
    headers = {'Content-Type': 'application/json'}
    json_payload = {'txhex': tx.to_hex()}
    r = requests.post('https://api.whatsonchain.com/v1/bsv/main/tx/raw',
                      data=json.dumps(json_payload),
                      headers=headers,
                      timeout=30)
    print('API response:', r.json())


contract = '../test/res/counter.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()
Counter = scryptlib.contract.build_contract_class(desc)
counter_obj = Counter() 

#############################################
# Initialize the counter on the blockchain. #
#############################################
#counter_initial_val = 0
#funding_txid = '4740d67a71f08c9f8400fff149495ca264e107b170d3016a8d0d2b1f829ba34f'
#funding_out_idx = 1
#unlock_key_priv = PrivateKey.from_WIF('****************************************************')
#change_addr = '1CSgaVxDF5KVuzzeSynwPxbXxdrqeZdWn4'
#miner_fee = 500
#contract_out_sats = 1337
#initialize_counter(counter_obj, counter_initial_val, funding_txid, funding_out_idx, unlock_key_priv, \
#        miner_fee, contract_out_sats, change_addr)

###############################
# Increment existing counter. #
###############################
prev_txid = '74f292086ae23bb226b533080946434d22d61adf44f2978407cd2a55f8346e0f'
prev_out_idx = 0
miner_fee = 1000
funding_txid = '7b5fd39859521094d61d05f11f42dafd0f4e45fb0b68b4e423760ba21ce5a743'
funding_out_idx = 0
unlock_key_priv = PrivateKey.from_WIF('****************************************************')
increment_counter(counter_obj, prev_txid, prev_out_idx, funding_txid, funding_out_idx, unlock_key_priv, \
        miner_fee)


