import requests

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Sig, PubKey, Ripemd160

import bitcoinx
from bitcoinx import SigHash, PrivateKey, Tx, TxInput, TxOutput, Script, pack_byte, JSONFlags, Bitcoin, hex_str_to_hash


unlock_key_priv = PrivateKey.from_WIF('****************************************************')
unlock_key_pub = unlock_key_priv.public_key
addr_dest = '1Pc1iF4g8iVmnu1puvGasSyDcwv2FS1VcH'
prev_txid = 'c1543650beafbf646e75aeeae9b091e4c477362db4a18e740d3f9d2ae250c013'
miner_fee = 120
contract = '../test/res/p2pkh.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

P2PKH = scryptlib.contract.build_contract_class(desc)
p2pkh_obj = P2PKH(Ripemd160(addr_dest))

prev_tx_hash = hex_str_to_hash(prev_txid)
prev_out_idx = 0

r = requests.get('https://api.whatsonchain.com/v1/bsv/main/tx/{}'.format(prev_txid)).json()
prev_locking_script = Script.from_hex(r['vout'][prev_out_idx]['scriptPubKey']['hex'])
unlocked_satoshis = int(r['vout'][prev_out_idx]['value'] * 10**8)
out_satoshis = unlocked_satoshis - miner_fee
n_sequence = 0xffffffff

tx_input = TxInput(prev_tx_hash, prev_out_idx, None, n_sequence)
tx_output = TxOutput(out_satoshis, p2pkh_obj.locking_script)

tx = Tx(2, [tx_input], [tx_output], 0x00000000)

sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
sighash = tx.signature_hash(0, unlocked_satoshis, prev_locking_script, sighash_flag)
sig = unlock_key_priv.sign(sighash, hasher=None)
sig = sig + pack_byte(sighash_flag)

unlock_script = Script() << sig << unlock_key_pub.to_bytes()
tx.inputs[0].script_sig = unlock_script


######## Broadcast transaction ########
import json
headers = {'Content-Type': 'application/json'}
json_payload = {'txhex': tx.to_hex()}
r = requests.post('https://api.whatsonchain.com/v1/bsv/main/tx/raw',
                  data=json.dumps(json_payload),
                  headers=headers,
                  timeout=30)
print('API response:', r.json())
