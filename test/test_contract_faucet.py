import pytest

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import SigHashPreimage, Int, Ripemd160, Sha256, PubKey, Sig, Bytes

import bitcoinx
from bitcoinx import SigHash, TxOutput, Script, PrivateKey, P2PKH_Address, Bitcoin, pack_byte


contract = './test/res/faucet.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

key_priv = PrivateKey.from_arbitrary_bytes(b'test0')
key_pub = key_priv.public_key
pkh = key_pub.hash160()

Faucet = scryptlib.contract.build_contract_class(desc)
faucet = Faucet()


def test_verify_without_change():
    deposit_sats = 100000
    input_sats = 100000
    output_sats = deposit_sats + input_sats

    faucet.set_data_part(scryptlib.utils.get_push_int(1602553516))

    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = faucet.locking_script
    context.utxo.value = input_sats

    tx_out = TxOutput(value=output_sats, script_pubkey=faucet.locking_script)
    context.tx.outputs.append(tx_out)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

    verify_result = faucet.deposit(SigHashPreimage(preimage), deposit_sats,
            Ripemd160(pkh), 0).verify(context)
    assert verify_result == True
    
    with pytest.raises(bitcoinx.VerifyFailed):
        faucet.deposit(SigHashPreimage(preimage), deposit_sats - 1,
               Ripemd160(pkh), 0).verify(context)



def test_verify_with_change():
    deposit_sats = 100000
    input_sats = 100000
    output_sats = deposit_sats + input_sats
    change_sats = 547

    faucet.set_data_part(scryptlib.utils.get_push_int(1602553516))

    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = faucet.locking_script
    context.utxo.value = input_sats

    tx_out_0 = TxOutput(value=output_sats, script_pubkey=faucet.locking_script)
    context.tx.outputs.append(tx_out_0)

    tx_out_1 = TxOutput(value=change_sats, script_pubkey=P2PKH_Address(pkh, Bitcoin).to_script())
    context.tx.outputs.append(tx_out_1)

    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = scryptlib.utils.get_preimage_from_input_context(context, sighash_flag)

    verify_result = faucet.deposit(SigHashPreimage(preimage), deposit_sats,
            Ripemd160(pkh), change_sats).verify(context)
    assert verify_result == True
    
    with pytest.raises(bitcoinx.VerifyFailed):
        faucet.deposit(SigHashPreimage(preimage), deposit_sats,
               Ripemd160(pkh), change_sats + 1).verify(context)


def test_verify_withdraw():
    withdraw_sats = 2000000
    fee = 3000
    input_sats = 10000000
    output_sats = input_sats - withdraw_sats - fee
    mature_time = 1627122529

    faucet.set_data_part(scryptlib.utils.get_push_int(mature_time))

    context = scryptlib.utils.create_dummy_input_context()
    context.utxo.script_pubkey = faucet.locking_script
    context.utxo.value = input_sats

    new_locking_script = faucet.code_part << Script(scryptlib.utils.get_push_int(mature_time + 300))
    tx_out_0 = TxOutput(value=output_sats, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out_0)

    tx_out_1 = TxOutput(value=withdraw_sats, script_pubkey=P2PKH_Address(pkh, Bitcoin).to_script())
    context.tx.outputs.append(tx_out_1)

    context.tx.inputs[0].sequence = 0xfffffffe
    context.tx.locktime = mature_time + 300

    preimage = scryptlib.utils.get_preimage_from_input_context(context)

    verify_result = faucet.withdraw(SigHashPreimage(preimage), Ripemd160(pkh)).verify(context)
    assert verify_result == True

    # Wrong mature time
    context.tx.outputs = []

    new_locking_script = faucet.code_part << Script(scryptlib.utils.get_push_int(mature_time + 299))
    tx_out_0 = TxOutput(value=output_sats, script_pubkey=new_locking_script)
    context.tx.outputs.append(tx_out_0)

    tx_out_1 = TxOutput(value=withdraw_sats, script_pubkey=P2PKH_Address(pkh, Bitcoin).to_script())
    context.tx.outputs.append(tx_out_1)

    context.tx.locktime = mature_time + 299

    preimage = scryptlib.utils.get_preimage_from_input_context(context)

    with pytest.raises(bitcoinx.VerifyFailed):
        faucet.withdraw(SigHashPreimage(preimage), Ripemd160(pkh)).verify(context)


