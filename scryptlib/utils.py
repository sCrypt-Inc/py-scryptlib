import sys
import errno
import re
import os
import math
from pathlib import Path

import bitcoinx
from bitcoinx import Script, Tx, TxInput, TxOutput, TxInputContext, SigHash, \
        pack_le_int32, pack_le_uint32, pack_le_uint16, ScriptError, pack_byte, Ops, \
        int_to_le_bytes

from scryptlib.compiler_wrapper import CompilerWrapper
import scryptlib.types


def compile_contract(contract, out_dir=None, compiler_bin=None, from_string=False, debug=True):
    '''
    Compile sCrypt contract from a file or a string object. Returns instance of class
    CompilerResult if the compilation was successfull.
    '''
    if not from_string:
        contract = Path(contract)
        if not contract.is_file():
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), contract.name)
    
    if not compiler_bin:
        compiler_bin = find_compiler()

    if not out_dir:
        out_dir = Path('./out')
    else:
        out_dir = Path(out_dir)

    if not out_dir.is_file() and not out_dir.is_dir():
        out_dir.mkdir(parents=True)
    elif not out_dir.is_dir():
        raise Exception('File "{}" is not a directory.'.format(str(out_dir)))

    compiler_wrapper = CompilerWrapper(
            debug=debug,
            stack=True,
            out_dir=out_dir,
            compiler_bin=compiler_bin
            )
    return compiler_wrapper.compile(contract)


def find_compiler():
    '''
    Searches known directories for a specific platform and returns Path object of the sCrypt
    compiler binary if found.
    '''
    scryptc = None

    if sys.platform.startswith('linux'):
        scryptc = find_compiler_linux()
    elif sys.platform == 'darwin':
        scryptc = find_compiler_darwin()
    elif sys.platform == 'win32' or sys.platform == 'cygwin':
        scryptc = find_compiler_windows()

    return scryptc
        

def find_compiler_linux():
    path_suffix = 'compiler/scryptc/linux/scryptc'

    res = find_compiler_local(path_suffix)
    if res:
        return res

    res = find_compiler_vscode(path_suffix)
    if res:
        return res


def find_compiler_darwin():
    path_suffix = 'compiler/scryptc/mac/scryptc'

    res = find_compiler_local(path_suffix)
    if res:
        return res

    res = find_compiler_vscode(path_suffix)
    if res:
        return res


def find_compiler_windows():
    path_suffix = 'compiler/scryptc/win32/scryptc.exe'

    res = find_compiler_local(path_suffix)
    if res:
        return res

    res = find_compiler_vscode(path_suffix)
    if res:
        return res


def find_compiler_vscode(path_suffix):
    env_home = os.path.expanduser('~')
    if env_home:
        home_dir = Path(env_home)
        for vscode_folder in ['.vscode-oss', '.vscode']:
            vscode_path = home_dir / Path('{}/extensions/'.format(vscode_folder))
            if vscode_path.exists() and vscode_path.is_dir():
                extension_res = None
                for extension_dir in sorted(vscode_path.glob('bsv-scrypt.scrypt-*')):
                    # Ensure that filename is of correct format.
                    match = re.match(r'bsv-scrypt\.scrypt-[0-9]\.[0-9]\.[0-9]', extension_dir.name)
                    if match:
                        extension_res = extension_dir

                if extension_res:
                    res = extension_dir / path_suffix
                    if res.exists():
                        return res


def find_compiler_local(path_suffix):
    path = Path('./') / path_suffix
    if path.exists():
        return path


def to_literal_array_type(type_name, sizes):
    '''
    Returns e.g. 'int', [2,2,3] -> 'int[2][2][3]'.
    '''
    str_buff = [type_name]
    for size in sizes:
        str_buff.append('[')
        str_buff.append(str(size))
        str_buff.append(']')
    return ''.join(str_buff)


def get_struct_name_by_type(type_name):
    '''
    Returns struct name from type string e.g.: 'struct ST1 {}[2][2][2]' -> 'ST1'.
    '''
    # TODO: Throw exception for malformed type string?
    type_name = type_name.strip()
    match = re.match(r'^struct\s(\w+)\s\{\}.*$', type_name)
    if match:
        return match.group(1)
    return ''


def resolve_type(type_str, aliases):
    if is_array_type(type_str):
        elem_type_name, array_sizes = factorize_array_type_str(type_str)
        return to_literal_array_type(resolve_type(elem_type_name, aliases), array_sizes)

    if is_struct_type(type_str):
        return resolve_type(get_struct_name_by_type(type_str), aliases)

    for alias in aliases:
        if alias['name'] == type_str:
            return resolve_type(alias['type'], aliases)

    if type_str in scryptlib.types.BASIC_SCRYPT_TYPES:
        return type_str
    else:
        return 'struct {} {{}}'.format(type_str)


def is_array_type(type_str):
    if re.match(r'^\w[\w.\s{}]+(\[[\w.]+\])+$', type_str):
        return True
    return False


def is_struct_type(type_str):
    if re.match(r'^struct\s(\w+)\s\{\}$', type_str):
        return True
    return False


def factorize_array_type_str(type_str):
    '''
    Factor array declaration string to array type and sizes.
    e.g. 'int[N][N][4]' -> ['int', ['N', 'N', '4']]
    '''
    array_sizes = []
    for match in re.finditer(r'\[([\w.]+)\]+', type_str):
        array_sizes.append(match.group(1))
    elem_type_name = type_str.split('[')[0]
    return elem_type_name, array_sizes


def type_of_arg(arg):
    if isinstance(arg, scryptlib.types.ScryptType):
        return arg.final_type
    elif isinstance(arg, bool):
        return 'bool'
    elif isinstance(arg, int):
        return 'int'
    elif isinstance(arg, bytes):
        return 'bytes'
    elif isinstance(arg, list):
        return 'list'
    raise Exception('Can\'t find matching sCrypt type for object of type "{}".'.format(arg.__class__))


def check_array(obj_list, elem_type, array_sizes):
    if not isinstance(obj_list, list):
        return False

    if int(array_sizes[0]) != len(obj_list):
        return False

    for elem in obj_list:
        if isinstance(elem, list):
            if not check_array(elem, elem_type, array_sizes[1:]):
                return False
        else:
            scrypt_type = type_of_arg(elem)
            if not (scrypt_type == elem_type and len(array_sizes) == 1):
                return False

    return True

def check_struct(struct_ast, struct, type_resolver):
    # TODO: check member types
    for param in struct_ast['params']:
        member = struct.member_by_key(param['name'])
        final_type = type_of_arg(member)
        param_final_type = type_resolver(param['type'])
        if not final_type:
            raise Exception('Argument of type struct "{}" is missing member "{}".'.format(struct_ast['name'], param['name']))
        elif final_type != param_final_type:
            if is_array_type(param_final_type):
                elem_type, array_sizes = factorize_array_type_str(param_final_type)
                if isinstance(struct.value[param['name']], list):
                    if not check_array(struct.value[param['name']], elem_type, array_sizes):
                        raise Exception('Array check failed. scryptlib.types.Struct "{}" property "{}" should be "{}".'.format(
                                            struct_ast['name'], param['name'], param_final_type))
                else:
                    raise Exception('scryptlib.types.Struct "{}" property "{}" should be "{}".'.format(
                                        struct_ast['name'], param['name'], param_final_type))
            else:
                raise Exception('Wrong argument type. Expected "{}", but got "{}".'.format(final_type, param_final_type))

    members = []
    for param in struct_ast['params']:
        members.append(param['name'])

    for member in struct.get_members():
        if not member in members:
            raise Exception('"{}" is not a member of struct "{}".'.format(member, struct_ast['name']))


def subscript(idx, array_sizes):
    if len(array_sizes) == 1:
        return '[{}]'.format(idx)
    elif len(array_sizes) > 1:
        sub_array_sizes = array_sizes[1:]
        offset = 1
        for size_str in sub_array_sizes:
            offset += int(size_str)
        return '[{}]{}'.format(math.floor(idx / offset), subscript(idx % offset, sub_array_sizes))


def flatten_array(obj_list, name, resolved_type):
    assert isinstance(obj_list, list)

    elem_type, array_sizes = factorize_array_type_str(resolved_type)

    res = []
    for idx, obj in enumerate(obj_list):
        # TODO: Throw this checking out. All members should be of scryptlib.types.ScryptType. Use primitives_to_scrypt_types().
        if isinstance(obj, bool):
            obj = scryptlib.types.Bool(obj)
        elif isinstance(obj, int):
            obj = scryptlib.types.Int(obj)
        elif isinstance(obj, list):
            res += flatten_array(obj, '{}[{}]'.format(name, idx), sub_array_type(resolved_type))
            continue
        elif isinstance(obj, scryptlib.types.Struct):
            res += flatten_struct(obj, '{}[{}]'.format(name, idx))
            continue
        res.append({
            'value': obj,
            'name': '{}{}'.format(name, subscript(idx, array_sizes)),
            'type': elem_type
            })
    return res


def flatten_struct(obj, name):
    assert isinstance(obj, scryptlib.types.Struct)

    keys = obj.get_members()
    res = []
    for key in keys:
        member = obj.member_by_key(key)
        if isinstance(member, scryptlib.types.Struct):
            res += flatten_struct(member, '{}.{}'.format(name, key))
        elif isinstance(member, list):
            resolved_type = obj.get_member_ast_final_type(key)
            res += flatten_array(member, '{}.{}'.format(name, key), resolved_type)
        else:
            res.append({
                'value': member,
                'name': '{}.{}'.format(name, key),
                'type': member.type_str
                })
    return res


def primitives_to_scrypt_types(obj):
    '''
    Returns matching object of scryptlib.types.ScryptType. Raises Exception, if not possible.
    '''
    res = None
    if isinstance(obj, list):
        res = []
        for item in obj:
            res.append(primitives_to_scrypt_types(item))
    elif isinstance(obj, bool):
        res = scryptlib.types.Bool(obj)
    elif isinstance(obj, int):
        res = scryptlib.types.Int(obj)
    elif isinstance(obj, scryptlib.types.ScryptType):
        res = obj

    if not res:
        raise Exception('Could not find matching sCrypt type for object of type "{}".'.format(obj.__class__.__name__))

    return res


def get_push_item(item_bytes):
    '''
    Returns script bytes to push item on the stack. ALL data is length prefixed.
    '''
    dlen = len(item_bytes)
    if dlen < Ops.OP_PUSHDATA1:
        return pack_byte(dlen) + item_bytes
    elif dlen <= 0xff:
        return pack_byte(Ops.OP_PUSHDATA1) + pack_byte(dlen) + item_bytes
    elif dlen <= 0xffff:
        return pack_byte(Ops.OP_PUSHDATA2) + pack_le_uint16(dlen) + item_bytes
    return pack_byte(Ops.OP_PUSHDATA4) + pack_le_uint32(dlen) + item_bytes


def get_push_int(value):
    '''Returns script bytes to push a numerical value to the stack.  Stack values are stored as
    signed-magnitude little-endian numbers.
    '''
    if value == 0:
        return b'\x01\x00'
    item = int_to_le_bytes(abs(value))
    if item[-1] & 0x80:
        item += pack_byte(0x80 if value < 0 else 0x00)
    elif value < 0:
        item = item[:-1] + pack_byte(item[-1] | 0x80)

    return get_push_item(item)
        

def sub_array_type(type_str):
    elem_type, array_sizes = factorize_array_type_str(type_str)
    return to_literal_array_type(elem_type, array_sizes[1:])


def create_dummy_input_context():
    '''
    Creates dummy instance of bitoinx.TxInputContext with empty locking and unlocking scripts.
    '''
    tx_version = 2
    tx_locktime = 0x00000000

    utxo_satoshis = 0
    script_pubkey = Script()
    utxo = TxOutput(utxo_satoshis, script_pubkey)
    prev_tx = Tx(tx_version, [], [utxo], tx_locktime)
    prev_txid = prev_tx.hash()

    utxo_idx = 0
    script_sig = Script()
    n_sequence = 0xffffffff
    curr_in = TxInput(prev_txid, utxo_idx, script_sig, n_sequence)
    curr_tx = Tx(tx_version, [curr_in], [], tx_locktime)

    input_idx = 0
    return TxInputContext(curr_tx, input_idx, utxo, is_utxo_after_genesis=True)


def get_preimage(tx, input_index, utxo_value, utxo_script, sighash_flag=None):
    if not sighash_flag:
        sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)

    txin = tx.inputs[input_index]
    hash_prevouts = hash_sequence = hash_outputs = bitcoinx.consts.ZERO

    sighash_not_single_none = sighash_flag.base not in (SigHash.SINGLE, SigHash.NONE)
    if not sighash_flag.anyone_can_pay:
        hash_prevouts = tx._hash_prevouts()
        if sighash_not_single_none:
            hash_sequence = tx._hash_sequence()
    if sighash_not_single_none:
        hash_outputs = tx._hash_outputs()
    elif (sighash_flag.base == SigHash.SINGLE and input_index < len(tx.outputs)):
        hash_outputs = double_sha256(tx.outputs[input_index].to_bytes())

    preimage = b''.join((
        pack_le_int32(tx.version),
        hash_prevouts,
        hash_sequence,
        txin.to_bytes_for_signature(utxo_value, utxo_script),
        hash_outputs,
        pack_le_uint32(tx.locktime),
        pack_le_uint32(sighash_flag),
    ))
    return preimage


def get_preimage_from_input_context(context, sighash_flag=None):
    if not sighash_flag:
        sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)

    tx = context.tx
    input_index = context.input_index
    utxo_value = context.utxo.value
    utxo_script = context.utxo.script_pubkey
    return get_preimage(tx, input_index, utxo_value, utxo_script, sighash_flag)
