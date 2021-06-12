import sys
import errno
import re
import os
from pathlib import Path

from bitcoinx import Script, Tx, TxInput, TxOutput, TxInputContext

from scryptlib.compiler_wrapper import CompilerWrapper
from scryptlib.types import ScryptType, Bool, Int, Struct, BASIC_TYPES, DOMAIN_SUBTYPES



def compile_contract(contract, out_dir=None, compiler_bin=None, from_string=False):
    '''
    Compile sCrypt contract from a file or a string object. Returns instance of class
    CompilerResult if the compilation was successfull.
    '''
    if not from_string:
        contract = Path(contract)
        if not contract.is_file():
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), contract.name)
    
    if not compiler_bin:
        #raise Exception('Auto finding sCrypt compiler is not yet implemented.') # TODO
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
            desc=True,
            debug=True,
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
        pass
    elif sys.platform == 'win32' or sys.platform == 'cygwin':
        pass

    return scryptc
        

def find_compiler_linux():
    path_suffix = 'compiler/scryptc/linux/scryptc'

    res = find_compiler_vscode_unix(path_suffix)
    if res:
        return res


def find_compiler_darwin():
    path_suffix = 'compiler/scryptc/mac/scryptc'

    res = find_compiler_vscode_unix(path_suffix)
    if res:
        return res


def find_compiler_windows():
    path_suffix = 'compiler/scryptc/win32/scryptc.exe'


def find_compiler_vscode_unix(path_suffix):
    env_home = os.environ['HOME']
    if env_home:
        home_dir = Path(env_home)
        vscode_path = home_dir / Path('.vscode-oss/extensions/')
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
    type_name = type_name.strip()
    match = re.match(r'^struct\s(\w+)\s\{\}$', type_name)
    if match:
        return match.group(1)
    return ''


def resolve_type(type_str, aliases):
    if is_array_type(type_str):
        elem_type_name, array_sizes = factorize_array_type_str(type_str)
        return to_literal_array_type(elem_type_name, array_sizes)

    if is_struct_type(type_str):
        resolve_type(get_struct_name_by_type(type_str), aliases)

    for alias in aliases:
        if alias['name'] == type_str:
            return resolve_type(alias['type'], aliases)

    if type_str in BASIC_TYPES.union(DOMAIN_SUBTYPES):
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


def check_array(obj_list, elem_type, array_sizes):
    if not isinstance(obj_list, list):
        return False

    if array_sizes[0] != len(obj_list):
        return False

    for elem in obj_list:
        if isinstance(elem, list):
            if not check_array(elem, elem_type, array_sizes[1:]):
                return False
        else:
            scrypt_type = obj.type_str
            if not (scrypt_type == elem_type and len(array_sizes) == 1):
                return False

    return True


def flatten_array(obj_list, name, resolved_type):
    assert isinstance(obj_list, list)

    elem_type, array_sizes = factorize_array_type_str(resolved_type)

    res = []
    for idx, obj in obj_list:
        if isinstance(obj, bool):
            obj = Bool(obj)
        elif isinstance(obj, int):
            obj = Int(obj)
        elif isinstance(obj, list):
            res.append(flatten_array(obj, '{}[{}]'.format(name, idx), sub_array_type(resolved_type)))
        elif isinstance(obj, Struct):
            res.append(flatten_struct(obj, '{}[{}]'.format(name, idx)))
        else:
            res.append({
                'value': obj,
                'name': '{}{}'.format(idx, subscript(idx, array_sizes)),
                'type': elem_type
                })
    return res


def flatten_struct(obj, name):
    assert isinstance(obj_list, Struct)

    keys = obj.get_members()
    res = []
    for key in keys:
        member = obj.member_by_key(key)
        if isinstance(member, Struct):
            res.append(flatten_struct(member, '{}.{}'.format(name, key)))
        elif isinstance(member, list):
            resolved_type = obj.get_member_ast_final_type(key)
            res.append(flatten_array(member, '{}.{}'.format(name, key), resolved_type))
        else:
            res.append({
                'value': member,
                'name': '{}.{}'.format(name, key),
                'type': member.type
                })
    return res


def sub_array_type(type_str):
    elem_type, array_sizes = factorize_array_type_str(type_str)
    return to_literal_array_type(elem_type, array_sizes[1:])


def create_dummy_input_context():
    '''
    Creates dummy instance of bitoinx.TxInputContext with empty locking and unlocking scripts.
    '''
    tx_version = 2
    tx_locktime = 0x00000000

    out_satoshis = 0
    script_pubkey = Script()
    prev_out = TxOutput(out_satoshis, script_pubkey)
    prev_tx = Tx(tx_version, [], [prev_out], tx_locktime)
    prev_txid = prev_tx.hash()

    prev_out_idx = 0
    script_sig = Script()
    n_sequence = 0xffffffff
    curr_in = TxInput(prev_txid, prev_out_idx, script_sig, n_sequence)
    curr_tx = Tx(tx_version, [curr_in], [], tx_locktime)

    input_idx = 0
    return TxInputContext(curr_tx, input_idx, prev_out, is_utxo_after_genesis=True)


def get_preimage(tx, input_index, utxo_value, script_code, sighash_type):
    pass


def get_preimage_from_input_context(context):
    pass
