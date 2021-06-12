import re
from bitcoinx import TxInputContext, InterpreterLimits, MinerPolicy, Script

import scryptlib.utils as utils
from scryptlib.compiler_wrapper import ABIEntityType
from scryptlib.types import Struct, Int


class ABICoder:

    def __init__(self, abi, alias):
        self.abi = abi
        self.alias = alias

    def encode_constructor_call(self, contract, asm, *args):
        abi_constructor = self.abi_constructor()
        c_params = self.__get_abi_params(abi_constructor)

        if len(args) != len(c_params):
            raise Exception('Wrong number of arguments passed to constructor.\
                    Expected {}, but got {}.'.format(len(c_params), len(args)))

        _c_params = []
        _args = []
        for idx, param in enumerate(c_params):
            arg = args[idx]
            resolved_type = utils.resolve_type(param['type'], self.alias)
            if utils.is_array_type(resolved_type):
                elem_type, array_sizes = utils.factorize_array_type_str(resolved_type)

                if not (isinstance(arg, list) or utils.check_array(arg, elem_type, array_sizes)):
                    raise Exception('Constructors parameter nr. {} should be of type "{}".'.format(idx, resolved_type))

                flattened_arr = utils.flatten_array(arg, param['name'], resolved_type)
                for obj in flattened_arr:
                    _c_params.append({ 'name': obj['name'], 'type': obj['type'] })
                    _args.append(obj['value'])
            elif utils.is_struct_type(resolved_type):
                if arg.final_type != resolved_type:
                    raise Exception('Constructors parameter nr. {} should be Struct object of type "{}".\
                            Got struct of type "{}" instead.'.format(idx, param['type'], arg.type))

                flattened_struct = utils.flatten_struct(arg, param['name'])
                for obj in flattened_struct:
                    _c_params.append({ 'name': obj['name'], 'type': obj['type'] })
                    _args.append(obj['value'])
            else:
                _c_params.append(param)
                _args.append(arg)

        finalized_asm = asm
        for idx, param in enumerate(_c_params):
            if not '${}'.format(param['name']) in asm:
                raise Exception('Missing "{}" contract constructor parameter in passed args.')
            param_regex = re.compile(escape_str_for_regex('${}'.format(param['name'])))
            finalized_asm = re.sub(param_regex, self.encode_param(_args[idx], param), finalized_asm)
        
        return FunctionCall('constructor', args, contract, locking_script=Script.from_asm(finalized_asm))

    def encode_pub_function_call(self, contract, name, *args):
        for entity in self.abi:
            if entity['name'] == name:
                if len(entity['params']) != len(args):
                    raise Exception('Wrong number of arguments passed to function call "{}",\
                            expected {}, but got {}.'.format(len(entity['params']), len(args)))
                asm = self.encode_params(args, entity['params'])
                if len(self.abi) > 2 and 'index' in entity:
                    pub_func_index = entity['index']
                    asm += ' {}'.format(Int(pub_func_index).asm)

                return FunctionCall(name, args, contract, unlocking_script=Script.from_asm(asm))

    def encode_params(self, args, param_entities):
        res = []
        for idx, arg in enumerate(args):
            res.append(self.encode_param(arg, param_entities[idx]))
        return ' '.join(res)

    def encode_param(self, arg, param_entity):
        resolved_type = utils.resolve_type(param_entity['type'], self.alias)
        if utils.is_array_type(resolved_type):
            if isinstance(arg, list):
                return self.encode_param_array(arg, param_entity)
            else:
                scrypt_type = arg.type_str
                raise Exception('Expected parameter "{}" as "{}", but got "{}".'.format(param_entity['name'],
                                    resolved_type, scrypt_type))
        if utils.is_struct_type(resolved_type):
            if isinstance(arg, Struct):
                if resolved_type != arg.final_type:
                    raise Exception('Expected struct of type "{}", but got struct of type "{}".'.format(
                                        param_entity['name'], resolved_type, arg.final_type))
            else:
                scrypt_type = arg.type_str
                raise Exception('Expected parameter ""{}" as struct of type "{}", but got "{}".'.format(
                                        param_entity['name'], resolved_type, scrypt_type))

        scrypt_type = arg.type_str
        if resolved_type != scrypt_type:
            raise Exception('Wrong argument type, expected "{}" or "{}", but got "{}".'.format(final_type,
                                param_entity['type'], scrypt_type))

        if isinstance(arg, bool):
            arg = Bool(arg)
        elif isinstance(arg, int):
            arg = Int(arg)

        return arg.asm

    def encode_param_array(self, args, param_entity):
        if len(args) == 0:
            raise Exception('Empty arrays not allowed.')
        
        first_arg_type = type(args[0])
        for arg in args:
            if type(arg) != first_arg_type:
                raise Exception('Array arguments are not of same type')

        resolved_type = utils.resolve_type(param_entity['type'], self.alias)
        elem_type, array_sizes = utils.factorize_array_type_str(resolve_type)

        if not utils.check_array(args, elem_type, array_sizes):
            raise Exception('Array check failed for "{}".'.format(param_entity['type']))

        res_buff = []
        for arg in utils.flatten_array(args, param_entity['name'], resolved_type):
            res_buff.append(self.encode_param(arg['value'], { 'name': arg['name'], 'type': arg['type'] }))
        return ' '.join(res_buff)

    def abi_constructor(self):
        constructor_abi = None
        for entity in self.abi:
            if entity['type'] == ABIEntityType.CONSTRUCTOR.value:
                constructor_abi = entity
                break
        return constructor_abi

    @staticmethod
    def __get_abi_params(abi_entity):
        return abi_entity.get('params', [])


class FunctionCall:

    def __init__(self, method_name, params, contract, locking_script=None, unlocking_script=None):
        if not (locking_script or unlocking_script):
            raise Exception('Binding locking_script_asm and unlocking_script_asm can\'t both be empty.')

        self.contract = contract
        self.locking_script = locking_script
        self.unlocking_script = unlocking_script
        self.method_name = method_name

        self.args = []
        for entity in self.contract.abi:
            if (method_name == 'constructor' and entity['type'] == 'constructor') or \
                    ('name' in entity and entity['name'] == method_name):
                for idx, param in enumerate(entity['params']):
                    self.args.append({
                        'name': param['name'],
                        'type': param['type'],
                        'value': params[idx]
                        })

    #def initialize(asm_var_values):
    #    for key, val in asm_var_values.items():
    #        self._locking_script_asm = re.sub('\\${}'.format(key), val, this._locking_script_asm)

    def to_asm(self):
        if self.unlocking_script:
            return self.unlocking_script.to_asm(decode_sighash=True)
        if self.locking_script:
            return self.locking_script.to_asm(decode_sighash=True)

    def verify(self, tx_input_context=utils.create_dummy_input_context(), interpreter_limits=None):
        assert isinstance(tx_input_context, TxInputContext)

        if not self.unlocking_script:
            raise Exception('Cannot verify function "{}". \
                    FunctionCall object is missing unlocking_script property.'.format(self.method_name))

        if not interpreter_limits:
            policies = [
                # A fairly restrictive policy
                MinerPolicy(100_000, 64, 20_000, 1_000, 16),
                # A loose policy
                MinerPolicy(10_000_000, 256, 10_000_000, 32_000, 256)
            ]
            interpreter_limits = InterpreterLimits(policies[1], is_genesis_enabled=True, is_consensus=True)

        # Set unlock script for passed input context.
        input_index = tx_input_context.input_index
        tx_input_context.tx.inputs[input_index].script_sig = self.unlocking_script

        return self.contract.run_verify(tx_input_context, interpreter_limits)


def escape_str_for_regex(string):
    special_chars = {'-', '\\', '^', '$', '*', '+', '?', '.', '(', ')', '|', '[', ']', '{', '}'}
    res_buff = []
    for c in string:
        if c in special_chars:
            res_buff.append('\\')
        res_buff.append(c)
    return ''.join(res_buff)
