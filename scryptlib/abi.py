import re

import scryptlib.utils as utils
from scryptlib.compiler_wrapper import ABIEntityType
from scryptlib.types import Struct


class ABICoder:

    def __init__(self, abi, alias):
        self.abi = abi
        self.alias = alias

    def encode_constructor_call(self, contract, asm, *args):
        abi_constructor = self.abi_constructor()
        c_params = self.__get_abi_params(abi_constructor)

        if len(args) != len(c_params):
            raise Exception('Wrong number of arguments pased to constructor.\
                    Expected {}, but got {}.'.format(len(c_params), len(args)))

        _c_params = []
        _args = []
        for idx, param in enumerate(c_params.values()):
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

        finalized_asm = asm.copy()
        for idx, param in enumerate(_c_params.values()):
            if not '${}'.format(param['name']) in asm:
                raise Exception('Missing "{}" contract constructor parameter in passed args.')
            param_regex = re.compile(escape_str_for_regex('${}'.format(param['name'])))
            finalized_asm = re.sub(param_regex, self.encode_param(_args[idx], param), finalized_asm)
        
        # TODO
        #return FunctionCall('constructor', args, { 'contract': contract, 'locking_script_asm': finalized_asm })
        return False

    def encode_param(self, arg, param_entity):
        resolved_type = utils.resolve_type(param_entity['type'], self.alias)
        if utils.is_array_type(resolved_type):
            if isinstance(arg, list):
                return self.encode_param_array(arg, param_entity)
            else:
                scrypt_type = utils.get_scrypt_type(arg)
                raise Exception('Expected parameter "{}" as "{}", but got "{}".'.format(param_entity['name'],
                                    resolved_type, scrypt_type))
        if utils.is_struct_type(resolved_type):
            if isinstance(arg, Struct):
                if resolved_type != arg.final_type:
                    raise Exception('Expected struct of type "{}", but got struct of type "{}".'.format(
                                        param_entity['name'], resolved_type, arg.final_type))
            else:
                scrypt_type = utils.get_scrypt_type(arg)
                raise Exception('Expected parameter ""{}" as struct of type "{}", but got "{}".'.format(
                                        param_entity['name'], resolved_type, scrypt_type))

        scrypt_type = utils.get_scrypt_type(arg)
        if resolved_type != scrypt_type:
            raise Exception('Wrong argument type, expected "{}" or "{}", but got "{}".'.format(final_type,
                                param_entity['type'], scrypt_type))

        if isinstance(arg, bool):
            arg = Bool(arg)
        elif isinstance(arg, int):
            arg = Int(arg)

        return arg.to_asm()

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
            res_buff.append(self.encode_param(arg['value'], { 'name': arg['name'], 'type': arg['type'] })
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


def escape_str_for_regex(string):
    special_chars = {'-', '\\', '^', '$', '*', '+', '?', '.', '(', ')', '|', '[', ']', '{', '}'}
    res_buff = []
    for c in string:
        if c in special_chars:
            res_buff.append('\\')
        res_buff.append(c)
    return ''.join(res_buff)
