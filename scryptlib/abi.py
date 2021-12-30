import copy
import re
from bitcoinx import TxInputContext, InterpreterLimits, MinerPolicy, Script

import scryptlib.utils as utils
import scryptlib.compiler_wrapper as compiler_wrapper
import scryptlib.types as types
import scryptlib.serializer as serializer


# TODO: Make type checking simpler.


CONTRACT_STATE_VERSION = 0


class ABICoder:

    def __init__(self, abi, aliases):
        self.abi = abi
        self.aliases = aliases

    def get_ls_code_part(self, contract, hex_script, *args):
        abi_constructor = self.abi_constructor()
        c_params = abi_constructor.get('params', [])

        if len(args) != len(c_params):
            raise Exception('Wrong number of arguments passed to constructor. ' \
                    'Expected {}, but got {}.'.format(len(c_params), len(args)))

        _c_params = []
        _args = []
        for idx, param in enumerate(c_params):
            arg = args[idx]
            arg = utils.primitives_to_scrypt_types(arg)
            resolved_type = utils.resolve_type(param['type'], self.aliases)
            is_param_statefull = param['state']
            if utils.is_array_type(resolved_type):
                elem_type, array_sizes = utils.factorize_array_type_str(resolved_type)

                if not utils.check_array(arg, elem_type, array_sizes):
                    raise Exception('Constructors parameter with index {} should be array of type "{}".'.format(idx, resolved_type))
                flattened_arr = utils.flatten_array(arg, param['name'], resolved_type)
                for obj in flattened_arr:
                    _c_params.append({ 'name': obj['name'], 
                                       'type': obj['type'],
                                       'state': is_param_statefull })
                    _args.append(obj['value'])
            elif utils.is_struct_type(resolved_type):
                if arg.final_type != resolved_type:
                    raise Exception('Constructors parameter with index {} should be struct of type "{}". ' \
                            'Got struct of type "{}" instead.'.format(idx, param['type'], arg.type_str))

                flattened_struct = utils.flatten_struct(arg, param['name'])
                for obj in flattened_struct:
                    _c_params.append({ 'name': obj['name'], 
                                       'type': obj['type'],
                                       'state': is_param_statefull })
                    _args.append(obj['value'])
            else:
                _c_params.append(param)
                _args.append(arg)

            if is_param_statefull:
                # If a statefull variable, set the passed value as a member of the contract object.
                setattr(contract, param['name'], arg)

        finalized_hex_script = hex_script
        for idx, param in enumerate(_c_params):
            if not '<{}>'.format(param['name']) in hex_script:
                raise Exception('Missing "{}" contract constructor parameter in passed args.'.format(param['name']))
            param_regex = re.compile(escape_str_for_regex('<{}>'.format(param['name'])))
            if param['state']:
                # State variables need only a placeholder value as they will get replaced during script execution.
                finalized_hex_script = re.sub(param_regex, '0100', finalized_hex_script)
            else:
                finalized_hex_script = re.sub(param_regex, self.encode_param(_args[idx], param), finalized_hex_script)


        finalized_hex_script = re.sub('<__codePart__>', '00', finalized_hex_script)

        # Replace inline assembly variable placeholders in locking script with the actual arguments.
        # TODO: Check if each value is instance of ScryptType
        if contract.inline_asm_vars:
            for key, val in contract.inline_asm_vars.items():
                param_regex = re.compile(escape_str_for_regex('<{}>'.format(key)))
                finalized_hex_script = re.sub(param_regex, val.hex, finalized_hex_script)

        return Script.from_hex(finalized_hex_script)
        #locking_script = Script.from_hex(finalized_hex_script)
        #return FunctionCall('constructor', args, contract, locking_script=locking_script)


    def get_ls_data_part(self, contract, custom_vals_dict=None):
        abi_constructor = self.abi_constructor()
        c_params = abi_constructor.get('params', [])

        state_buff = []

        for param in c_params:
            if not param['state']:
                continue

            param_name = param['name']
            resolved_type = utils.resolve_type(param['type'], self.aliases)

            if custom_vals_dict:
                val = custom_vals_dict[param_name]
            else:
                val = getattr(contract, param_name, None)
                if not val:
                    raise Exception('Statefull variable "{}" has no value.'.format(param_name))

            val = utils.primitives_to_scrypt_types(val)

            # Do type checking.
            if utils.is_array_type(resolved_type):
                elem_type, array_sizes = utils.factorize_array_type_str(resolved_type)
                if not utils.check_array(val, elem_type, array_sizes):
                    raise Exception('Statefull variable "{}" should be array of type "{}".'.format(param_name, resolved_type))
            elif utils.is_struct_type(resolved_type):
                if val.final_type != resolved_type:
                    raise Exception('Statefull variable "{}" should be struct of type "{}". ' \
                            'Got struct of type "{}" instead.'.format(param_name, param['type'], val.type_str))
            else:
                if val.final_type != resolved_type:
                    raise Exception('Statefull variable "{}" should be of type "{}". ' \
                            'Got object of type "{}" instead.'.format(param_name, param['type'], val.type_str))

            state_buff.append(serializer.serialize(val).hex())

        # State length and state version.
        state_len = 0
        for elem in state_buff:
            state_len += len(elem) // 2
        if state_len > 0:
            size_bytes = state_len.to_bytes(4, 'little')
            state_buff.append(size_bytes.hex())
            state_buff.append(CONTRACT_STATE_VERSION.to_bytes(1, 'little').hex())

        return Script.from_hex(''.join(state_buff))

    def encode_pub_function_call(self, contract, name, *args):
        for entity in self.abi:
            if entity['name'] == name:
                if len(entity['params']) != len(args):
                    raise Exception('Wrong number of arguments passed to function call "{}", ' \
                            'expected {}, but got {}.'.format(name, len(entity['params']), len(args)))
                hex_script = self.encode_params(args, entity['params'])
                if len(self.abi) > 2 and 'index' in entity:
                    pub_func_index = entity['index']
                    hex_script += '{}'.format(types.Int(pub_func_index).hex) # TODO
                unlocking_script = Script.from_hex(hex_script) 
                return FunctionCall(name, args, contract, unlocking_script=unlocking_script)

    def encode_params(self, args, param_entities):
        res = []
        for idx, arg in enumerate(args):
            res.append(self.encode_param(arg, param_entities[idx]))
        return ''.join(res)

    def encode_param(self, arg, param_entity):
        resolved_type = utils.resolve_type(param_entity['type'], self.aliases)
        if utils.is_array_type(resolved_type):
            if isinstance(arg, list):
                return self.encode_param_array(arg, param_entity)
            else:
                scrypt_type = arg.type_str
                raise Exception('Expected parameter "{}" as "{}", but got "{}".'.format(param_entity['name'],
                                    resolved_type, scrypt_type))
        if utils.is_struct_type(resolved_type):
            if isinstance(arg, types.Struct):
                if resolved_type != arg.final_type:
                    raise Exception('Expected struct of type "{}", but got struct of type "{}".'.format(
                                        param_entity['name'], resolved_type, arg.final_type))
            else:
                scrypt_type = arg.type_str
                raise Exception('Expected parameter "{}" as struct of type "{}", but got "{}".'.format(
                                        param_entity['name'], resolved_type, scrypt_type))

        scrypt_type = utils.type_of_arg(arg)
        if resolved_type != scrypt_type:
            raise Exception('Wrong argument type. Expected "{}", but got "{}".'.format(param_entity['type'], 
                                scrypt_type))

        if isinstance(arg, bool):
            arg = types.Bool(arg)
        elif isinstance(arg, int):
            arg = types.Int(arg)
        elif isinstance(arg, bytes):
            arg = types.Bytes(arg)

        return arg.hex

    def encode_param_array(self, args, param_entity):
        if len(args) == 0:
            raise Exception('Empty arrays not allowed.')
        
        first_arg_type = type(args[0])
        for arg in args:
            if type(arg) != first_arg_type:
                raise Exception('Array arguments are not of same type.')

        resolved_type = utils.resolve_type(param_entity['type'], self.aliases)
        elem_type, array_sizes = utils.factorize_array_type_str(resolved_type)

        if not utils.check_array(args, elem_type, array_sizes):
            raise Exception('Array check failed for "{}".'.format(param_entity['type']))

        res_buff = []
        for arg in utils.flatten_array(args, param_entity['name'], resolved_type):
            res_buff.append(self.encode_param(arg['value'], { 'name': arg['name'], 'type': arg['type'] }))
        return ''.join(res_buff)

    def abi_constructor(self):
        constructor_abi = None
        for entity in self.abi:
            if entity['type'] == compiler_wrapper.ABIEntityType.CONSTRUCTOR.value:
                constructor_abi = entity
                break
        return constructor_abi


class FunctionCall:

    def __init__(self, method_name, params, contract, unlocking_script=None):
        if not unlocking_script:
            raise Exception('Binding unlocking_script can\'t be empty.')

        self.contract = contract
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

    def verify(self, tx_input_context=utils.create_dummy_input_context(), interpreter_limits=None,
            use_contract_script_pair=True):
        '''
        Evaluate lock and unlock script pair using the passed TxInputContext object.
        Additionally an InterpreterLimits object can be passed to limit the scope of verification.

        If not TxInputContext object is passed, a dummy context object gets created and used in the verification 
        process.

        If use_contract_script_pair is set to True (defaults to True), then evaluate the scriptPubKey and scriptSig
        pair of the contract object, instead of the ones passed via the TxInputContext object.
        '''
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
            interpreter_limits = InterpreterLimits(policies[1], is_genesis_enabled=True, is_consensus=True, base_flags='consensus')

        # Make a deep copy of the passed TxInputContext object, because it may be modified from here on.
        tx_input_context = copy.deepcopy(tx_input_context)

        if use_contract_script_pair:
            self.update_input_context_scripts(tx_input_context)

        return tx_input_context.verify_input(interpreter_limits)

    def update_input_context_scripts(self, tx_input_context):
        '''
        Updates the unlocking input script (scriptSig) and the matching UTXOs locking script (scriptPubKey)
        to the unlocking script of this FunctionCall object and the locking script of the contract object it belongs to.

        Notice, that the function doesn't create a copy of the context object, but rather just modifies it.
        '''
        # Set unlock script for passed input context.
        input_index = tx_input_context.input_index
        tx_input_context.tx.inputs[input_index].script_sig = self.unlocking_script

        # Set utxo script to verify sciptSig against.
        tx_input_context.utxo.script_pubkey = self.contract.locking_script

        return tx_input_context

    @property
    def script(self):
        '''
        The function calls scriptSig.
        '''
        return self.unlocking_script


def escape_str_for_regex(string):
    special_chars = {'-', '\\', '^', '$', '*', '+', '?', '.', '(', ')', '|', '[', ']', '{', '}'}
    res_buff = []
    for c in string:
        if c in special_chars:
            res_buff.append('\\')
        res_buff.append(c)
    return ''.join(res_buff)
