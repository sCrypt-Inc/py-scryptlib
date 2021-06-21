import bitcoinx
from bitcoinx import Script, OP_RETURN

from scryptlib.compiler_wrapper import CompilerResult
from scryptlib.abi import ABICoder


class ContractBase:

    def __init__(self):
        self.calls = dict()
        self.asm_args = None
        self._data_part = None

    def replace_asm_vars(self, asm_var_values):
        self.asm_args = asm_var_values
        self.scripted_constructor.initialize(asm_var_values)

    #def run_verify(self, tx_input_context, interpreter_limits):
    #    # Set output script to verify sciptSig against.
    #    tx_input_context.utxo.script_pubkey = self.locking_script
    #    return tx_input_context.verify_input(interpreter_limits)

    def set_data_part(self, state):
        if isinstance(state, bytes):
            self._data_part = state
        elif isinstance(state, str):
            self._data_part = bytes.fromhex(state)
        else:
            raise NotImplementedError('Invalid object type for contract data part "{}"'.format(state.__class__))

    @property
    def locking_script(self):
        ls = self.scripted_constructor.locking_script
        if self._data_part and len(self._data_part) > 0:
            ls = ls << OP_RETURN
            ls = ls << Script(self._data_part)
        return ls

    @property
    def code_part(self):
        return self.scripted_constructor.locking_script << OP_RETURN

    @staticmethod
    def find_src_info():
        pass

    @staticmethod
    def find_last_f_exec():
        pass


def build_contract_class(desc):
    if isinstance(desc, CompilerResult):
        desc = desc.to_desc()

    def constructor(self, *args):
        super(self.__class__, self).__init__()
        #contract_empty_constructor = False
        #for obj in self.abi:
        #    if obj['type'] == 'constructor' and len(obj['params']) == 0:
        #        contract_empty_constructor = True
        #        break

        #if len(args) > 0 or contract_empty_constructor:
        #    self.scripted_constructor = self.abi_coder.encode_constructor_call(self, self.asm, *args)
        self.scripted_constructor = self.abi_coder.encode_constructor_call(self, self.asm, *args)

    @classmethod
    def from_asm(cls, asm):
        contract_obj = cls()
        contract_obj.scripted_constructor = cls.abi_coder.encode_constructor_call_from_asm(contract_obj, asm)
        return contract_obj

    @classmethod
    def from_hex(cls, val):
        return cls.from_asm(Script.from_hex(val).to_asm())

    @property
    def asm_vars(self):
        return self.get_asm_vars(self.asm, self.scripted_constructor.to_asm())

    contract_class_attribs = dict()
    contract_class_attribs['__init__'] = constructor
    contract_class_attribs['contract_name'] = desc['contract']
    contract_class_attribs['abi'] = desc['abi']
    contract_class_attribs['asm'] = desc['asm']
    contract_class_attribs['abi_coder'] = ABICoder(desc['abi'], desc.get('alias', []))
    contract_class_attribs['file'] = desc['file']
    contract_class_attribs['structs'] = desc['structs']
    for entity in desc['abi']:
        # TODO: Is it possible to avoid these conflicts?
        if not 'name' in entity:
            continue
        entity_name = entity['name']
        if entity_name in dir(ContractBase) or entity_name in contract_class_attribs:
            raise Exception('Method name "{}" conflicts with ContractClass member name.'.format(entity_name))

        def func_call_handler(self, *args):
            call = contract_class_attribs['abi_coder'].encode_pub_function_call(self, entity_name, *args)
            self.calls[entity_name] = call
            return call

        contract_class_attribs[entity_name] = func_call_handler

    return type('Contract', (ContractBase,), contract_class_attribs)


