from functools import partialmethod

from bitcoinx import Script, OP_RETURN

import scryptlib.utils as utils
import scryptlib.compiler_wrapper as compiler_wrapper
import scryptlib.abi as abi
import scryptlib.types as types
import scryptlib.serializer as serializer


class ContractBase:

    def set_data_part(self, state):
        if isinstance(state, bytes):
            self._manual_data_part = Script(state)
        elif isinstance(state, str):
            self._manual_data_part = Script(bytes.fromhex(state))
        elif isinstance(state, dict):
            self._manual_data_part = Script(serializer.serialize_state(state))
        else:
            raise NotImplementedError('Invalid object type for contract data part "{}".'.format(state.__class__))

    @property
    def locking_script(self):
        ls = self._code_part
        data_part = self.data_part
        if data_part and len(data_part) > 0:
            ls = ls << OP_RETURN
            ls = ls << data_part
        return ls

    @property
    def code_part(self):
        return self._code_part << OP_RETURN

    @property
    def data_part(self):
        if self._manual_data_part:
            return self._manual_data_part
        return self.abi_coder.get_ls_data_part(self)

    def get_state_script(self, vals_dict):
        '''
        Returns a locking script object with data part updated with values passed in  the vals_dict parameter.
        This doesn't update the actual contracts state variables values.

        Parameters
        ----------
        vals_dict: dict
            A dictionary with contracts statefull variable names as keys and values of according ScryptType or primitive type.
        '''
        ls = self._code_part
        ls = ls << OP_RETURN
        return ls << self.abi_coder.get_ls_data_part(self, custom_vals_dict=vals_dict)

    @staticmethod
    def find_src_info():
        pass

    @staticmethod
    def find_last_f_exec():
        pass


def build_contract_class(desc):
    if isinstance(desc, compiler_wrapper.CompilerResult):
        desc = desc.to_desc()

    def constructor(self, *args, **kwargs):
        self.calls = dict()
        self.inline_asm_vars = kwargs.get('asm_vars')

        self._code_part = self.abi_coder.get_ls_code_part(self, self.hex, *args)
        self._manual_data_part = None

    @classmethod
    def from_asm(cls, asm):
        # TODO
        #contract_obj = cls()
        #contract_obj.scripted_constructor = cls.abi_coder.encode_constructor_call_from_asm(contract_obj, asm)
        #return contract_obj
        return

    @classmethod
    def from_hex(cls, val):
        # TODO
        #return cls.from_asm(Script.from_hex(val).to_asm())
        return

    contract_class_attribs = dict()
    contract_class_attribs['__init__'] = constructor
    contract_class_attribs['contract_name'] = desc['contract']
    contract_class_attribs['abi'] = desc['abi']
    contract_class_attribs['asm'] = desc['asm']
    contract_class_attribs['hex'] = desc['hex']
    contract_class_attribs['abi_coder'] = abi.ABICoder(desc['abi'], desc.get('alias', []))
    contract_class_attribs['file'] = desc['file']
    contract_class_attribs['structs'] = desc['structs']
    for entity in desc['abi']:
        entity_type = entity['type']
        if entity_type == 'function':
            entity_name = entity['name']
            # TODO: Is it possible to avoid these conflicts?
            if entity_name in dir(ContractBase) or entity_name in contract_class_attribs:
                raise Exception('Public function name "{}" conflicts with ContractClass member name.'.format(entity_name))

            def func_call_handler(self, entity_name, *args):
                call = contract_class_attribs['abi_coder'].encode_pub_function_call(self, entity_name, *args)
                self.calls[entity_name] = call
                return call

            contract_class_attribs[entity_name] = partialmethod(func_call_handler, entity_name)
        elif entity_type == 'constructor':
            for param in entity['params']:
                if param['state']:
                    param_name = param['name']
                    if param_name in dir(ContractBase) or param_name in contract_class_attribs:
                        raise Exception('Statefull variable name "{}" conflicts with ContractClass member name.'.format(param_name))
                    contract_class_attribs[param_name] = None

    return type('Contract', (ContractBase,), contract_class_attribs)


def build_struct_classes(desc):
    struct_classes = dict()
    structs = desc['structs'] if 'structs' in desc else []
    aliases = desc['alias'] if 'alias' in desc else []
    final_type_resolver = build_type_resolver(aliases)

    for struct in structs:
        name = struct['name']
        def constructor(self, struct_obj):
            # TODO: Solve recursion problem with calling super constructor.
            #       For now value is set manualy.
            #super(self.__class__, self).__init__(struct_obj)
            assert isinstance(struct_obj, dict)
            self.value = struct_obj
            self._type_resolver = final_type_resolver
            self.bind()
        type_class_attribs = dict()
        type_class_attribs['__init__'] = constructor
        type_class_attribs['struct_ast'] = struct
        struct_classes[name] = type(name, (types.Struct,), type_class_attribs)
    return struct_classes


def build_type_classes(desc):
    # TODO: Type class constructors shold accept primitive types like ints and bytes where applicable.
    #       They also should accept lists.
    struct_classes = build_struct_classes(desc)

    alias_classes = dict()
    aliases = desc['alias'] if 'alias' in desc else []
    final_type_resolver = build_type_resolver(aliases)

    for alias in aliases:
        alias_name = alias['name']
        final_type = final_type_resolver(alias_name)
        if utils.is_struct_type(final_type):
            struct_name = utils.get_struct_name_by_type(final_type)
            def constructor(self, struct_obj):
                # TODO: Solve recursion problem with calling super constructor.
                #       For now value is set manualy.
                #super(self.__class__, self).__init__(struct_obj)
                assert isinstance(struct_obj, dict)
                self.value = struct_obj
                self.type_str = alias_name
                self._type_resolver = final_type_resolver
                self.bind()
            alias_class_atribs = dict()
            alias_class_atribs['__init__'] = constructor
            alias_classes[alias_name] = type(alias_name, (struct_classes[struct_name],), alias_class_atribs)
        elif utils.is_array_type(final_type):
            elem_type_name, _ = utils.factorize_array_type_str(final_type)
            if elem_type_name in types.BASIC_SCRYPT_TYPES:
                alias_classes[alias_name] = list()
            elif utils.is_struct_type(elem_type_name):
                struct_name = utils.get_struct_name_by_type(elem_type_name)
                alias_classes[alias_name] = list()
        else:
            if final_type in types.BASIC_SCRYPT_TYPES:
                def constructor(self, struct_obj):
                    # TODO: Solve recursion problem with calling super constructor.
                    #       For now value is set manualy.
                    #super(self.__class__, self).__init__(struct_obj)
                    assert isinstance(struct_obj, dict)
                    self.value = struct_obj
                    self.type_str = alias_name
                    self._type_resolver = final_type_resolver
                    self.bind()
                alias_class_atribs = dict()
                alias_class_atribs['__init__'] = constructor
                alias_classes[alias_name] = type(alias_name, (types.BASIC_SCRYPT_TYPES[final_type],), alias_class_atribs)
            else:
                raise Exception('Could not resolve alias "{}" for type "{}".'.format(alias_name, alias['type']))

    return {**alias_classes, **struct_classes}


def build_type_resolver(aliases):
    resolved_types = dict()
    for alias in aliases:
        final_type = utils.resolve_type(alias['name'], aliases)
        resolved_types[alias['name']] = final_type

    def resolver_func(alias):
        if utils.is_struct_type(alias):
            alias = utils.get_struct_name_by_type(alias)
        array_type = ''
        if utils.is_array_type(alias):
            elem_type_name, sizes = utils.factorize_array_type_str(alias)
            if utils.is_struct_type(elem_type_name):
                alias = utils.get_struct_name_by_type(elem_type_name)
            else:
                alias = elem_type_name
            array_type_buff = []
            for size in sizes:
                array_type_buff.append('[{}]'.format(size))
            array_type = ''.join(array_type_buff)
        if alias in types.BASIC_SCRYPT_TYPES:
            return '{}{}'.format(alias, array_type)
        if alias in resolved_types:
            return '{}{}'.format(resolved_types[alias], array_type)
        return 'struct {} {{}}{}'.format(alias, array_type)

    return resolver_func

