from functools import partialmethod

import bitcoinx
from bitcoinx import Script, OP_RETURN

import scryptlib.utils as utils
from scryptlib.compiler_wrapper import CompilerResult
from scryptlib.abi import ABICoder
from scryptlib.types import BASIC_SCRYPT_TYPES, Struct
from scryptlib.serializer import serialize_state


class ContractBase:

    def set_data_part(self, state):
        if isinstance(state, bytes):
            self._data_part = state
        elif isinstance(state, str):
            self._data_part = bytes.fromhex(state)
        elif isinstance(state, dict):
            self._data_part = serialize_state(state)
        else:
            raise NotImplementedError('Invalid object type for contract data part "{}".'.format(state.__class__))

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

    @property
    def data_part(self):
        if self._data_part:
            return Script(self._data_part)
        return None

    @staticmethod
    def find_src_info():
        pass

    @staticmethod
    def find_last_f_exec():
        pass


def build_contract_class(desc):
    if isinstance(desc, CompilerResult):
        desc = desc.to_desc()

    def constructor(self, *args, **kwargs):
        self.calls = dict()
        self._data_part = None
        self.inline_asm_vars = kwargs.get('asm_vars')

        self.scripted_constructor = self.abi_coder.encode_constructor_call(self, self.hex, *args)

    @classmethod
    def from_asm(cls, asm):
        contract_obj = cls()
        contract_obj.scripted_constructor = cls.abi_coder.encode_constructor_call_from_asm(contract_obj, asm)
        return contract_obj

    @classmethod
    def from_hex(cls, val):
        return cls.from_asm(Script.from_hex(val).to_asm())

    contract_class_attribs = dict()
    contract_class_attribs['__init__'] = constructor
    contract_class_attribs['contract_name'] = desc['contract']
    contract_class_attribs['abi'] = desc['abi']
    contract_class_attribs['asm'] = desc['asm']
    contract_class_attribs['hex'] = desc['hex']
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

        def func_call_handler(self, entity_name, *args):
            call = contract_class_attribs['abi_coder'].encode_pub_function_call(self, entity_name, *args)
            self.calls[entity_name] = call
            return call

        contract_class_attribs[entity_name] = partialmethod(func_call_handler, entity_name)

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
        struct_classes[name] = type(name, (Struct,), type_class_attribs)
    return struct_classes


def build_type_classes(desc):
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
            if elem_type_name in BASIC_SCRYPT_TYPES:
                alias_classes[alias_name] = list()
            elif utils.is_struct_type(elem_type_name):
                struct_name = utils.get_struct_name_by_type(elem_type_name)
                alias_classes[alias_name] = list()
        else:
            if final_type in BASIC_SCRYPT_TYPES:
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
                alias_classes[alias_name] = type(alias_name, (BASIC_SCRYPT_TYPES[final_type],), alias_class_atribs)
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
        if alias in BASIC_SCRYPT_TYPES:
            return '{}{}'.format(alias, array_type)
        if alias in resolved_types:
            return '{}{}'.format(resolved_types[alias], array_type)
        return 'struct {} {{}}{}'.format(alias, array_type)

    return resolver_func

