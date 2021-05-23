from scryptlib.compiler_wrapper import CompilerResult
from scryptlib.abi import ABICoder


class ContractBase:
    scripted_constructor = None

    def locking_script(self):
        ls_asm = self.scripted_constructor.to_asm()
        if isinstance(self._data_part, str):
            dp = self._data_part.strip()
            if dp != '':
                ls_asm.append(' OP_RETURN {}'.format(dp))
            else:
                ls_asm.append(' OP_RETURN')
        return # TODO: bitcoinX asm


def build_contract_class(desc):
    if isinstance(desc, CompilerResult):
        desc = desc.to_desc()

    # TODO: construct contract class
    #            - constructor(c_params) -> self.scripted_constructor = abi.encodeConstructorCall(self, self.asm, c_params)
    #            - *classmethod* from_asm(asm) -> obj = cls(); abi.encodeConstructorCallFromASM(obj, asm)
    #            - *classmethod* from_hex(hex) -> cls.from_asm(bitcoinX(hex))
    #            - *property* asm_vars -> ContractBase.get_asm_vars(self.asm, self.scripted_constructor.to_asm())
    #            - *property* asm_args -> None
    #            - *static var* contract_name = desc.contract_name
    #            - *static var* abi = desc.abi
    #            - *static var* asm = desc.asm.map(...)
    #            - *static var* abi_coder = abi.AbiCoder(desc.abi, desc.alias)
    #            - *static var* opcodes = desc.asm
    #            - *static var* file = desc.file
    #            - *static var* structs = desc.structs
    #            DO: for earch abi entity:
    #                 *static dict* prototypes[entity.name] = func(
    #                                       call = abi.encodePubFunctionCall(self, entity.name, args)
    #                                       self.calls.set(entity.name, call)
    #                                       return call
    #                                       )


    def constructor(self, *args):
        super().__init__()

        contract_empty_constructor = False
        for obj in self.abi:
            if obj.type == 'constructor' and len(obj.params) == 0:
                contract_empty_constructor = True
                break

        if len(args) > 0 or contract_empty_constructor:
            self.scripted_constructor = self.abi_coder.encode_constructor_call(self, self.asm, *args)

    @classmethod
    def from_asm(cls, asm):
        contract_obj = cls()
        contract_obj.scripted_constructor = cls.abi_coder.encode_constructor_call_from_asm(contract_obj, asm)
        return contract_obj

    @classmethod
    def from_hex(cls, hex_bytes):
        return cls.from_asm(#TODO bitcoinX)

    @property
    def asm_vars(self):
        return self.get_asm_vars(self.asm, self.scripted_constructor.to_asm())

    contract_class_attribs = dict()
    contract_class_attribs['contract_name'] = desc['contract']
    contract_class_attribs['abi'] = desc['abi']
    contract_class_attribs['asm'] = desc['asm']
    contract_class_attribs['abi_coder'] = ABICoder(desc['abi'], desc.get('alias', []))
    contract_class_attribs['file'] = desc['file']
    contract_class_attribs['structs'] = desc['structs']
    contract_class_attribs['prototype'] = dict()
    for entity in desc['abi']:
        # TODO: Is it possible to avoid these conflicts?
        entity_name = entity['name']
        if entity_name in dir(ContractBase) or entity_name in contract_class_attribs:
            raise Exception('Method name "{}" conflicts with ContractClass member name.'.format(entity_name))

        def func_call_handler(*args):
            call = contract_class_attribs['abi_coder'].encode_pub_function_call(self, entity_name, *args)
            self.calls[entity_name] = call
            return call

        contract_class_attribs[entity_name] = func_call_handler

    return type('Contract', (ContractBase), contract_class_attribs)


