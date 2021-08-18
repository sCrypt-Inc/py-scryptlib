import bitcoinx
from bitcoinx import Script, base58_decode_check

import scryptlib.utils


# TODO: Throw out asm properties?


class ScryptType:

    type_str = None

    def __init__(self, value):
        self.value = value
        self._type_resolver = None

    @property
    def asm(self):
        return None
    
    @property
    def hex(self):
        return None

    @property
    def json(self):
        return self.asm

    @property
    def final_type(self):
        if self._type_resolver:
            return self._type_resolver(self.type_str)
        return self.type_str


class Int(ScryptType):

    type_str = 'int'

    def __init__(self, value):
        assert isinstance(value, int)
        super().__init__(value)

    @property
    def asm(self):
        if self.value == -1:
            return 'OP_1NEGATE'
        if self.value >= 0 and self.value <= 16:
            return 'OP_{}'.format(self.value)
        return bitcoinx.push_int(self.value)[1:].hex()

    @property
    def hex(self):
        return bitcoinx.push_int(self.value).hex()



class Bool(ScryptType):

    type_str = 'bool'

    def __init__(self, value):
        assert isinstance(value, bool)
        super().__init__(value)

    @property
    def asm(self):
        if self.value:
            return 'OP_TRUE'
        return 'OP_FALSE'

    @property
    def hex(self):
        return Script.from_asm(self.asm).to_hex()


class Bytes(ScryptType):

    type_str = 'bytes'
    
    def __init__(self, value):
        if isinstance(value, str):
            value = bytes.fromhex(value)
        assert isinstance(value, bytes)
        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value).to_hex()


class PrivKey(ScryptType):

    type_str = 'PrivKey'

    def __init__(self, value):
        if isinstance(value, bytes):
            value = bitcoinx.PrivateKey(value)
        assert isinstance(value, bitcoinx.PrivateKey)
        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value.to_bytes()).to_hex()


class PubKey(ScryptType):

    type_str = 'PubKey'

    def __init__(self, value):
        if isinstance(value, bytes):
            value = bitcoinx.PublicKey(value)
        assert isinstance(value, bitcoinx.PublicKey)
        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value.to_bytes()).to_hex()


class Sig(ScryptType):

    type_str = 'Sig'

    def __init__(self, value):
        # TODO: Check signature format, preferably using bitcoinX.
        if isinstance(value, str):
            value = bytes.fromhex(value)
        assert isinstance(value, bytes)
        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value).to_hex()



class Ripemd160(ScryptType):

    type_str = 'Ripemd160'

    def __init__(self, value):
        if isinstance(value, str):
            if len(value) == 40:
                value = bytes.fromhex(value)
            else:
                value = base58_decode_check(value)[1:]

        assert isinstance(value, bytes)
        assert len(value) == 20

        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value).to_hex()


class Sha1(ScryptType):

    type_str = 'Sha1'

    def __init__(self, value):
        if isinstance(value, str):
            assert len(value) == 40
            value = bytes.fromhex(value)

        assert isinstance(value, bytes)
        assert len(value) == 20
        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value).to_hex()



class Sha256(ScryptType):

    type_str = 'Sha256'

    def __init__(self, value):
        if isinstance(value, str):
            assert len(value) == 64
            value = bytes.fromhex(value)

        assert isinstance(value, bytes)
        assert len(value) == 32
        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value).to_hex()



class SigHashType(ScryptType):

    type_str = 'SigHashType'

    def __init__(self, value):
        if isinstance(value, int):
            value = bitcoinx.SigHash(value)
        assert isinstance(value, bitcoinx.SigHash)
        super().__init__(value)

    @property
    def asm(self):
        return self.value.to_string()

    @property
    def hex(self):
        return '{0:x}'.format(self.value)


class SigHashPreimage(ScryptType):

    type_str = 'SigHashPreimage'

    def __init__(self, value):
        assert isinstance(value, bytes)
        super().__init__(value)

    @classmethod
    def from_tx(cls, tx, input_index, utxo_value, script_code, sighash):
        preimage_bytes = scryptlib.scryptlib.utils.get_preimage(tx, input_index, script_code, sighash)
        return cls(preimage_bytes)

    @classmethod
    def from_input_context(cls, context, sighash):
        preimage_bytes = scryptlib.scryptlib.utils.get_preimage_from_input_context(context, sighash)
        return cls(preimage_bytes)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return (Script() << self.value).to_hex()


class OpCodeType(ScryptType):

    type_str = 'OpCodeType'

    def __init__(self, value):
        assert isinstance(value, bytes)
        super().__init__(value)

    @property
    def asm(self):
        return self.hex

    @property
    def hex(self):
        return self.value.hex()


class Struct(ScryptType):

    struct_ast = None

    def __init__(self, value):
        assert isinstance(value, dict)
        super().__init__(value)

    def bind(self):
        '''
        Order members so they match the order in the AST. Also set self.type_str based on the name in the AST.
        (Since Python 3.6 dictionaries maintain insert ordering)
        '''
        scryptlib.utils.check_struct(self.struct_ast, self, self._type_resolver)
        new_val = dict()
        for param in self.struct_ast['params']:
            name = param['name']
            new_val[name] = self.value[name]
        self.value = new_val
        self.type_str = self.struct_ast['name']

    def member_by_key(self, key):
        member = self.value[key]
        if isinstance(member, ScryptType) or isinstance(member, bytes):
            return member
        elif isinstance(member, bool):
            return Bool(member)
        elif isinstance(member, int):
            return Int(member)
        elif isinstance(member, list):
            return member
        #return member
        raise Exception('Unknown struct member type "{}" for member "{}".'.format(member.__class__, key))

    def get_members(self):
        return list(self.value.keys())


    def get_member_ast_final_type(self, key):
        '''
        Get the member type declared by the structure in the AST.
        '''
        param_entity = None
        for p in self.struct_ast['params']:
            if p['name'] == key:
                param_entity = p

        if not param_entity:
            raise Exception('"{}" is not a member of struct {}.'.format(key, self.struct_ast['name']))

        return self._type_resolver(param_entity['type']);

    @property
    def asm(self):
        self.bind()

        res_buff = []
        flat_struct = scryptlib.utils.flatten_struct(self, '')
        for elem in flat_struct:
            res_buff.append(elem['value'].asm)

        return ' '.join(res_buff)

    @property
    def hex(self):
        self.bind()

        res_buff = []
        flat_struct = scryptlib.utils.flatten_struct(self, '')
        for elem in flat_struct:
            res_buff.append(elem['value'].hex)

        #return ''.join(res_buff)
        return Script.from_hex(''.join(res_buff)).to_hex()
        

BASIC_SCRYPT_TYPES = {
        'bool': Bool,
        'int': Int,
        'bytes': Bytes,
        'PubKey': PubKey,
        'Sig': Sig,
        'Ripemd160': Ripemd160,
        'Sha1': Sha1,
        'Sha256': Sha256,
        'SigHashType': SigHashType,
        'SigHashPreimage': SigHashPreimage,
        'OpCodeType': OpCodeType
    }


