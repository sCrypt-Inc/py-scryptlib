import bitcoinx
from bitcoinx import Script


BASIC_TYPES = {
        'bool',
        'int',
        'bytes'
    }


DOMAIN_SUBTYPES = {
        'PubKey',
        'Sig',
        'Ripemd160',
        'Sha1',
        'Sha256',
        'SigHashType',
        'SigHashPreimage',
        'OpCodeType'
    }


class ScryptType:

    type_str = None

    def __init__(self, value):
        self.value = value

    @property
    def asm(self):
        return None

    @property
    def json(self):
        return self.asm


class Int(ScryptType):

    type_str = 'int'

    def __init__(self, value):
        assert isinstance(value, int)
        super().__init__(value)

    @property
    def asm(self):
        if self.value == 0:
            return 'OP_1NEGATE'
        if self.value > 0 and self.value <= 16:
            return 'OP_{}'.format(self.value)
        return bitcoinx.push_int(self.value)[1:].hex()


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


class Bytes(ScryptType):

    type_str = 'bytes'
    
    def __init__(self, value):
        assert isinstance(value, bytes)
        super().__init__(value)

    @property
    def asm(self):
        return self.value.hex()


class PrivKey(ScryptType):

    type_str = 'PrivKey'

    def __init__(self, value):
        if isinstance(value, bytes):
            value = bitcoinx.PrivateKey(value)
        assert isinstance(value, bitcoinx.PrivateKey)
        super().__init__(value)

    @property
    def asm(self):
        return self.value.to_hex()


class PubKey(ScryptType):

    type_str = 'PubKey'

    def __init__(self, value):
        if isinstance(value, bytes):
            value = bitcoinx.PublicKey(value)
        assert isinstance(value, bitcoinx.PublicKey)
        super().__init__(value)

    @property
    def asm(self):
        return self.value.to_hex()


class Sig(ScryptType):

    type_str = 'Sig'

    def __init__(self, value):
        # TODO: Check signature format, preferably using bitcoinX.
        assert isinstance(value, bytes)
        super().__init__(value)

    @property
    def asm(self):
        return self.value.hex()


class Ripemd160(ScryptType):

    type_str = 'Ripemd160'

    def __init__(self, value):
        assert isinstance(value, bytes)
        assert len(value) == 20

        # TODO: make hash string also passable to constructor
        super().__init__(value)

    @property
    def asm(self):
        return self.value.hex()


class Sha1(ScryptType):

    type_str = 'Sha1'

    def __init__(self, value):
        assert isinstance(value, bytes)
        assert len(value) == 20
        super().__init__(value)

    @property
    def asm(self):
        return self.value.hex()


class Sha256(ScryptType):

    type_str = 'Sha256'

    def __init__(self, value):
        assert isinstance(value, bytes)
        assert len(value) == 32
        super().__init__(value)

    @property
    def asm(self):
        return self.value.hex()


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


class SigHashPreimage(ScryptType):

    type_str = 'SigHashPreimage'

    def __init__(self, value):
        assert isinstance(value, bytes)
        assert len(value) == 32
        super().__init__(value)

    @classmethod
    def from_tx(cls, tx, input_index, value, script_code, sighash):
        # TODO: test
        if isinstance(sighash, SigHashType):
            # We need to pass the bitcoinX sighash vlaue primitive as a parameter.
            sighash = sighash.value
        value = value.signature_hash(input_index, value, script_code, sighash)
        return cls(value)

    @property
    def asm(self):
        return self.value.hex()


class OpCodeType(ScryptType):

    type_str = 'OpCodeType'

    def __init__(self, value):
        assert isinstance(value, bytes)
        super().__init__(value)

    @property
    def asm(self):
        return self.value.hex()


# TODO
class Struct(ScryptType):

    def __init__(self, value):
        assert isinstance(value, dict)
        super().__init__(value)

