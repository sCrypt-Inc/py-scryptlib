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

    def __init__(self, value):
        self.__check_value(value)
        self.value = value

    @property
    def asm(self):
        return ''

    @property
    def json(self):
        return self.asm

    @staticmethod
    def __check_value(value):
        return True


class Int(ScryptType):

    def __init__(self, value):
        super().__init__(value)

    @property
    def asm(self):
        if self.value == 0:
            return 'OP_1NEGATE'
        if self.value > 0 and self.value <= 16:
            return 'OP_{}'.format(self.value)
        return Script.asm_word_to_bytes(str(self.value))[1:].hex()

    @staticmethod
    def __check_value(value):
        assert isinstance(value, int)


class Bool(ScryptType):

    def __init__(self, value):
        super().__init__(value)

    @property
    def asm(self):
        if self.value:
            return 'OP_TRUE'
        return 'OP_FALSE'

    @staticmethod
    def __check_value(value):
        assert isinstance(value, bool)


class Bytes(ScryptType):

    def __init__(self, value):
        super().__init__(value)

    @property
    def asm(self):
        return self.value.hex()

    @staticmethod
    def __check_value(value):
        assert isinstance(value, bool)

