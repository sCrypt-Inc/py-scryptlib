import scryptlib.utils

import bitcoinx
from bitcoinx import pack_byte, le_bytes_to_int
from bitcoinx.script import *


# TODO: What to do about negative integers?


STATE_LEN_2BYTES = 2
STATE_LEN_4BYTES = 4


def encode_state_len(len_int, size_bytes):
    len_bytes = pack_byte(len_int)
    size_diff = size_bytes - len(len_bytes)

    if size_diff < 0:
        raise Exception('Size of encoding too small for passed state length. Needs at least {} additional bytes.'.fromat(size_diff * -1))

    return len_bytes[::-1] + b'\x00' * size_diff


def serialize_bool(val):
    if val:
       return pack_byte(OP_TRUE)
    return pack_byte(OP_FALSE)


def serialize_int(val):
    return scryptlib.utils.get_push_int(val)


def serialize_string(val):
    if val == '':
        res = pack_byte(0)
    res = str.encode(val, 'utf-8')
    return scryptlib.utils.get_push_item(res)


def serialize_hex(val):
    res = bytes.fromhex(val)
    return scryptlib.utils.get_push_item(res)


def serialize_bytes(val):
    return scryptlib.utils.get_push_item(val)


def serialize_with_schema(state, key, schema):
    dtype = schema[key].__name__
    if dtype == 'bool':
        return serialize_bool(state[key])
    elif dtype == 'int':
        return serialize_int(state[key])
    elif dtype == 'str':
        return serialize_string(state[key])
    elif dtype == 'bytes':
        return serialize_bytes(state[key])
    raise Exception('Invalid data type "{}".'.format(dtype))


def serialize(val):
    if isinstance(val, bool):
        return serialize_bool(val)
    elif isinstance(val, int):
        return serialize_int(val)
    elif isinstance(val, str):
        return serialize_string(val)
    elif isinstance(val, bytes):
        return serialize_bytes(val)
    raise Exception('Invalid data type "{}".'.format(val.__class__))


def serialize_state(state, length_label_size=STATE_LEN_2BYTES, schema=None):
    buff = []

    for key, val in state.items():
        if schema:
            buff.append(serialize_with_schema(state, key, schema))
        else:
            buff.append(serialize(val))

    state_data = b''.join(buff)
    state_len = encode_state_len(len(state_data), length_label_size)
    return state_data + scryptlib.utils.get_push_item(state_len)


def deserialize_state(data, schema, length_label_size=STATE_LEN_2BYTES):
    res = dict()

    if isinstance(data, Script):
        # If a Script object is passed, try to find OP_RETURN and deserialize only the part after it.
        # If no OP_RETURN is found, try to deserialize the whole script.
        data_items = []
        found = False
        for op, item in data.ops_and_items():
            if op == OP_RETURN:
                found = True
                continue
            if found:
                data_items.append((op, item))

        if len(data_items) == 0:
            data_items = data.ops_and_items()
        else:
            data_items = iter(data_items)
    else:
        data_items = Script(data).ops_and_items()


    # Since Python 3.6 dictionaries maintain order.
    for key, val in schema.items():
        op, item = next(data_items)
        if isinstance(val, bool):
            if item == b'':
                res[key] = False
                continue
            elif item == b'\x01':
                res[key] = True
                continue
            raise Exception('Invalid item data "{}" for boolean type.'.format(item.hex()))
        elif isinstance(val, int):
            res[key] = le_bytes_to_int(item)
        elif isinstance(val, str):
            res[key] = str.decode(item, 'utf-8') 
        elif isinstance(val, bytes):
            res[key] = val
        else:
            raise Exception('Invalid value type "{}" for key "{}" in schema.'.format(
                                val.__class__, key))

    return res


