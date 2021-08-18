import pytest
import math

import scryptlib.utils
import scryptlib.contract
from scryptlib.types import Int

import bitcoinx
from bitcoinx import PrivateKey, pack_byte


# Function to find modulo inverse of b. It returns
# -1 when inverse doesn't exist.
# mod_inverse works for values m, that are prime
def mod_inverse(b, m):
    g = math.gcd(b, m)
    if (g != 1):
        # print("Inverse doesn't exist")
        return -1
    else:
        # If b and m are relatively prime,
        # then modulo inverse is b^(m-2) mode m
        return pow(b, m - 2, m)
 
 
# Function to compute a/b under modulo m
def mod_divide(a, b, m):
    a = a % m
    inv = mod_inverse(b, m)
    if(inv == -1):
        raise Exception("Division not defined")
    return (inv * a) % m


def get_lambda(P1x, P1y, P2x, P2y, p):
    # lambda - gradient of the line between P1 and P2
    # if P1 == P2:
    #    lambda = ((3 * (P1x**2) + a) / (2 * P1y)) % p
    # else:
    #    lambda = ((P2y - P1y) / (P2x - P1x)) % p
    if P1x == P2x and P1y == P2y:
        a = 0
        lambda_numerator = 3 * (P1x**2) + a
        lambda_denominator = 2 * P1y
        return mod_divide(lambda_numerator, lambda_denominator, p)
    else:
        lambda_numerator = P2y - P1y
        lambda_denominator = P2x - P1x
        return mod_divide(lambda_numerator, lambda_denominator, p)



p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

contract = './test/res/ecAddition.scrypt'

compiler_result = scryptlib.utils.compile_contract(contract)
desc = compiler_result.to_desc()

ECAddition = scryptlib.contract.build_contract_class(desc)
type_classes = scryptlib.contract.build_type_classes(desc)

Point = type_classes['Point']


def test_verify_correct():
    k1 = PrivateKey.from_random()
    k2 = PrivateKey.from_random()

    P1x, P1y = k1.public_key.to_point()
    P2x, P2y = k2.public_key.to_point()

    ec_addition = ECAddition(
            Point({
                'x': Int(P1x),
                'y': Int(P1y)
                }),
            Point({
                'x': Int(P2x),
                'y': Int(P2y)
                })
            )

    lambda_val = get_lambda(P1x, P1y, P2x, P2y, p)

    Px = (lambda_val**2 - P1x - P2x) % p
    Py = (lambda_val * (P1x - Px) - P1y) % p

    verify_result = ec_addition.testSum(
            Int(lambda_val),
            Point({
                'x': Int(Px),
                'y': Int(Py)
                })
            ).verify()
    assert verify_result == True


def test_verify_correct_2():
    # P1 == P2
    k1 = PrivateKey.from_random()

    P1x, P1y = k1.public_key.to_point()
    P2x, P2y = k1.public_key.to_point()

    ec_addition = ECAddition(
            Point({
                'x': Int(P1x),
                'y': Int(P1y)
                }),
            Point({
                'x': Int(P2x),
                'y': Int(P2y)
                })
            )

    lambda_val = get_lambda(P1x, P1y, P2x, P2y, p)

    Px = (lambda_val**2 - P1x - P2x) % p
    Py = (lambda_val * (P1x - Px) - P1y) % p

    verify_result = ec_addition.testSum(
            Int(lambda_val),
            Point({
                'x': Int(Px),
                'y': Int(Py)
                })
            ).verify()
    assert verify_result == True


def test_verify_correct_3():
    # P2 == ZERO
    k1 = PrivateKey.from_random()

    P1x, P1y = k1.public_key.to_point()
    P2x, P2y = (0, 0)

    ec_addition = ECAddition(
            Point({
                'x': Int(P1x),
                'y': Int(P1y)
                }),
            Point({
                'x': Int(P2x),
                'y': Int(P2y)
                })
            )

    lambda_val = 0x21e8     # The value of lambda is irrelevant in this cas and can be anything

    verify_result = ec_addition.testSum(
            Int(lambda_val),
            Point({
                'x': Int(P1x),
                'y': Int(P1y)
                })
            ).verify()
    assert verify_result == True


def test_verify_wrong_sum():
    k1 = PrivateKey.from_random()
    k2 = PrivateKey.from_random()

    P1x, P1y = k1.public_key.to_point()
    P2x, P2y = k2.public_key.to_point()

    ec_addition = ECAddition(
            Point({
                'x': Int(P1x),
                'y': Int(P1y)
                }),
            Point({
                'x': Int(P2x),
                'y': Int(P2y)
                })
            )

    lambda_val = get_lambda(P1x, P1y, P2x, P2y, p)

    Px = (lambda_val**2 - P1x - P2x) % p
    Py = (lambda_val * (P1x - Px) - P1y) % p

    verify_result = ec_addition.testSum(
            Int(lambda_val),
            Point({
                'x': Int(Px + 1),
                'y': Int(Py)
                })
            ).verify()
    assert verify_result == False


def test_verify_wrong_lambda():
    k1 = PrivateKey.from_random()
    k2 = PrivateKey.from_random()

    P1x, P1y = k1.public_key.to_point()
    P2x, P2y = k2.public_key.to_point()

    ec_addition = ECAddition(
            Point({
                'x': Int(P1x),
                'y': Int(P1y)
                }),
            Point({
                'x': Int(P2x),
                'y': Int(P2y)
                })
            )

    lambda_val = get_lambda(P1x, P1y, P2x, P2y, p)

    Px = (lambda_val**2 - P1x - P2x) % p
    Py = (lambda_val * (P1x - Px) - P1y) % p

    verify_result = ec_addition.testSum(
            Int(lambda_val + 1),
            Point({
                'x': Int(Px),
                'y': Int(Py)
                })
            ).verify()
    assert verify_result == False
