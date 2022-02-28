import scryptlib.utils
import scryptlib.contract


contract = './test/res/demo.scrypt'

compiler_result_debug = scryptlib.utils.compile_contract(contract, debug=True)
desc_debug = compiler_result_debug.to_desc()

DemoDebug = scryptlib.contract.build_contract_class(desc_debug)
demo_debug = DemoDebug(7, 4)

compiler_result_optimized = scryptlib.utils.compile_contract(contract, debug=False)
desc_optimized = compiler_result_optimized.to_desc()

DemoOptimized = scryptlib.contract.build_contract_class(desc_optimized)
demo_optimized = DemoOptimized(7, 4)


def test_smaller_script_size():
    assert len(demo_debug.locking_script) > len(demo_optimized.locking_script)


def test_verify_optimized():
    verify_result = demo_optimized.add(7 + 4).verify()
    assert verify_result == True

    verify_result = demo_optimized.add(7 - 4).verify()
    assert verify_result == False

