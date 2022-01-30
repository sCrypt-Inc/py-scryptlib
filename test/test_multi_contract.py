import pytest

import scryptlib.utils
import scryptlib.contract


contract = '''
contract Demo1 {
    int x;
    int y;

    constructor(int x, int y) {
        this.x = x;
        this.y = y;
    }

    public function sub(int z) {
        require(z == this.x - this.y);
    }
}

contract Demo2 {
    int x;

    public function test(int y) {
        require(this.x == y);

        Demo1 demo1 = new Demo1(this.x, y);
        require(demo1.sub(this.x - y));
    }
}
'''

compiler_result = scryptlib.utils.compile_contract(contract, from_string=True)
desc = compiler_result.to_desc()

# We should always get the lastly defined contract here.
Demo2 = scryptlib.contract.build_contract_class(desc)
demo = Demo2(7)

def test_verify_correct():
    verify_result = demo.test(7).verify()
    assert verify_result == True

