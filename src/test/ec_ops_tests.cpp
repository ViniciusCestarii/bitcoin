// Copyright (c) XXXX-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/tx_invalid.json.h>
#include <test/data/tx_valid.json.h>
#include <test/util/setup_common.h>

#include <validation.h>

#include <boost/test/unit_test.hpp>

typedef std::vector<unsigned char> valtype;

script_verify_flags flags = SCRIPT_VERIFY_TAPROOT;

BOOST_FIXTURE_TEST_SUITE(ec_ops_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_ec_point_add_opcode)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT;
    ScriptError err;

    std::vector<valtype> stack;

    valtype point1 = ParseHex("03d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612");
    valtype point2 = ParseHex("038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0ac");

    stack.push_back(point1);
    stack.push_back(point2);

    CScript script;
    script << OP_EC_POINT_ADD;

    BOOST_CHECK(EvalScript(stack, script, flags, BaseSignatureChecker(), SigVersion::TAPSCRIPT, execdata, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    BOOST_CHECK_EQUAL(stack.size(), 1);
    BOOST_CHECK_EQUAL(stack[0].size(), 33);
    valtype expected_sum = ParseHex("0284df99cc50d1ec93e9bc32c666325a389dd69a7f42777b8f1670ad66d2e622c9");
    BOOST_CHECK_EQUAL(HexStr(stack[0]), HexStr(expected_sum));
    BOOST_CHECK_EQUAL(execdata.m_validation_weight_left, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT - VALIDATION_WEIGHT_EC_POINT_ADD);
}

BOOST_AUTO_TEST_CASE(test_ec_point_add_opcode_infinity)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT;
    ScriptError err;

    std::vector<valtype> stack;

    valtype point1 = ParseHex("03d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612");
    valtype point2 = ParseHex("02d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612");

    stack.push_back(point1);
    stack.push_back(point2);

    CScript script;
    script << OP_EC_POINT_ADD;

    BOOST_CHECK(EvalScript(stack, script, flags, BaseSignatureChecker(), SigVersion::TAPSCRIPT, execdata, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    BOOST_CHECK_EQUAL(stack.size(), 1);
    BOOST_CHECK_EQUAL(stack[0].size(), 0);
}

BOOST_AUTO_TEST_CASE(op_ec_point_add_invalid_points)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT;
    ScriptError err;

    std::vector<valtype> stack;

    valtype point1 = ParseHex("deadbeef");
    valtype point2 = ParseHex("deadbeef");

    stack.push_back(point1);
    stack.push_back(point2);

    CScript script;
    script << OP_EC_POINT_ADD;

    BOOST_CHECK(!EvalScript(stack, script, flags, BaseSignatureChecker(), SigVersion::TAPSCRIPT, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EC_POINT_ADD);
}

BOOST_AUTO_TEST_CASE(test_ec_point_add_opcode_65_bytes_point)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT;
    ScriptError err;

    std::vector<valtype> stack;

    valtype point1 = ParseHex("0437a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1bab96ced90a1b8f9b43a18fc900ff55af2be0e94b90a434fca5b9e226b835024cd");
    valtype point2 = ParseHex("02d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612");

    stack.push_back(point1);
    stack.push_back(point2);

    CScript script;
    script << OP_EC_POINT_ADD;

    BOOST_CHECK(!EvalScript(stack, script, flags, BaseSignatureChecker(), SigVersion::TAPSCRIPT, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EC_POINT_ADD);
}

BOOST_AUTO_TEST_CASE(test_ec_point_add_opcode_validation_weight_exceeded)
{
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT - (SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT - VALIDATION_WEIGHT_EC_POINT_ADD + 1);
    ScriptError err;

    std::vector<valtype> stack;

    valtype point1 = ParseHex("03d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612");
    valtype point2 = ParseHex("038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0ac");

    stack.push_back(point1);
    stack.push_back(point2);

    CScript script;
    script << OP_EC_POINT_ADD;

    BOOST_CHECK(!EvalScript(stack, script, flags, BaseSignatureChecker(), SigVersion::TAPSCRIPT, execdata, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_SUITE_END()