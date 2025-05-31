import unittest

# from hashlib import sha256

from main import *


class TestBlockchainFunctions(unittest.TestCase):
    def test_serialize_uint64(self):
        self.assertEqual(serialize_uint64(0), b"\x00" * 8)
        self.assertEqual(serialize_uint64(1), b"\x01" + b"\x00" * 7)
        self.assertEqual(serialize_uint64(18446744073709551615), b"\xff" * 8)
        self.assertEqual(
            serialize_uint64(1234567890), b"\xd2\x02\x96\x49\x00\x00\x00\x00"
        )

    def test_serialize_uint256(self):
        self.assertEqual(serialize_uint256(0), b"\x00" * 32)
        self.assertEqual(serialize_uint256(1), b"\x01" + b"\x00" * 31)
        self.assertEqual(serialize_uint256(2**256 - 1), b"\xff" * 32)
        self.assertEqual(
            serialize_uint256(12345678901234567890),
            b"\xd2\x0a\x1f\xeb\x8c\xa9\x54\xab" + b"\x00" * 24,
        )

    def test_serialize_bool(self):
        self.assertEqual(serialize_bool(True), b"\x01")
        self.assertEqual(serialize_bool(False), b"\x00")

    def test_serialize_bytes(self):
        self.assertEqual(serialize_bytes(b"\x01\x02\x03\x04", 4), b"\x01\x02\x03\x04")
        with self.assertRaises(AssertionError):
            serialize_bytes(b"\x01\x02\x03", 4)

    def test_camel_to_snake(self):
        self.assertEqual(camel_to_snake("camel"), "camel")
        self.assertEqual(camel_to_snake("camelCase"), "camel_case")
        self.assertEqual(camel_to_snake("thisIsCamelCase"), "this_is_camel_case")
        self.assertEqual(camel_to_snake("snake_case"), "snake_case")

    def test_normalize_hex(self):
        self.assertEqual(normalize_hex("0x1234"), "0x1234")
        self.assertEqual(normalize_hex("1234"), "1234")  # Adjust if prefix added
        self.assertEqual(normalize_hex("0x123"), "0x0123")
        with self.assertRaises(ValueError):
            normalize_hex("0x12G4")

    def test_merkle_root_basic(self):
        self.assertEqual(merkle_root_basic(b"\x01" * 32, "bytes32"), b"\x01" * 32)
        padded_uint = b"\x64\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 24
        self.assertEqual(merkle_root_basic(100, "uint64"), padded_uint)
        # print(f"sha3: {sha256(padded_uint).digest().hex()}, hashlib: {hashlib.sha256(padded_uint).digest().hex()}")
        padded_bool = b"\x01" + b"\x00" * 31
        self.assertEqual(merkle_root_basic(True, "Boolean"), padded_bool)

    def test_merkle_root_list(self):
        self.assertEqual(merkle_root_list([]), b"\x00" * 32)
        self.assertEqual(merkle_root_list([b"\x01" * 32]), b"\x01" * 32)
        two_elements = sha256(b"\x01" * 32 + b"\x02" * 32).digest()
        self.assertEqual(merkle_root_list([b"\x01" * 32, b"\x02" * 32]), two_elements)

    def test_merkle_root_ssz_list(self):
        # Single uint64
        elements = [123]
        elements_roots = [merkle_root_basic(123, "uint64")]
        chunks_root = merkle_root_list(elements_roots)
        length_packed = len(elements).to_bytes(32, "little")
        expected = sha256(chunks_root + length_packed).digest()
        self.assertEqual(
            merkle_root_ssz_list(elements, "uint64", MAX_VALIDATORS), expected
        )
        # Empty list
        length_packed = (0).to_bytes(32, "little")
        expected = sha256(b"\x00" * 32 + length_packed).digest()
        self.assertEqual(merkle_root_ssz_list([], "uint64", MAX_VALIDATORS), expected)

    def test_merkle_root_vector(self):
        # Vector of bytes32 with limit 8
        elements = [b"\x01" * 32, b"\x02" * 32]
        expected = merkle_root_list(elements + [b"\x00" * 32] * (8 - len(elements)))
        self.assertEqual(merkle_root_vector(elements, "bytes32", 8), expected)

    def test_merkle_root_container_fork(self):
        fork = Fork(
            previous_version=b"\x01\x02\x03\x04",
            current_version=b"\x05\x06\x07\x08",
            epoch=123,
        )
        # Compute individual field roots
        roots = [
            b"\x01\x02\x03\x04" + b"\x00" * 28,  # bytes4
            b"\x05\x06\x07\x08" + b"\x00" * 28,  # bytes4
            serialize_uint64(123) + b"\x00" * 24,  # uint64
        ]
        expected = merkle_root_list(roots)
        self.assertEqual(fork.merkle_root(), expected)

    def test_json_to_class_simple(self):
        data = {
            "previousVersion": "0x01020304",
            "currentVersion": "0x05060708",
            "epoch": "123",
        }
        fork = json_to_class(data, Fork)
        self.assertEqual(fork.previous_version, b"\x01\x02\x03\x04")
        self.assertEqual(fork.current_version, b"\x05\x06\x07\x08")
        self.assertEqual(fork.epoch, 123)

    def test_merkle_root_ssz_list_validators(self):
        validators = [
            Validator(
                pubkey=b"\x01" * 48,
                withdrawal_credentials=b"\x02" * 32,
                effective_balance=32000000,
                slashed=False,
                activation_eligibility_epoch=0,
                activation_epoch=0,
                exit_epoch=0,
                withdrawable_epoch=0,
            )
        ]
        elements_roots = [v.merkle_root() for v in validators]
        chunks_root = merkle_root_list(elements_roots)
        length_packed = (1).to_bytes(32, "little")
        expected = sha256(chunks_root + length_packed).digest()
        self.assertEqual(
            merkle_root_ssz_list(validators, "Validator", MAX_VALIDATORS), expected
        )

    def test_merkle_root_vector_block_roots(self):
        roots = [b"\x01" * 32, b"\x02" * 32]
        padded = roots + [b"\x00" * 32] * (SLOTS_PER_HISTORICAL_ROOT - 2)
        expected = merkle_root_list(padded)
        self.assertEqual(
            merkle_root_vector(roots, "bytes32", SLOTS_PER_HISTORICAL_ROOT), expected
        )

    def test_json_to_class_beacon_state(self):
        data = {
            "genesisValidatorsRoot": "0x" + "01" * 32,
            "slot": "123",
            "fork": {
                "previousVersion": "0x00000000",
                "currentVersion": "0x00000000",
                "epoch": "0",
            },
            "latestBlockHeader": {
                "slot": "0",
                "proposerIndex": "0",
                "parentRoot": "0x" + "00" * 32,
                "stateRoot": "0x" + "00" * 32,
                "bodyRoot": "0x" + "00" * 32,
            },
            "blockRoots": ["0x" + "02" * 32] * 8,
            "stateRoots": ["0x" + "03" * 32] * 8,
            "eth1Data": {
                "depositRoot": "0x" + "00" * 32,
                "depositCount": "0",
                "blockHash": "0x" + "00" * 32,
            },
            "eth1DepositIndex": "0",
            "latestExecutionPayloadHeader": {
                "parentHash": "0x" + "00" * 32,
                "feeRecipient": "0x" + "00" * 20,
                "stateRoot": "0x" + "00" * 32,
                "receiptsRoot": "0x" + "00" * 32,
                "logsBloom": "0x" + "00" * 256,
                "prevRandao": "0x" + "00" * 32,
                "blockNumber": "0",
                "gasLimit": "0",
                "gasUsed": "0",
                "timestamp": "0",
                "extraData": "0x",
                "baseFeePerGas": "0x" + "00" * 32,
                "blockHash": "0x" + "00" * 32,
                "transactionsRoot": "0x" + "00" * 32,
                "withdrawalsRoot": "0x" + "00" * 32,
                "blobGasUsed": "0",
                "excessBlobGas": "0",
                "base_fee_per_gas": "3884",
            },
            "validators": [
                {
                    "pubkey": "0x" + "04" * 48,
                    "withdrawalCredentials": "0x" + "00" * 32,
                    "effectiveBalance": "32000000",
                    "slashed": False,
                    "activationEligibilityEpoch": "0",
                    "activationEpoch": "0",
                    "exitEpoch": "0",
                    "withdrawableEpoch": "0",
                }
            ],
            "balances": ["32000000"],
            "randaoMixes": ["0x" + "05" * 32] * 8,
            "nextWithdrawalIndex": "0",
            "nextWithdrawalValidatorIndex": "0",
            "slashings": ["0"],
            "totalSlashing": "0",
        }
        state = json_to_class(data, BeaconState)
        self.assertEqual(state.slot, 123)
        self.assertEqual(state.genesis_validators_root, b"\x01" * 32)
        self.assertEqual(len(state.validators), 1)
        self.assertEqual(state.validators[0].pubkey, b"\x04" * 48)

    def test_merkleize_header(self):
        data = {
            "slot": "5703797",
            "proposer_index": "51",
            "parent_root": "0x1913775a098a6b8fcaf01b087bc81b49cae260efc590480672e0058d41267aa7",
            "state_root": "0xe9cf5760a7e029ca578c53b1ceb3dba31a45e881edbb754a80336fef6e917aa9",
            "body_root": "0xaf2ca5708703fbce19cab72b4b35d37bbf132c79e16881cc0577fc6da56934bb",
        }
        header = json_to_class(data, BeaconBlockHeader)
        # print(header.slot, header.proposer_index, header.parent_root.hex(), header.state_root.hex(), header.body_root.hex())
        # Compute expected Merkle root manually
        leaves = [
            serialize_uint64(5703797) + b"\x00" * 24,
            serialize_uint64(51) + b"\x00" * 24,
            bytes.fromhex(
                "1913775a098a6b8fcaf01b087bc81b49cae260efc590480672e0058d41267aa7"
            ),
            bytes.fromhex(
                "e9cf5760a7e029ca578c53b1ceb3dba31a45e881edbb754a80336fef6e917aa9"
            ),
            bytes.fromhex(
                "af2ca5708703fbce19cab72b4b35d37bbf132c79e16881cc0577fc6da56934bb"
            ),
            b"\x00" * 32,
            b"\x00" * 32,
            b"\x00" * 32,
        ]
        tree = build_merkle_tree(leaves)
        # for branch in tree:
        #     for leaf in branch:
        #         print(f"leaf: {leaf.hex()}")
        expected_root = tree[-1][0]
        self.assertEqual(header.merkle_root(), expected_root)
        self.assertEqual(
            header.merkle_root(),
            bytes.fromhex(
                "ede734ed54e9cff6ef9700404491c77187fd958c29150f9548bf5abc86d50dee"  # parent hash of next slot
            ),
        )

    def test_generate_merkle_witness(self):
        proof, state_root = generate_merkle_witness("test/data/state.json", 39)
        self.assertIsInstance(state_root, bytes)
        self.assertEqual(len(state_root), 32)
        self.assertEqual(
            state_root,
            bytes.fromhex(
                "e9cf5760a7e029ca578c53b1ceb3dba31a45e881edbb754a80336fef6e917aa9"
            ),
        )
        self.assertIsInstance(proof, list)


if __name__ == "__main__":
    unittest.main()
