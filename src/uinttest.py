import unittest
from dataclasses import fields
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

    def test_merkleize_header2(self):
        data = {
            "slot": "5788394",
            "proposer_index": "47",
            "parent_root": "0xd6f0665c550102f6db8d4ac17d6ba1ef5808728d29c6ecb33ce9ae9213fc7cec",
            "state_root": "0x01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8",
            "body_root": "0xfc3eb7bd05e6b6b68946b48183c2e3a628bbdc4b5f8d0fcce2ad38e6cd2e4a22",
        }
        header = json_to_class(data, BeaconBlockHeader)
        # print(header.slot, header.proposer_index, header.parent_root.hex(), header.state_root.hex(), header.body_root.hex())
        # Compute expected Merkle root manually
        leaves = [
            serialize_uint64(5788394) + b"\x00" * 24,
            serialize_uint64(47) + b"\x00" * 24,
            bytes.fromhex(
                "d6f0665c550102f6db8d4ac17d6ba1ef5808728d29c6ecb33ce9ae9213fc7cec"
            ),
            bytes.fromhex(
                "01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8"
            ),
            bytes.fromhex(
                "fc3eb7bd05e6b6b68946b48183c2e3a628bbdc4b5f8d0fcce2ad38e6cd2e4a22"
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
            header.merkle_root().hex(),
            bytes.fromhex(
                "28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74"  # parent hash of next slot
            ).hex(),
        )

    def test_generate_merkle_witness(self):
        proof, state_root = generate_merkle_witness("test/data/state2.json", 39)
        self.assertIsInstance(state_root, bytes)
        self.assertEqual(len(state_root), 32)
        self.assertEqual(
            state_root,
            bytes.fromhex(
                "7aac2bab3ed70e35ba9123b739f6375caed3b51c8c947703087b911d54b0cc9f"
            ),
        )
        self.assertIsInstance(proof, list)

    def test_proposer_index_proof(self):
        # Beacon block header data
        header_data = {
            "slot": "0x5852f2",
            "proposer_index": "0x33",
            "parent_block_root": "0x155f296b0f1125544889bf879fdcef2378af621cce314682da092ecc6adf8ec8",
            "state_root": "0x7aac2bab3ed70e35ba9123b739f6375caed3b51c8c947703087b911d54b0cc9f",
            "body_root": "0xea41d9a12d46e604dd4c8c52da906a1840635955cd105e5a8fbfa685964c593b",
        }
        header = json_to_class(header_data, BeaconBlockHeader)
        header_root = header.merkle_root()
        # Build field roots
        field_roots = [
            merkle_root_basic(header.slot, "uint64"),
            merkle_root_basic(header.proposer_index, "uint64"),
            merkle_root_basic(header.parent_root, "bytes32"),
            merkle_root_basic(header.state_root, "bytes32"),
            merkle_root_basic(header.body_root, "bytes32"),
        ]

        # Pad to next power of two (8 leaves)
        import math

        n = len(field_roots)  # 5
        k = math.ceil(math.log2(max(n, 1)))  # log2(5) ≈ 2.32, ceil = 3
        num_leaves = 1 << k  # 2^3 = 8
        padded_leaves = field_roots + [b"\0" * 32] * (num_leaves - n)

        # Build tree and get proof
        header_tree = build_merkle_tree(padded_leaves)

        index = 1  # Second field in BeaconBlockHeader
        header_proof = get_proof(header_tree, index)

        # Leaf for proposer_index (uint64: 51 = 0x33)
        leaf = merkle_root_basic(51, "uint64")  # 0x3300000000000000 + 24 zero bytes

        # Proposer index proof
        proof = [
            bytes.fromhex(h[2:])
            for h in [
                "0xf252580000000000000000000000000000000000000000000000000000000000",
                "0xaa6897c859983bc20a1a9e4e8e371df04869d77377e20596ee45329b82e02509",
                "0x8dc6933956b28092ca349896d3adbd09a2b829aa2a206792df8580347e8a6405",
            ]
        ]
        for i in range(0, len(proof)):
            # print(f"proof actual: {proof[i].hex()}")
            # print(f"proof generated: {header_proof[i].hex()}")
            self.assertEqual(header_proof[i].hex(), proof[i].hex())
        self.assertTrue(verify_merkle_proof(leaf, proof, index, header_root))

        # proof_list = get_proof(validators_tree, validator_index)

    # some ref tests
    # https://github.com/ethereum/consensus-spec-tests
    def test_eth1_data_merkle(self):
        header = Eth1Data(
            deposit_root=bytes.fromhex(
                "9b5668ffd8b1d0b8f497b9d430341a0e199087d3a4426adc404c10e199d207db"
            ),
            deposit_count=864455600355765796,
            block_hash=bytes.fromhex(
                "04a473fd6629f54f3f2c238bfe77f0965ca85924cefd8772256faffb06103ab8"
            ),
        )
        final_root = header.merkle_root()
        self.assertEqual(
            final_root.hex(),
            "410c5f2ad586471a6b858503a6044ba8d4515168bae6753907315dc84e65a349",
        )

    def test_fork_merkle(self):
        header = Fork(
            previous_version=bytes.fromhex("22085f34"),
            current_version=bytes.fromhex("6759798c"),
            epoch=48711760419766586,
        )
        final_root = header.merkle_root()
        self.assertEqual(
            final_root.hex(),
            "12db905a772366069bed4d2e165f51d7afd78a72f4e485d2b1eb1c0b6142252f",
        )

    def test_execution_payload_header_merkle(self):
        header = ExecutionPayloadHeader(
            parent_hash=bytes.fromhex(
                "dc74572718fd0c3e947ccc4287f2f5d2e9e8fb9520c055ce6548ad5ccb3f9e33"
            ),
            fee_recipient=bytes.fromhex("b6083bad5a4d3134d709539ed3dc09b8be90c6a6"),
            state_root=bytes.fromhex(
                "baf1d72bb2c2189f564bae2cebdccd7d3ba3434687ff2f5f61b5a36c1aa04b55"
            ),
            receipts_root=bytes.fromhex(
                "5db20defa6b67308b95bfae8c9f9d8ccc706cd8ad84396a7b14684b1a3cf7373"
            ),
            logs_bloom=bytes.fromhex(
                "892e55ade5f7bc1b7f001b2355cc82397e53dac69a23d34b17a0f4b4038d68a07481a8fc2ffeca71700ee7cd16f3c13165ad826aa9dddb81e1b0ac53df7fa3759175af49cf432cfe8a27a41bef548533465510366ae8c827eb83374cb85da70e0a61866c56466cc62a13aacd5cc671b5876757c37ffb7425b0c8e94b16f8e4285098b7a237bd48ba3518580d1b91c974d502e3a3acf05350b898c7141ee8adb8698ea7a59e8d48d33e3eed5bb9a46886ee3f95072e9a792101c41686e5c837e0fd13e902c08896670719adb4d918d6ef9cf9ec6f5be597e3d81a7293ee6a72b68aac10402ddeb5f814da4e0e412e98b1ba95a0395766fac26270aaf5c81a3263"
            ),
            prev_randao=bytes.fromhex(
                "a5e764e111faa88ef4a97717d70320040c9238f0d355a35c1e7b820457b99431"
            ),
            block_number=16341509426905322341,
            gas_limit=12493063017558285766,
            gas_used=14609395124503691893,
            timestamp=1544961326346202544,
            extra_data=bytes.fromhex(
                "7d93909becdef90c36cfbcba695fd0e69102b37dfd05afb370672090e7"
            ),
            base_fee_per_gas=61884265331504407787052872047516276847429314869981376707991449424234902978858,  # Will be fixed to bytes
            block_hash=bytes.fromhex(
                "d12c3a50b09aa835c00c7ac3038e23bbb067e932eae13718009cd1c35feaf46f"
            ),
            transactions_root=bytes.fromhex(
                "f59f0643c89235a7261955bebaff5b134a31c3f0251b89b21a8f7e3f998fa351"
            ),
            withdrawals_root=bytes.fromhex(
                "99e2b76ffa8087b096b0c7bfd79bb31a57669127ded9d13aea9e71e724d3cf16"
            ),
            blob_gas_used=7719391158488866226,
            excess_blob_gas=14548901732660767201,
        )
        final_root = header.merkle_root()
        self.assertEqual(
            final_root.hex(),
            "e6b87e3797a1d9a297c1f58b87b9c38911b5ed524f2ccbe61b785204ec0380d9",
        )

    def test_execution_payload_header_merkle2(self):
        header = ExecutionPayloadHeader(
            parent_hash=bytes.fromhex(
                "897e1cce86fe0a1175937648a4816f3303b1fe30dd33f13c894688058366e9c6"
            ),
            fee_recipient=bytes.fromhex("68a04dBAc577D1a9E8442fd368C50D65d304Ab17"),
            state_root=bytes.fromhex(
                "588ee67eac70377d054fa9e0a8fa6108d7e8098a348afb22ac4f289ae0fea1e6"
            ),
            receipts_root=bytes.fromhex(
                "1fdaf3cac88f30202a65cccc3ef21cdcecc8915f198c77fbf21b283515cff708"
            ),
            logs_bloom=bytes.fromhex(
                "0018020040042000800080000200000000000000080000100014013000010000000040000000201000080040100020010100018200006000000000000820042000080000000000080080000801200080000040000200000200110800052000000400000002020040100000001400080000000408000408000200001000081000920440003521000004311400800000000008000080000100000088400000000042000001000a24000280200008000000001100024000000005000000000000240000000202000001029101002000640000002101001020000020042000002000109084080008000001000801024180040008800100004000c220004804020020"
            ),
            prev_randao=bytes.fromhex(
                "01b9a537f2e0a7cf4bb3d298f512f9c478e4f2f9e915b04ddfeef95c4e0b75b8"
            ),
            block_number=5788402,
            gas_limit=36000000,
            gas_used=1861457,
            timestamp=1748773066,
            extra_data=bytes.fromhex(
                "d883010f0b846765746888676f312e32342e32856c696e7578"
            ),
            base_fee_per_gas=8,  # Will be fixed to bytes
            block_hash=bytes.fromhex(
                "76b247f73fc1b65353c7e4e3ed1a3e8652e261decc8afca6756de6733ad1b25a"
            ),
            transactions_root=bytes.fromhex(
                "501de7cbf8dfc9028c8063398b1b20d1ad74fb8951b6e0fcfe735ea2b26b976c"
            ),
            withdrawals_root=bytes.fromhex(
                "ad48c078abc7af2fc02142b76d431a3d09661349486debb0ad2bea224392cb6c"
            ),
            blob_gas_used=0,
            excess_blob_gas=0,
        )
        final_root = header.merkle_root()
        self.assertEqual(
            final_root.hex(),
            "6c1d76195c93d80260c2d4134aacdb969907113de90909da620100fa579eb0c5",
        )

    def test_validator_pubkey_proof(self):
        header_data = {
            "slot": "0x5852f2",
            "proposer_index": "0x33",
            "parent_block_root": "0x155f296b0f1125544889bf879fdcef2378af621cce314682da092ecc6adf8ec8",
            "state_root": "0x7aac2bab3ed70e35ba9123b739f6375caed3b51c8c947703087b911d54b0cc9f",
            "body_root": "0xea41d9a12d46e604dd4c8c52da906a1840635955cd105e5a8fbfa685964c593b",
        }
        header = json_to_class(header_data, BeaconBlockHeader)
        # state_root = header.state_root
        block_header_root = header.merkle_root()
        self.assertEqual(
            block_header_root.hex(),
            "3d6dded8aa57791988455356078cd96ac75091735152b7e8adf33de25082da9b",
        )

        validator_data = {
            "pubkey": "0xa15875a9e554e446e5fcd463245f4d7bd6863b1a5f51d33ac828d06f9185c5705f1d0a442b52df142ee74f300a01551f",
            "withdrawalCredentials": "0x010000000000000000000000a957e9785bc9eeeaa64593dd8259f2e07046d3c8",
            "effectiveBalance": "0x1fb9c9a5d82000",
            "slashed": False,
            "activationEligibilityEpoch": "0x1cc7",
            "activationEpoch": "0x1cc8",
            "exitEpoch": "0xffffffffffffffff",
            "withdrawableEpoch": "0xffffffffffffffff",
        }

        validator = json_to_class(validator_data, Validator)
        # Build field roots
        field_roots = [
            merkle_root_basic(validator.pubkey, "bytes48"),
            merkle_root_basic(validator.withdrawal_credentials, "bytes32"),
            merkle_root_basic(validator.effective_balance, "uint64"),
            merkle_root_basic(validator.slashed, "Boolean"),
            merkle_root_basic(validator.activation_eligibility_epoch, "uint64"),
            merkle_root_basic(validator.activation_epoch, "uint64"),
            merkle_root_basic(validator.exit_epoch, "uint64"),
            merkle_root_basic(validator.withdrawable_epoch, "uint64"),
        ]
        # Build tree and get proof
        validator_tree = build_merkle_tree(field_roots)

        index = 0  # First field in Validator
        validator_proof = get_proof(validator_tree, index)

        pubkey = bytes.fromhex(
            "a15875a9e554e446e5fcd463245f4d7bd6863b1a5f51d33ac828d06f9185c5705f1d0a442b52df142ee74f300a01551f"
        )
        self.assertEqual(pubkey, validator.pubkey)

        leaf = merkle_root_basic(pubkey, "bytes48")
        proof = [
            bytes.fromhex(h[2:])
            for h in [
                "0x010000000000000000000000a957e9785bc9eeeaa64593dd8259f2e07046d3c8",
                "0xffae64d081b01627ab57193796a2d0d929c534c3f8c33ed85c94c349942b54ce",
                "0x81efbba19b2ca44f019dce8721b55e188b046efa92569c5e03ee59e58b1b97b4",
                "0x8ffeac1518192ddb9d356a31f48b853728228dfe67d592aea2baf505edd328a7",
                "0x196f230b0bb0392b28b2c634db1a3865671cf4d5ff9e40742392559580a824e4",
                "0xd71fb4d8d2a7e12fc9ca671cdd99c66ff36efd1b7b1cb92a2fcc9cede30eb2b2",
                "0x14a328f40b853e7a2d5483054d16c9f460b1a36d8ed49afe213343d474dea20b",
                "0x5fc75066c323834880ff0fe0657a16329b16c43cc447a49e2f90174f0495aebd",
                "0x21db48a3dc27b86d5fffab71df74780aa38023c2f03280b48028c6fc11aafc03",
                "0x74d256a5f003db5f5dc1f5451427fc7df21087495ee8183f0722395973d5acd8",
                "0x87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c",
                "0x26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193",
                "0x506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1",
                "0xffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b",
                "0x6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220",
                "0xb7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f",
                "0xdf6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e",
                "0xb58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784",
                "0xd49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb",
                "0x8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb",
                "0x8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab",
                "0x95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4",
                "0xf893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f",
                "0xcddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa",
                "0x8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c",
                "0xfeb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167",
                "0xe71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7",
                "0x31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0",
                "0x21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544",
                "0x619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765",
                "0x7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4",
                "0x848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1",
                "0x8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636",
                "0xb5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c",
                "0x985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7",
                "0xc6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff",
                "0x1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5",
                "0x2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d",
                "0x328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c",
                "0xbfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327",
                "0x55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74",
                "0xf7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76",
                "0xad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f",
                "0x4500000000000000000000000000000000000000000000000000000000000000",
                "0x6c1d76195c93d80260c2d4134aacdb969907113de90909da620100fa579eb0c5",
                "0xe77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e",
                "0x1b8afbf6f0034f939f0cfc6e3b03362631bdce35a43b65cbb8f732fa08373b69",
                "0xfbad9a092ada7c1c0f9c3ae9d7bd048ee458e53a987fd40a69b4d9752c6f47db",
                "0x155f296b0f1125544889bf879fdcef2378af621cce314682da092ecc6adf8ec8",
                "0x2e672338e4de9807ff3cf1d6e5e3c8e69948f6f23c53bec560a00f23798226f9",
                "0x8dc6933956b28092ca349896d3adbd09a2b829aa2a206792df8580347e8a6405",
            ]
        ]

        index_all = 0
        index_all_2 = 0
        for i in range(0, len(validator_proof)):
            # print(f"actual proof: {proof[i].hex()}")
            # print(f"gen proof: {validator_proof[i].hex()}")
            self.assertEqual(proof[i], validator_proof[i])
            index_all += 1

        validator_root = validator.merkle_root()

        # verify validator list
        state = load_and_process_state("test/data/state2.json")
        # elements_roots = [merkle_root_element(v, "Validator") for v in state.validators]
        # val_list_tree = merkle_list_tree(elements_roots)
        # index = 51  # Validator index = 51
        # validator_list_proof = get_proof(val_list_tree, index)
        elements_roots = [merkle_root_element(v, "Validator") for v in state.validators]
        # Suppose there are 64 actual validators in state.validators.

        validator_list_capacity = VALIDATOR_REGISTRY_LIMIT  # 2^40
        validator_list_index = 51  # example index
        validator_list_proof = get_fixed_capacity_proof(
            elements_roots, validator_list_index, validator_list_capacity
        )
        # Now append the “length chunk” (69 validators) at the end:
        length_chunk = len(elements_roots).to_bytes(
            32, "little"
        )  # b'\x45' + b'\x00'*31
        validator_list_proof.append(length_chunk)
        leaf = elements_roots[validator_list_index]
        validators_root = compute_root_from_proof(
            leaf, validator_list_index, validator_list_proof
        )

        for i in range(0, len(validator_list_proof)):
            # print(f"actual proof: {proof[i + index_all].hex()}")
            # print(f"gen proof: {validator_list_proof[i].hex()}")
            self.assertEqual(proof[i + index_all], validator_list_proof[i])
            index_all_2 += 1

        index_all_2 += index_all
        index_all = index_all_2
        length_packed = len(elements_roots).to_bytes(32, "little")
        # validators_list_leaf = sha256(val_list_tree[-1][0] + length_packed).digest()
        # print(f"val__list_leaf: {validators_list_leaf.hex()}")

        # reset state root for merkle
        state.latest_block_header.state_root = int(0).to_bytes(32)
        state.state_roots[2] = bytes.fromhex(
            "01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8"
        )
        # state.state_roots[2] = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        state.block_roots[2] = bytes.fromhex(
            "28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74"
        )
        # state.block_roots[2] = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")

        # verify val list leaf in beacon state
        state_fields = [
            # Field (0): genesis_validators_root
            merkle_root_basic(state.genesis_validators_root, "bytes32"),
            # Field (1): slot
            merkle_root_basic(state.slot, "uint64"),
            # Field (2): fork
            state.fork.merkle_root(),
            # Field (3): latest_block_header
            state.latest_block_header.merkle_root(),
            # Field (4): block_roots
            # merkle_root_vector(state.block_roots, "bytes32", SLOTS_PER_HISTORICAL_ROOT),
            encode_block_roots(state.block_roots),
            # Field (5): state_roots
            # merkle_root_vector(state.state_roots, "bytes32", SLOTS_PER_HISTORICAL_ROOT),
            encode_block_roots(state.state_roots),
            # Field (6): eth1_data
            state.eth1_data.merkle_root(),
            # Field (7): eth1_deposit_index
            merkle_root_basic(state.eth1_deposit_index, "uint64"),
            # Field (8): latest_execution_payload_header
            state.latest_execution_payload_header.merkle_root(),
            # Field (9): validators
            validators_root,
            # Field (10): balances
            # merkle_root_vector(state.balances, "uint64", MAX_VALIDATORS),
            # merkle_root_ssz_list(state.balances, "uint64", MAX_VALIDATORS),
            encode_balances(state.balances),
            # merkle_root_ssz_list(state.balances, "uint64", MAX_VALIDATORS),
            # Field (11): randao_mixes
            # merkle_root_vector(
            #     state.randao_mixes, "bytes32", EPOCHS_PER_HISTORICAL_VECTOR
            # ),
            # merkle_root_ssz_list(
            #     state.randao_mixes, "bytes32", EPOCHS_PER_HISTORICAL_VECTOR
            # ),
            encode_randao_mixes(state.randao_mixes),
            # Field (12): next_withdrawal_index
            merkle_root_basic(state.next_withdrawal_index, "uint64"),
            # Field (13): next_withdrawal_validator_index
            merkle_root_basic(state.next_withdrawal_validator_index, "uint64"),
            # Field (14): slashings
            # merkle_root_vector(state.slashings, "uint64", EPOCHS_PER_SLASHINGS_VECTOR),
            encode_slashings(state.slashings),
            # Field (15): total_slashing
            merkle_root_basic(state.total_slashing, "uint64"),
        ]
        # print(f"state fields: {[field.hex() for field in state_fields]}")
        # for field in fields(state.latest_execution_payload_header):
        #     value=getattr(state.latest_execution_payload_header, field.name)
        #     if isinstance(value, (bytes)):
        #         value = value.hex()
        #     print(f"{field.name}: {value}")
        # Pad to next power of two
        n = len(state_fields)
        k = math.ceil(math.log2(max(n, 1)))
        num_leaves = 1 << k
        padded = state_fields + [b"\0" * 32] * (num_leaves - n)

        state_tree = build_merkle_tree(padded)

        proof_state = get_proof(
            state_tree,
            9,
        )  # validators at index 9
        # # Berachain treats BeaconState as a Vector of length 32 (i.e., pad 16→32).
        # state_capacity = 32
        # # We want a proof for field index 9 in a 32‐leaf tree
        # proof_state = get_fixed_capacity_proof(
        #     state_fields, index=9, capacity=state_capacity
        # )

        # leaf = state_fields[9]

        state_root = state_tree[-1][0]
        print(f"state_root: {state_root.hex()}")

        full_proof = validator_proof + validator_list_proof + proof_state
        # for i in range(0, len(full_proof)):
        #     print(full_proof[i].hex())
        # print(state.balances)
        # for i in range(0, len(state.randao_mixes)):
        #     print(state.randao_mixes[i].hex())
        for i in range(0, len(proof_state)):
            # print(f"actual proof: {proof[i + index_all_2].hex()}")
            # print(f"gen proof: {proof_state[i].hex()}")
            # fails here on second run
            self.assertEqual(proof[i + index_all_2], proof_state[i])
            index_all += 1

        # index = 51  # Assuming validator index 51
        # self.assertTrue(verify_merkle_proof(leaf, full_proof, index_all, state_root))


if __name__ == "__main__":
    unittest.main()
