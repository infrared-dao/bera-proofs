import unittest
import hashlib

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
        # print(f"sha3: {sha3_256(padded_uint).digest().hex()}, hashlib: {hashlib.sha256(padded_uint).digest().hex()}")
        padded_bool = b"\x01" + b"\x00" * 31
        self.assertEqual(merkle_root_basic(True, "Boolean"), padded_bool)

    def test_merkle_root_list(self):
        self.assertEqual(merkle_root_list([]), b"\x00" * 32)
        self.assertEqual(merkle_root_list([b"\x01" * 32]), b"\x01" * 32)
        two_elements = sha3_256(b"\x01" * 32 + b"\x02" * 32).digest()
        self.assertEqual(merkle_root_list([b"\x01" * 32, b"\x02" * 32]), two_elements)

    def test_merkle_root_ssz_list(self):
        # Single uint64
        elements = [123]
        elements_roots = [merkle_root_basic(123, "uint64")]
        chunks_root = merkle_root_list(elements_roots)
        length_packed = len(elements).to_bytes(32, "little")
        expected = sha3_256(chunks_root + length_packed).digest()
        self.assertEqual(
            merkle_root_ssz_list(elements, "uint64", MAX_VALIDATORS), expected
        )
        # Empty list
        length_packed = (0).to_bytes(32, "little")
        expected = sha3_256(b"\x00" * 32 + length_packed).digest()
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
