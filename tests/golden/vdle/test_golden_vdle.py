"""Golden tests for VDLE protocol framing and chunking."""

import unittest
from reconstruction.vdle import (
    build_flash_block,
    init_vdle_reply,
    parse_segment_info,
    iter_flash_chunks,
    XXL_THRESHOLD,
    JOB_FLASH_WRITE,
    JOB_FLASH_WRITE_XXL,
)


class TestGoldenVDLE(unittest.TestCase):
    def test_21_byte_block_header_format(self):
        """21-byte block header format matching live execution of FUN_004668b0."""
        addr = 0x00A00000
        data = b"\xde\xad\xbe\xef"
        blk = build_flash_block(addr, data)
        # Expected:
        # [0:4]   01 01 00 00
        # [4:8]   00 00 00 00
        # [8:12]  00 FF 00 00
        # [12]    00
        # [13:15] len_le16 = 4
        # [15:17] duplicate len_le16 = 4
        # [17:21] addr_le32 = 0x00A00000
        # [21:25] de ad be ef
        # [25]    03 (ETX)
        expected_header = (
            b"\x01\x01\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\xff\x00\x00"
            + b"\x00"
            + b"\x04\x00"
            + b"\x04\x00"
            + b"\x00\x00\xa0\x00"
        )
        self.assertEqual(blk[:21], expected_header)
        self.assertEqual(blk[21:25], data)
        self.assertEqual(blk[25:], b"\x03")
        self.assertEqual(len(blk), 26)

    def test_init_vdle_reply(self):
        """INIT_VDLE returns OKAY;<segment_count>."""
        self.assertEqual(init_vdle_reply(1), "OKAY;1")
        self.assertEqual(init_vdle_reply(5), "OKAY;5")

    def test_parse_segment_info(self):
        """parse_segment_info parses OKAY;0x<addr>;0x<size>."""
        addr, size = parse_segment_info("OKAY;0x00870000;0x00000100")
        self.assertEqual(addr, 0x00870000)
        self.assertEqual(size, 0x00000100)

    def test_iter_flash_chunks(self):
        """iter_flash_chunks splits 0x110 bytes into 0x100 and 0x10 tail."""
        chunks = list(iter_flash_chunks(0x00870000, 0x110, 0x100, 0))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0], (0x00870000, 0x100))
        self.assertEqual(chunks[1], (0x00870100, 0x10))

    def test_xxl_threshold(self):
        """Block sizes > 254 (0xFE) select FLASH_SCHREIBEN_XXL."""
        self.assertEqual(XXL_THRESHOLD, 0xFE)
        self.assertEqual(
            JOB_FLASH_WRITE if 16 <= XXL_THRESHOLD else JOB_FLASH_WRITE_XXL,
            JOB_FLASH_WRITE,
        )
        self.assertEqual(
            JOB_FLASH_WRITE if 256 <= XXL_THRESHOLD else JOB_FLASH_WRITE_XXL,
            JOB_FLASH_WRITE_XXL,
        )


if __name__ == "__main__":
    unittest.main()
