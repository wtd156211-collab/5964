"""dnsmsg 的 unittest 测试：samples 验收 + 压缩指针/错误诊断/构造边界。"""

import json
import os
import time
import unittest

import dnsmsg
from dnsmsg import DNSError, build_query, parse_message, render_message

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def load_json(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return json.load(fh)


def render_hex(hex_str):
    return render_message(bytes.fromhex(hex_str))


class TestBuildQuery(unittest.TestCase):
    """构造的字节必须与 samples/queries.json 逐字节一致（ID 与 RD 之外不可变）。"""

    def test_samples_byte_exact(self):
        for case in load_json("queries.json"):
            with self.subTest(case=case["name"], type=case["type"]):
                got = build_query(case["name"], case["type"], qid=case["id"], rd=case["rd"])
                self.assertEqual(got.hex(), case["hex"])

    def test_built_query_parses_back(self):
        for case in load_json("queries.json"):
            with self.subTest(case=case["name"]):
                lines = parse_message(bytes.fromhex(case["hex"]))
                self.assertIn(case["parsed_query"], lines)

    def test_defaults_id_zero_rd_one(self):
        msg = build_query("example.com", "A")
        self.assertEqual(msg[:4].hex(), "00000100")

    def test_trailing_dot_equivalent(self):
        self.assertEqual(build_query("example.com.", "A"),
                         build_query("example.com", "A"))

    def test_invalid_names(self):
        for bad in ("", ".", "a..b", "a" * 64 + ".com",
                    ".".join(["a" * 63] * 4) + ".com"):  # 4*64+1 = 257 > 255
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    build_query(bad, "A")

    def test_invalid_type_and_id(self):
        with self.assertRaises(ValueError):
            build_query("example.com", "MX")
        with self.assertRaises(ValueError):
            build_query("example.com", "A", qid=65536)


class TestParseResponses(unittest.TestCase):
    def test_samples(self):
        for case in load_json("responses.json"):
            with self.subTest(case=case["case"]):
                msg = bytes.fromhex(case["hex"])
                self.assertEqual(len(msg), case["bytes"])
                self.assertEqual(parse_message(msg), case["expected"])

    def test_deterministic(self):
        for case in load_json("responses.json"):
            msg = bytes.fromhex(case["hex"])
            self.assertEqual(render_message(msg), render_message(msg))


class TestBrokenMessages(unittest.TestCase):
    def test_samples(self):
        for case in load_json("broken.json"):
            with self.subTest(case=case["case"]):
                self.assertEqual(render_hex(case["hex"]).rstrip("\n"), case["expected"])

    def test_truncated_header(self):
        self.assertEqual(render_message(b"\x00" * 5), "error,TRUNCATED,0\n")

    def test_unsupported_section(self):
        # NSCOUNT=1 -> 固定偏移 8
        msg = bytes.fromhex("000081800001000000010000")
        self.assertEqual(render_message(msg), "error,UNSUPPORTED_SECTION,8\n")

    def test_unsupported_class(self):
        # 问题段 CLASS=3（CHAOS），CLASS 字段在偏移 25
        msg = bytes.fromhex(
            "000001000001000000000000"
            "076578616d706c6503636f6d00"
            "00010003")
        self.assertEqual(render_message(msg), "error,UNSUPPORTED_CLASS,27\n")

    def test_reserved_pointer_forms(self):
        for first in (0x40, 0x80):
            msg = bytes.fromhex("000001000001000000000000") + bytes([first, 0x00]) + b"\x00\x01\x00\x01"
            with self.subTest(first=first):
                self.assertEqual(render_message(msg), "error,BAD_POINTER,12\n")

    def test_forward_pointer(self):
        # 问题名字是指向自身之后偏移的指针
        msg = bytes.fromhex("000001000001000000000000") + bytes([0xC0, 0x20]) + b"\x00\x01\x00\x01"
        self.assertEqual(render_message(msg), "error,BAD_POINTER,12\n")

    def test_name_too_long(self):
        # 4 个 63 字节标签：4*64+1 = 257 > 255，名字起始于 12
        qname = b"".join(bytes([63]) + b"a" * 63 for _ in range(4)) + b"\x00"
        msg = bytes.fromhex("000001000001000000000000") + qname + b"\x00\x01\x00\x01"
        self.assertEqual(render_message(msg), "error,NAME_TOO_LONG,12\n")


class TestPointerChains(unittest.TestCase):
    """逐级前指的指针链：8 层恰好通过，第 9 层报 POINTER_LOOP。"""

    @staticmethod
    def make_chain_message(n_answers):
        # 问题：example.com A；第 i 条应答的名字指针指向第 i-1 条的名字
        msg = bytearray(bytes.fromhex(
            "123481800001" + f"{n_answers:04x}" + "00000000"
            "076578616d706c6503636f6d0000010001"))
        name_off = 29   # 第一条应答名字的偏移
        prev_off = 12   # 问题里的名字
        for _ in range(n_answers):
            msg += bytes([0xC0 | (prev_off >> 8), prev_off & 0xFF])
            msg += bytes.fromhex("000100010000003c000401020304")
            prev_off = name_off
            name_off += 16
        return bytes(msg)

    def test_depth_8_ok(self):
        lines = parse_message(self.make_chain_message(8))
        self.assertEqual(lines[-1], "a,example.com,A,IN,60,1.2.3.4")

    def test_depth_9_loop(self):
        self.assertEqual(render_message(self.make_chain_message(9)),
                         "error,POINTER_LOOP,29\n")


class TestRdataFormats(unittest.TestCase):
    @staticmethod
    def a_response(rtype_hex, rdata_hex):
        return bytes.fromhex(
            "000081800001000100000000"
            "076578616d706c6503636f6d0000010001"
            "c00c" + rtype_hex + "0001" + "0000012c" + f"{len(bytes.fromhex(rdata_hex)):04x}" + rdata_hex)

    def answer_line(self, rtype_hex, rdata_hex):
        return parse_message(self.a_response(rtype_hex, rdata_hex))[-1]

    def test_aaaa_zero_compression(self):
        # 最长零段压缩
        self.assertTrue(self.answer_line("001c", "20010db8000000000000000000000001")
                        .endswith(",2001:db8::1"))
        # 全零
        self.assertTrue(self.answer_line("001c", "00" * 16).endswith(",::"))
        # 单个零段不压缩
        self.assertTrue(self.answer_line("001c", "20010db8000000010002000300040005")
                        .endswith(",2001:db8:0:1:2:3:4:5"))
        # 等长零段取靠前
        self.assertTrue(self.answer_line("001c", "fe01" + "0000" * 2 + "0002" + "0000" * 2 + "0003" + "0004")
                        .endswith(",fe01::2:0:0:3:4"))

    def test_txt_multiple_segments_joined(self):
        # "v=spf1 " + "-all" -> "v=spf1 -all"
        line = self.answer_line("0010", "07763d7370663120042d616c6c")
        self.assertTrue(line.endswith(',"v=spf1 -all"'))

    def test_txt_json_escaping(self):
        line = self.answer_line("0010", "0361225c")  # 'a"\\'
        self.assertTrue(line.endswith(',"a\\"\\\\"'))

    def test_txt_length_mismatch(self):
        # 段声明 5 字节但 RDATA 只剩 2 字节，RDLENGTH 字段在偏移 39
        msg = self.a_response("0010", "050102")
        self.assertEqual(render_message(msg), "error,LENGTH_MISMATCH,39\n")

    def test_cname_rdlength_mismatch(self):
        # CNAME 的 RDATA 名字占 13 字节，但声明 14
        msg = bytearray(self.a_response("0005", "076578616d706c6503636f6d00"))
        msg[40] = 14
        msg += b"\x00"
        self.assertEqual(render_message(bytes(msg)), "error,LENGTH_MISMATCH,39\n")


class TestBulk(unittest.TestCase):
    def test_bulk_stats_and_speed(self):
        start = time.monotonic()
        stats = dnsmsg.summarize_bulk(os.path.join(SAMPLES, "bulk.bin"))
        elapsed = time.monotonic() - start
        expected = {}
        with open(os.path.join(SAMPLES, "bulk.expected.txt"), encoding="utf-8") as fh:
            for line in fh:
                key, _, val = line.strip().partition("=")
                expected[key] = int(val)
        self.assertEqual(stats["messages"], expected["messages"])
        self.assertEqual(stats["answers"], expected["answers"])
        self.assertEqual(stats["A"], expected["A"])
        self.assertEqual(stats["AAAA"], expected["AAAA"])
        self.assertEqual(stats["TXT"], expected["TXT"])
        self.assertEqual(stats["CNAME"], expected["CNAME"])
        self.assertEqual(stats["errors"], 0)
        self.assertLess(elapsed, 5.0, f"批量解析超时: {elapsed:.2f}s")


if __name__ == "__main__":
    unittest.main()
