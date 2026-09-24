import json
import os
import time
import unittest

import dnsmsg

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def load_sample(name):
    with open(os.path.join(SAMPLES, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


class QueryBuildTest(unittest.TestCase):
    def test_samples_byte_exact(self):
        for case in load_sample("queries.json"):
            with self.subTest(case=case["name"], qtype=case["type"]):
                packet = dnsmsg.build_query(
                    case["name"], case["type"], qid=case["id"], rd=case["rd"]
                )
                self.assertEqual(packet.hex(), case["hex"])

    def test_query_roundtrip_question_line(self):
        for case in load_sample("queries.json"):
            with self.subTest(case=case["name"]):
                lines = dnsmsg.parse_message(bytes.fromhex(case["hex"]))
                self.assertEqual(lines[4], case["parsed_query"])

    def test_defaults(self):
        packet = dnsmsg.build_query("example.com", "A")
        self.assertEqual(packet[:4].hex(), "00000100")  # ID=0, RD=1

    def test_trailing_dot_equivalent(self):
        self.assertEqual(
            dnsmsg.build_query("example.com.", "A"),
            dnsmsg.build_query("example.com", "A"),
        )

    def test_invalid_names(self):
        for bad in ("", ".", "a..b", "x" * 64 + ".com", ".".join(["a" * 63] * 5)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    dnsmsg.build_query(bad, "A")

    def test_invalid_type(self):
        with self.assertRaises(ValueError):
            dnsmsg.build_query("example.com", "MX")


class ResponseParseTest(unittest.TestCase):
    def test_samples(self):
        for case in load_sample("responses.json"):
            with self.subTest(case=case["case"]):
                msg = bytes.fromhex(case["hex"])
                self.assertEqual(len(msg), case["bytes"])
                self.assertEqual(dnsmsg.parse_message(msg), case["expected"])

    def test_deterministic(self):
        for case in load_sample("responses.json"):
            msg = bytes.fromhex(case["hex"])
            self.assertEqual(dnsmsg.format_message(msg), dnsmsg.format_message(msg))


class BrokenMessageTest(unittest.TestCase):
    def test_samples(self):
        for case in load_sample("broken.json"):
            with self.subTest(case=case["case"]):
                msg = bytes.fromhex(case["hex"])
                self.assertEqual(len(msg), case["bytes"])
                with self.assertRaises(dnsmsg.DNSError) as ctx:
                    dnsmsg.parse_message(msg)
                self.assertEqual(ctx.exception.line(), case["expected"])

    def test_truncated_header(self):
        with self.assertRaises(dnsmsg.DNSError) as ctx:
            dnsmsg.parse_message(b"\x00" * 5)
        self.assertEqual(ctx.exception.code, "TRUNCATED")
        self.assertEqual(ctx.exception.offset, 0)

    def test_unsupported_section(self):
        # NSCOUNT=1 -> 固定报偏移 8
        msg = bytes.fromhex("000081800001000000010000")
        with self.assertRaises(dnsmsg.DNSError) as ctx:
            dnsmsg.parse_message(msg)
        self.assertEqual(ctx.exception.line(), "error,UNSUPPORTED_SECTION,8")

    def test_bad_pointer_backward(self):
        # 问题名字直接是指向自身偏移的指针
        msg = bytes.fromhex("000001000001000000000000" + "c00c" + "00010001")
        with self.assertRaises(dnsmsg.DNSError) as ctx:
            dnsmsg.parse_message(msg)
        self.assertEqual(ctx.exception.line(), "error,BAD_POINTER,12")

    def test_bad_pointer_reserved_form(self):
        # 首字节高两位 10 是保留形式
        msg = bytes.fromhex("000001000001000000000000" + "8000" + "00010001")
        with self.assertRaises(dnsmsg.DNSError) as ctx:
            dnsmsg.parse_message(msg)
        self.assertEqual(ctx.exception.line(), "error,BAD_POINTER,12")

    def test_bad_pointer_out_of_range(self):
        # 指针向前但目标越界不可能（目标 < 自身偏移必在界内），
        # 这里构造指针目标落在报文内但指向截断名字之外的情形由 TRUNCATED 覆盖。
        msg = bytes.fromhex("000001000001000000000000" + "c0")
        with self.assertRaises(dnsmsg.DNSError) as ctx:
            dnsmsg.parse_message(msg)
        self.assertEqual(ctx.exception.code, "TRUNCATED")

    def test_unsupported_class(self):
        # QCLASS=3 (CH)
        msg = bytes.fromhex(
            "000001000001000000000000"
            "076578616d706c6503636f6d00"
            "00010003"
        )
        with self.assertRaises(dnsmsg.DNSError) as ctx:
            dnsmsg.parse_message(msg)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_CLASS")
        self.assertEqual(ctx.exception.offset, 27)

    def test_name_too_long(self):
        # 四个 63 字节标签，拼出来超过 255
        label = "3f" + "61" * 63
        msg = bytes.fromhex(
            "000001000001000000000000" + label * 4 + "00" + "00010001"
        )
        with self.assertRaises(dnsmsg.DNSError) as ctx:
            dnsmsg.parse_message(msg)
        self.assertEqual(ctx.exception.code, "NAME_TOO_LONG")
        self.assertEqual(ctx.exception.offset, 12)


class BulkTest(unittest.TestCase):
    def test_bulk_stats_and_speed(self):
        with open(os.path.join(SAMPLES, "bulk.bin"), "rb") as fh:
            data = fh.read()
        start = time.monotonic()
        messages, answers, type_counts = dnsmsg.bulk_stats(data)
        elapsed = time.monotonic() - start
        with open(os.path.join(SAMPLES, "bulk.expected.txt"), "r") as fh:
            expected = fh.read().splitlines()
        actual = ["messages=%d" % messages, "answers=%d" % answers]
        actual += ["%s=%d" % item for item in type_counts.items()]
        self.assertEqual(actual, expected)
        self.assertLess(elapsed, 5.0, "bulk parse too slow: %.2fs" % elapsed)


if __name__ == "__main__":
    unittest.main()
