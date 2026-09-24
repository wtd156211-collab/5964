"""DNS 报文解析与查询构造（受限子集，仅标准库）。

支持范围：
- 查询（QR=0）与应答（QR=1）报文，OPCODE=0；
- 记录类型 A(1)、CNAME(5)、TXT(16)、AAAA(28)，CLASS 仅 IN(1)；
- 只解析 QUESTION 与 ANSWER 段，NSCOUNT/ARCOUNT 必须为 0；
- 名字压缩指针：必须严格向前指，跟随深度上限 8 层。
"""

import ipaddress
import json
import struct

TYPE_TO_CODE = {"A": 1, "CNAME": 5, "TXT": 16, "AAAA": 28}
CODE_TO_TYPE = {code: name for name, code in TYPE_TO_CODE.items()}
CLASS_IN = 1

HEADER_LENGTH = 12
MAX_POINTER_DEPTH = 8
MAX_NAME_LENGTH = 255
MAX_LABEL_LENGTH = 63


class DNSError(Exception):
    """报文诊断错误。code 为错误码，offset 为出错位置的字节偏移（从 0 开始）。"""

    def __init__(self, code, offset):
        super().__init__("%s at offset %d" % (code, offset))
        self.code = code
        self.offset = offset

    def line(self):
        return "error,%s,%d" % (self.code, self.offset)


def _read(msg, offset, length):
    """从 offset 读 length 字节；不够时报 TRUNCATED，偏移指向这次读取的起点。"""
    if offset < 0 or offset + length > len(msg):
        raise DNSError("TRUNCATED", offset)
    return msg[offset:offset + length]


def _read_u16(msg, offset):
    return struct.unpack(">H", _read(msg, offset, 2))[0]


def _read_u32(msg, offset):
    return struct.unpack(">I", _read(msg, offset, 4))[0]


def parse_name(msg, start):
    """解析 start 处的名字，返回 (域名字符串, 名字结束后游标应停的位置)。

    单趟扫描：游标沿标签前进，遇到指针就跳到目标继续，但只记录第一次
    跳转前的位置作为返回值（指针占两个字节，游标停在其后）。
    指针必须严格向前指，跟随层数超过 MAX_POINTER_DEPTH 报 POINTER_LOOP。
    """
    labels = []
    offset = start
    end_offset = None
    jumps = 0
    wire_length = 1  # 结束符占 1 字节
    while True:
        if offset >= len(msg):
            raise DNSError("TRUNCATED", offset)
        head = msg[offset]
        tag = head & 0xC0
        if tag == 0xC0:
            _read(msg, offset, 2)
            target = ((head & 0x3F) << 8) | msg[offset + 1]
            if target >= offset or target >= len(msg):
                raise DNSError("BAD_POINTER", offset)
            jumps += 1
            if jumps > MAX_POINTER_DEPTH:
                raise DNSError("POINTER_LOOP", offset)
            if end_offset is None:
                end_offset = offset + 2
            offset = target
            continue
        if tag != 0:
            raise DNSError("BAD_POINTER", offset)
        if head == 0:
            if end_offset is None:
                end_offset = offset + 1
            break
        _read(msg, offset + 1, head)
        wire_length += 1 + head
        if wire_length > MAX_NAME_LENGTH:
            raise DNSError("NAME_TOO_LONG", start)
        labels.append(bytes(msg[offset + 1:offset + 1 + head]))
        offset += 1 + head
    name = b".".join(labels).decode("latin-1")
    return name, end_offset


def _check_type(msg, offset):
    code = _read_u16(msg, offset)
    if code not in CODE_TO_TYPE:
        raise DNSError("UNSUPPORTED_TYPE", offset)
    return code


def _check_class(msg, offset):
    code = _read_u16(msg, offset)
    if code != CLASS_IN:
        raise DNSError("UNSUPPORTED_CLASS", offset)


def _parse_rdata(msg, rdata_offset, rdlength, rdlength_offset, type_code):
    """解析 RDATA，返回值的字符串形式。声明长度与实耗不符报 LENGTH_MISMATCH。"""
    rdata = _read(msg, rdata_offset, rdlength)
    if type_code == TYPE_TO_CODE["A"]:
        if rdlength != 4:
            raise DNSError("LENGTH_MISMATCH", rdlength_offset)
        return ".".join(str(part) for part in rdata)
    if type_code == TYPE_TO_CODE["AAAA"]:
        if rdlength != 16:
            raise DNSError("LENGTH_MISMATCH", rdlength_offset)
        return ipaddress.IPv6Address(rdata).compressed
    if type_code == TYPE_TO_CODE["CNAME"]:
        name, end_offset = parse_name(msg, rdata_offset)
        if end_offset - rdata_offset != rdlength:
            raise DNSError("LENGTH_MISMATCH", rdlength_offset)
        return name
    # TXT：若干「长度 + 内容」段，直接拼接
    parts = []
    pos = 0
    while pos < rdlength:
        size = rdata[pos]
        if pos + 1 + size > rdlength:
            raise DNSError("LENGTH_MISMATCH", rdlength_offset)
        parts.append(rdata[pos + 1:pos + 1 + size])
        pos += 1 + size
    return json.dumps(b"".join(parts).decode("latin-1"))


def parse_message_records(msg):
    """解析整个报文，返回 (头部四行, 问题列表, 回答列表)。

    问题元素为 (name, type_name)；回答元素为 (name, type_name, ttl, value)。
    出错抛 DNSError。
    """
    header = _read(msg, 0, HEADER_LENGTH)
    ident, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", header)
    if nscount != 0 or arcount != 0:
        raise DNSError("UNSUPPORTED_SECTION", 8)
    head_lines = [
        "id=%d" % ident,
        "flags=0x%04x" % flags,
        "qdcount=%d" % qdcount,
        "ancount=%d" % ancount,
    ]
    offset = HEADER_LENGTH
    questions = []
    for _ in range(qdcount):
        name, offset = parse_name(msg, offset)
        type_code = _check_type(msg, offset)
        _check_class(msg, offset + 2)
        offset += 4
        questions.append((name, CODE_TO_TYPE[type_code]))
    answers = []
    for _ in range(ancount):
        name, offset = parse_name(msg, offset)
        type_code = _check_type(msg, offset)
        _check_class(msg, offset + 2)
        ttl = _read_u32(msg, offset + 4)
        rdlength_offset = offset + 8
        rdlength = _read_u16(msg, rdlength_offset)
        rdata_offset = offset + 10
        value = _parse_rdata(msg, rdata_offset, rdlength, rdlength_offset, type_code)
        answers.append((name, CODE_TO_TYPE[type_code], ttl, value))
        offset = rdata_offset + rdlength
    return head_lines, questions, answers


def parse_message(msg):
    """解析报文，返回输出行列表；出错抛 DNSError。"""
    head_lines, questions, answers = parse_message_records(msg)
    lines = list(head_lines)
    for name, type_name in questions:
        lines.append("q,%s,%s,IN" % (name, type_name))
    for name, type_name, ttl, value in answers:
        lines.append("a,%s,%s,IN,%d,%s" % (name, type_name, ttl, value))
    return lines


def format_message(msg):
    """解析报文并返回完整输出文本（出错时返回 error 行）。"""
    try:
        return "\n".join(parse_message(msg)) + "\n"
    except DNSError as err:
        return err.line() + "\n"


def encode_name(name):
    """把域名编码成「标签 + 结束符」的字节序列（不做压缩）。"""
    text = name[:-1] if name.endswith(".") else name
    if not text:
        raise ValueError("empty domain name")
    out = bytearray()
    for label in text.split("."):
        raw = label.encode("ascii")
        if not raw:
            raise ValueError("empty label in %r" % name)
        if len(raw) > MAX_LABEL_LENGTH:
            raise ValueError("label too long in %r" % name)
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > MAX_NAME_LENGTH:
        raise ValueError("name too long: %r" % name)
    return bytes(out)


def build_query(name, qtype, qid=0, rd=1):
    """构造查询报文。除 ID 与 RD 标志外，其余字段固定。"""
    try:
        type_code = TYPE_TO_CODE[qtype.upper()]
    except KeyError:
        raise ValueError("unsupported type: %r" % qtype)
    flags = 0x0100 if rd else 0x0000
    header = struct.pack(">HHHHHH", qid & 0xFFFF, flags, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", type_code, CLASS_IN)


def iter_bulk(data):
    """遍历「4 字节大端长度 + 报文」重复构成的批量流，逐条产出报文。"""
    offset = 0
    while offset < len(data):
        (size,) = struct.unpack(">I", _read(data, offset, 4))
        yield _read(data, offset + 4, size)
        offset += 4 + size


def bulk_stats(data):
    """统计批量流：返回 (消息数, 回答总数, 各类型计数（按首次出现序）)。"""
    messages = 0
    answers = 0
    type_counts = {}
    for msg in iter_bulk(data):
        _, _, answer_list = parse_message_records(msg)
        messages += 1
        answers += len(answer_list)
        for _, type_name, _, _ in answer_list:
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
    return messages, answers, type_counts
