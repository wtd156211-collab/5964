"""DNS 报文解析与查询构造（受限子集）。

范围：标准查询（OPCODE=0）的查询/应答报文；记录类型仅 A/CNAME/TXT/AAAA；
CLASS 仅 IN；只解析 QUESTION 与 ANSWER 两段（NSCOUNT/ARCOUNT 必须为 0）。
支持名字压缩指针：严格向前指、深度上限 8 层。规则细节见 README.md。

只用标准库。命令行用法：

    python3 dnsmsg.py query example.com A --id 4660 --rd 1   # 输出报文 hex
    python3 dnsmsg.py parse <hex>                            # 逐行输出解析结果
    python3 dnsmsg.py bulk samples/bulk.bin                  # 批量统计
"""

from __future__ import annotations

import json
import struct

# ---------------------------------------------------------------- 常量

TYPE_A = 1
TYPE_CNAME = 5
TYPE_TXT = 16
TYPE_AAAA = 28

CLASS_IN = 1

SUPPORTED_TYPES = {
    TYPE_A: "A",
    TYPE_CNAME: "CNAME",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
}
TYPE_CODES = {name: code for code, name in SUPPORTED_TYPES.items()}

HEADER_LEN = 12
MAX_POINTER_DEPTH = 8      # 一次名字解析最多跟随的指针层数
MAX_NAME_WIRE_LEN = 255    # 名字展开后的线格式总长度上限（含结束符）
MAX_LABEL_LEN = 63


class DNSError(Exception):
    """报文解析错误。code 为 README 定义的错误码，offset 为字节偏移（从 0 起）。"""

    def __init__(self, code: str, offset: int):
        super().__init__(f"{code} at offset {offset}")
        self.code = code
        self.offset = offset

    def line(self) -> str:
        return f"error,{self.code},{self.offset}"


# ---------------------------------------------------------------- 基础读取

def _need(msg: bytes, pos: int, n: int) -> None:
    """需要在 pos 处读 n 字节；报文不够长则报 TRUNCATED，偏移取字段起始 pos。"""
    if pos + n > len(msg):
        raise DNSError("TRUNCATED", pos)


def _read_u16(msg: bytes, pos: int) -> tuple[int, int]:
    _need(msg, pos, 2)
    return (msg[pos] << 8) | msg[pos + 1], pos + 2


def _read_u32(msg: bytes, pos: int) -> tuple[int, int]:
    _need(msg, pos, 4)
    return struct.unpack_from("!I", msg, pos)[0], pos + 4


# ---------------------------------------------------------------- 名字解析

def read_name(msg: bytes, start: int) -> tuple[str, int]:
    """从 start 解析一个（可能被压缩的）名字。

    返回 (名字文本, 名字结束后游标位置)。游标停在结束符之后，或第一个
    指针占用的两个字节之后（不跳到指针目标末尾）。

    单次遍历完成：跟随指针只移动解析位置 pos，不复制报文；labels 里只存
    各标签的切片视图。防御三条：
      - 指针目标必须严格小于指针自身偏移（堵死自指/互指/后指，链必收敛）；
      - 跟随层数超过 MAX_POINTER_DEPTH 报 POINTER_LOOP，偏移取该层指针；
      - 高两位为 01/10 的保留形式报 BAD_POINTER。
    """
    labels: list[bytes] = []
    pos = start
    end: int | None = None   # 主线上名字结束后的位置（首个指针之后或结束符之后）
    depth = 0
    wire_len = 1             # 展开后的线格式长度，结束符占 1 字节
    while True:
        _need(msg, pos, 1)
        b = msg[pos]
        kind = b & 0xC0
        if kind == 0xC0:
            _need(msg, pos, 2)
            target = ((b & 0x3F) << 8) | msg[pos + 1]
            # 严格向前指；target < pos 又蕴含 target 落在报文范围内（pos < len）
            if target >= pos:
                raise DNSError("BAD_POINTER", pos)
            depth += 1
            if depth > MAX_POINTER_DEPTH:
                raise DNSError("POINTER_LOOP", pos)
            if end is None:
                end = pos + 2
            pos = target
        elif kind == 0x00:
            if b == 0:
                if end is None:
                    end = pos + 1
                break
            _need(msg, pos, 1 + b)
            wire_len += 1 + b
            if wire_len > MAX_NAME_WIRE_LEN:
                raise DNSError("NAME_TOO_LONG", start)
            labels.append(msg[pos + 1: pos + 1 + b])
            pos += 1 + b
        else:
            # 01 / 10 保留形式
            raise DNSError("BAD_POINTER", pos)
    name = ".".join(label.decode("utf-8", "replace") for label in labels)
    return name, end


# ---------------------------------------------------------------- RDATA

def _format_aaaa(rdata: bytes) -> str:
    """RFC 5952 零压缩：小写、最长零段压成 ::、等长取靠前、单零段不压。"""
    groups = struct.unpack("!8H", rdata)
    best_start, best_len = -1, 0
    i = 0
    while i < 8:
        if groups[i] == 0:
            j = i
            while j < 8 and groups[j] == 0:
                j += 1
            if j - i > best_len:      # 严格大于 => 等长取靠前的一段
                best_start, best_len = i, j - i
            i = j
        else:
            i += 1
    if best_len < 2:
        return ":".join(f"{g:x}" for g in groups)
    left = ":".join(f"{g:x}" for g in groups[:best_start])
    right = ":".join(f"{g:x}" for g in groups[best_start + best_len:])
    return left + "::" + right


def _parse_rdata(msg: bytes, rtype: int, rdata_start: int, rdlen: int,
                 rdlen_offset: int) -> str:
    """按类型解析 RDATA，返回值的文本形式。声明长度与实际不符报 LENGTH_MISMATCH。"""
    _need(msg, rdata_start, rdlen)
    rdata_end = rdata_start + rdlen
    if rtype == TYPE_A:
        if rdlen != 4:
            raise DNSError("LENGTH_MISMATCH", rdlen_offset)
        return ".".join(str(b) for b in msg[rdata_start:rdata_end])
    if rtype == TYPE_AAAA:
        if rdlen != 16:
            raise DNSError("LENGTH_MISMATCH", rdlen_offset)
        return _format_aaaa(msg[rdata_start:rdata_end])
    if rtype == TYPE_CNAME:
        name, end = read_name(msg, rdata_start)
        if end != rdata_end:
            raise DNSError("LENGTH_MISMATCH", rdlen_offset)
        return name
    # TXT：若干「长度 + 内容」字符串段，必须恰好填满 RDATA，拼接后按 JSON 字符串输出
    parts: list[bytes] = []
    pos = rdata_start
    while pos < rdata_end:
        seg_len = msg[pos]
        pos += 1
        if pos + seg_len > rdata_end:
            raise DNSError("LENGTH_MISMATCH", rdlen_offset)
        parts.append(msg[pos:pos + seg_len])
        pos += seg_len
    text = b"".join(parts).decode("utf-8", "replace")
    return json.dumps(text, ensure_ascii=False)


# ---------------------------------------------------------------- 报文解析

def parse_message(msg: bytes) -> list[str]:
    """解析一份报文，返回输出行列表（不含行尾 LF）。出错抛 DNSError。"""
    _need(msg, 0, HEADER_LEN)
    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!6H", msg, 0)
    if nscount != 0 or arcount != 0:
        raise DNSError("UNSUPPORTED_SECTION", 8)
    lines = [
        f"id={msg_id}",
        f"flags=0x{flags:04x}",
        f"qdcount={qdcount}",
        f"ancount={ancount}",
    ]
    pos = HEADER_LEN
    for _ in range(qdcount):
        name, pos = read_name(msg, pos)
        type_off = pos
        rtype, pos = _read_u16(msg, pos)
        class_off = pos
        rclass, pos = _read_u16(msg, pos)
        if rtype not in SUPPORTED_TYPES:
            raise DNSError("UNSUPPORTED_TYPE", type_off)
        if rclass != CLASS_IN:
            raise DNSError("UNSUPPORTED_CLASS", class_off)
        lines.append(f"q,{name},{SUPPORTED_TYPES[rtype]},IN")
    for _ in range(ancount):
        name, pos = read_name(msg, pos)
        type_off = pos
        rtype, pos = _read_u16(msg, pos)
        class_off = pos
        rclass, pos = _read_u16(msg, pos)
        ttl, pos = _read_u32(msg, pos)
        rdlen_off = pos
        rdlen, pos = _read_u16(msg, pos)
        if rtype not in SUPPORTED_TYPES:
            raise DNSError("UNSUPPORTED_TYPE", type_off)
        if rclass != CLASS_IN:
            raise DNSError("UNSUPPORTED_CLASS", class_off)
        value = _parse_rdata(msg, rtype, pos, rdlen, rdlen_off)
        pos += rdlen
        lines.append(f"a,{name},{SUPPORTED_TYPES[rtype]},IN,{ttl},{value}")
    return lines


def render_message(msg: bytes) -> str:
    """解析报文并渲染成行尾 LF 的文本；出错时输出单行 error,<码>,<偏移>。"""
    try:
        return "\n".join(parse_message(msg)) + "\n"
    except DNSError as exc:
        return exc.line() + "\n"


# ---------------------------------------------------------------- 查询构造

def build_query(name: str, rtype: str, qid: int = 0, rd: int = 1) -> bytes:
    """构造标准查询报文。rtype 为 "A"/"AAAA"/"CNAME"/"TXT"；rd 取 0/1。

    域名允许末尾带点（编码时去掉）；空域名、空标签、标签超 63 字节、
    整体超 255 字节、类型不支持、id 越界都抛 ValueError。
    """
    if rtype not in TYPE_CODES:
        raise ValueError(f"不支持的记录类型: {rtype!r}")
    if not 0 <= qid <= 0xFFFF:
        raise ValueError(f"id 超出范围: {qid}")
    if rd not in (0, 1):
        raise ValueError(f"rd 只能是 0 或 1: {rd!r}")
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise ValueError("空域名")
    qname = bytearray()
    for label in name.split("."):
        raw = label.encode("utf-8")
        if not raw:
            raise ValueError(f"域名含空标签: {name!r}")
        if len(raw) > MAX_LABEL_LEN:
            raise ValueError(f"标签超过 {MAX_LABEL_LEN} 字节: {label!r}")
        qname.append(len(raw))
        qname += raw
    qname.append(0)
    if len(qname) > MAX_NAME_WIRE_LEN:
        raise ValueError(f"域名超过 {MAX_NAME_WIRE_LEN} 字节: {name!r}")
    flags = 0x0100 if rd else 0x0000   # QR=0 OPCODE=0 AA=TC=RA=0 Z=0 RCODE=0，仅 RD 可变
    header = struct.pack("!6H", qid, flags, 1, 0, 0, 0)
    question = bytes(qname) + struct.pack("!HH", TYPE_CODES[rtype], CLASS_IN)
    return header + question


# ---------------------------------------------------------------- 批量处理

def iter_bulk(stream) -> "iter[bytes]":
    """从「4 字节大端长度 + 报文字节」的流里逐个产出报文。"""
    while True:
        head = stream.read(4)
        if not head:
            return
        if len(head) < 4:
            raise DNSError("TRUNCATED", 0)
        (length,) = struct.unpack("!I", head)
        body = stream.read(length)
        if len(body) < length:
            raise DNSError("TRUNCATED", 0)
        yield body


def summarize_bulk(path: str) -> dict:
    """解析批量文件，返回统计：消息数、回答条数、各类型计数、出错数。"""
    counts = {name: 0 for name in TYPE_CODES}
    messages = answers = errors = 0
    with open(path, "rb") as fh:
        for msg in iter_bulk(fh):
            try:
                lines = parse_message(msg)
            except DNSError:
                errors += 1
                continue
            messages += 1
            for line in lines:
                if line.startswith("a,"):
                    answers += 1
                    counts[line.split(",", 3)[2]] += 1
    return {"messages": messages, "answers": answers, "errors": errors, **counts}


# ---------------------------------------------------------------- 命令行

def main(argv=None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="dnsmsg", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("query", help="构造查询报文，输出十六进制")
    q.add_argument("name")
    q.add_argument("type", choices=["A", "AAAA", "CNAME", "TXT"])
    q.add_argument("--id", type=int, default=0)
    q.add_argument("--rd", type=int, default=1, choices=[0, 1])

    p = sub.add_parser("parse", help="解析十六进制报文，逐行输出结果")
    p.add_argument("hex", help="报文的十六进制字符串")

    b = sub.add_parser("bulk", help="解析批量文件（长度前缀流），输出统计")
    b.add_argument("path")

    args = parser.parse_args(argv)
    if args.cmd == "query":
        sys.stdout.write(build_query(args.name, args.type, args.id, args.rd).hex() + "\n")
    elif args.cmd == "parse":
        sys.stdout.write(render_message(bytes.fromhex(args.hex)))
    else:
        stats = summarize_bulk(args.path)
        out = [
            f"messages={stats['messages']}",
            f"answers={stats['answers']}",
            f"A={stats['A']}",
            f"AAAA={stats['AAAA']}",
            f"TXT={stats['TXT']}",
            f"CNAME={stats['CNAME']}",
        ]
        if stats["errors"]:
            out.append(f"errors={stats['errors']}")
        sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
