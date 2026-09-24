"""命令行入口：构造查询、解析报文、批量统计。

用法：
  python3 dnstool.py query NAME TYPE [--id N] [--rd 0|1]   输出查询报文十六进制
  python3 dnstool.py parse HEX                             解析一条报文（十六进制）
  python3 dnstool.py parse --file PATH                     解析文件里的一条报文
  python3 dnstool.py bulk PATH                             统计长度前缀批量流
"""

import argparse
import sys

import dnsmsg


def main(argv=None):
    parser = argparse.ArgumentParser(prog="dnstool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_query = sub.add_parser("query", help="构造查询报文")
    p_query.add_argument("name")
    p_query.add_argument("type")
    p_query.add_argument("--id", type=int, default=0)
    p_query.add_argument("--rd", type=int, default=1, choices=(0, 1))

    p_parse = sub.add_parser("parse", help="解析一条报文")
    p_parse.add_argument("hex", nargs="?", help="报文的十六进制串")
    p_parse.add_argument("--file", help="从文件读报文字节")

    p_bulk = sub.add_parser("bulk", help="统计长度前缀批量流")
    p_bulk.add_argument("path")

    args = parser.parse_args(argv)

    if args.cmd == "query":
        try:
            packet = dnsmsg.build_query(args.name, args.type, qid=args.id, rd=args.rd)
        except ValueError as err:
            print("invalid input: %s" % err, file=sys.stderr)
            return 2
        print(packet.hex())
        return 0

    if args.cmd == "parse":
        if args.file:
            with open(args.file, "rb") as fh:
                msg = fh.read()
        elif args.hex:
            msg = bytes.fromhex(args.hex)
        else:
            parser.error("parse 需要 HEX 或 --file")
        sys.stdout.write(dnsmsg.format_message(msg))
        return 0

    with open(args.path, "rb") as fh:
        data = fh.read()
    try:
        messages, answers, type_counts = dnsmsg.bulk_stats(data)
    except dnsmsg.DNSError as err:
        print(err.line())
        return 1
    print("messages=%d" % messages)
    print("answers=%d" % answers)
    for type_name, count in type_counts.items():
        print("%s=%d" % (type_name, count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
