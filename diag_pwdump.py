#!/usr/bin/env python3

import sys

HEX = set("0123456789abcdefABCDEF")


def check_line(lineno, raw):
    problems = []

    # Line ending check (before any stripping)
    if raw.endswith("\r\n"):
        problems.append("CRLF line ending (Windows) -- strip the trailing \\r")
    elif raw.endswith("\r"):
        problems.append("bare CR line ending -- unusual, strip it")

    line = raw.rstrip("\r\n")

    if line == "":
        problems.append("blank line")
        return problems

    if line.strip() != line:
        problems.append("leading/trailing whitespace")

    # BOM / non-ascii check
    if any(ord(c) > 127 for c in line):
        problems.append("contains non-ASCII characters (possible encoding issue, e.g. UTF-16 copy-paste)")

    parts = line.split(":")
    if len(parts) < 7:
        problems.append(f"expected at least 7 colon-separated fields (user:rid:lm:nt:::), found {len(parts)}: {line[:0]}<hidden>")
        # still try to check what we can
    else:
        username, rid = parts[0], parts[1]
        lm_hash, nt_hash = parts[2], parts[3]

        if not rid.isdigit():
            problems.append(f"RID field (2nd field) isn't purely numeric (len={len(rid)})")

        for label, h in (("LM hash", lm_hash), ("NT hash", nt_hash)):
            if len(h) != 32:
                problems.append(f"{label} field isn't 32 characters (got {len(h)})")
            elif not all(c in HEX for c in h):
                bad_positions = [i for i, c in enumerate(h) if c not in HEX]
                problems.append(f"{label} field has non-hex characters at position(s) {bad_positions}")

        # trailing ":::" -- secretsdump format ends with three empty fields
        if parts[-3:] != ["", "", ""]:
            problems.append("line doesn't end with ':::' (extra/missing trailing fields) -- may indicate this isn't a credential line at all (e.g. a banner/status line)")

    return problems


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 diagnose_pwdump.py yourfile.txt")

    path = sys.argv[1]

    # Detect encoding issues up front.
    with open(path, "rb") as f:
        raw_bytes = f.read()
    if raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
        print("[!] File starts with a UTF-16 BOM -- this is almost certainly why hashcat is failing.")
        print("    Convert it to plain UTF-8 first, e.g.:")
        print("    iconv -f UTF-16 -t UTF-8 yourfile.txt -o yourfile_utf8.txt")
        print()
    elif raw_bytes.startswith(b"\xef\xbb\xbf"):
        print("[!] File starts with a UTF-8 BOM -- strip it, e.g.:")
        print("    sed -i '1s/^\\xef\\xbb\\xbf//' yourfile.txt")
        print()

    total_lines = 0
    bad_lines = 0
    # newline="" disables universal-newline translation so CRLF/CR endings
    # are preserved and detectable instead of being silently normalized away.
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        for lineno, raw in enumerate(f, 1):
            total_lines += 1
            problems = check_line(lineno, raw)
            if problems:
                bad_lines += 1
                print(f"line {lineno}: " + "; ".join(problems))

    print()
    print(f"Checked {total_lines} lines, {bad_lines} had issues.")
    if bad_lines == 0:
        print("No structural issues found -- the file looks like valid pwdump format. "
              "If hashcat still rejects it, double check you're using -m 1000 and that "
              "the file doesn't have a trailing blank line hashcat's version dislikes, "
              "or try -m 1000 with --username explicitly.")


if __name__ == "__main__":
    main()
