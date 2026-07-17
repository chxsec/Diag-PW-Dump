diag_pwdump.py

Overview

Checks a secretsdump/DCSync/pwdump-format hash file for the issues that commonly make hashcat reject the whole file with:

Failed to parse hashes using the 'pwdump' format.

Expected line shape:

DOMAIN\username:RID:LMHASH:NTHASH:::

What it catches


CRLF (Windows-style) line endings
UTF-16 / BOM encoding issues
Non-numeric RID fields
LM/NT hash fields that aren't exactly 32 characters
Non-hex characters in the hash fields
Stray banner/log lines mixed into the file (e.g. secretsdump status output)
Blank lines


Usage

bashpython3 diag_pwdump.py yourfile.txt

Run this locally against your real file — it never prints full hash values or usernames, only line numbers and short diagnostic messages, so it's safe to share the output (or a summary of it) without exposing credential material.
