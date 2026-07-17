"""
diagnose_pwdump.py

Checks a secretsdump/DCSync/pwdump-format hash file for the issues that
commonly make hashcat reject the whole file with:

    Failed to parse hashes using the 'pwdump' format.

Expected line shape:

    DOMAIN\\username:RID:LMHASH:NTHASH:::

Run this locally against your real file -- it never prints full hash
values or usernames, only line numbers and short diagnostic messages, so
it's safe to share the output (or a summary of it) without exposing
credential material.

Usage:
    python3 diagnose_pwdump.py yourfile.txt
"""
