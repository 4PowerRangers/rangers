#!/usr/bin/env python3
"""Offline Tempera-Mnemonic-1 wallet credential derivation."""

import argparse
import hashlib
import hmac
import re


PATH = "m/44'/60'/0'/0/0"
_CHECKSUM = re.compile(r"^w[0-9a-f]{4}$")


def derive_wallet(mnemonic: str) -> str:
    words = mnemonic.strip().lower().split()
    if len(words) != 12 or any(not word.isalpha() for word in words[:11]):
        raise ValueError("expected exactly 12 lowercase words")
    expected = hashlib.sha256(" ".join(words[:11]).encode()).hexdigest()[:4]
    if not _CHECKSUM.fullmatch(words[11]) or words[11][1:] != expected:
        raise ValueError("mnemonic checksum mismatch")
    seed = hashlib.pbkdf2_hmac("sha512", " ".join(words).encode(), b"Tempera-Mnemonic-1", 2048)
    return hmac.new(seed, PATH.encode(), hashlib.sha256).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mnemonic")
    args = parser.parse_args()
    print(derive_wallet(args.mnemonic))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
