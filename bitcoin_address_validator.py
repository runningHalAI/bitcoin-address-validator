"""
bitcoin_address_validator.py

Validate and detect Bitcoin address types:
- Legacy P2PKH (prefix 1, Base58Check)
- P2SH (prefix 3, Base58Check)
- Native SegWit bech32 (prefix bc1q)
- Taproot bech32m (prefix bc1p)

Usage examples:
    python3 bitcoin_address_validator.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    python3 bitcoin_address_validator.py bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

"""

import sys
import re
import hashlib
from typing import Optional

# Alphabet for Base58
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# Bech32 character set
BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


class BitcoinAddressValidator:
    @staticmethod
    def base58_decode(s: str) -> Optional[bytes]:
        num = 0
        for char in s:
            if char not in BASE58_ALPHABET:
                return None
            num = num * 58 + BASE58_ALPHABET.index(char)
        combined = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')

        # Add leading zero bytes
        n_pad = len(s) - len(s.lstrip('1'))
        return b'\x00' * n_pad + combined

    @staticmethod
    def base58_check(s: str) -> bool:
        decoded = BitcoinAddressValidator.base58_decode(s)
        if not decoded or len(decoded) < 4:
            return False
        checksum = decoded[-4:]
        vh160 = decoded[:-4]
        h = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()
        return checksum == h[:4]

    @staticmethod
    def bech32_polymod(values) -> int:
        GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = (chk >> 25)
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                if ((b >> i) & 1):
                    chk ^= GENERATORS[i]
        return chk

    @staticmethod
    def bech32_hrp_expand(hrp: str):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @staticmethod
    def bech32_verify_checksum(hrp: str, data) -> bool:
        return BitcoinAddressValidator.bech32_polymod(BitcoinAddressValidator.bech32_hrp_expand(hrp) + data) == 1

    @staticmethod
    def bech32m_verify_checksum(hrp: str, data) -> bool:
        return BitcoinAddressValidator.bech32_polymod(BitcoinAddressValidator.bech32_hrp_expand(hrp) + data) == 0x2bc830a3

    @staticmethod
    def decode_bech32(address: str) -> Optional[tuple]:
        if (any(ord(x) < 33 or ord(x) > 126 for x in address)):
            return None
        if (address.lower() != address and address.upper() != address):
            return None
        address = address.lower()
        pos = address.rfind('1')
        if pos == -1 or pos < 1 or pos + 7 > len(address):
            return None
        hrp = address[:pos]
        data = address[pos+1:]
        data_values = []
        for c in data:
            if c not in BECH32_CHARSET:
                return None
            data_values.append(BECH32_CHARSET.find(c))
        return hrp, data_values

    @staticmethod
    def validate_bech32(address: str) -> str:
        decode_result = BitcoinAddressValidator.decode_bech32(address)
        if not decode_result:
            return "Invalid"
        hrp, data = decode_result
        if BitcoinAddressValidator.bech32_verify_checksum(hrp, data):
            return "bech32"
        elif BitcoinAddressValidator.bech32m_verify_checksum(hrp, data):
            return "bech32m"
        else:
            return "Invalid"

    @staticmethod
    def validate(address: str) -> str:
        """
        Validate a Bitcoin address and return its type or 'Invalid'.

        Types:
        - Legacy P2PKH (starts with '1')
        - P2SH (starts with '3')
        - Native SegWit bech32 (starts with 'bc1q')
        - Taproot bech32m (starts with 'bc1p')
        """
        if address.startswith('1') or address.startswith('3'):
            if BitcoinAddressValidator.base58_check(address):
                if address.startswith('1'):
                    return 'Legacy P2PKH'
                else:
                    return 'P2SH'
            else:
                return 'Invalid'
        elif address.lower().startswith('bc1'):
            typ = BitcoinAddressValidator.validate_bech32(address)
            if typ == 'bech32':
                # Check prefix for native segwit (bc1q)
                if address.lower().startswith('bc1q'):
                    return 'Native SegWit bech32'
                else:
                    return 'Unknown bech32'
            elif typ == 'bech32m':
                if address.lower().startswith('bc1p'):
                    return 'Taproot bech32m'
                else:
                    return 'Unknown bech32m'
            else:
                return 'Invalid'
        else:
            return 'Invalid'


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <bitcoin_address>")
        sys.exit(1)
    address = sys.argv[1]
    result = BitcoinAddressValidator.validate(address)
    print(f"Address: {address}\nType: {result}")

# -- Hal
