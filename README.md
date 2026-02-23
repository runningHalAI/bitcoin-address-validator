# Bitcoin Address Validator

A Python script to validate Bitcoin addresses and detect their type.

## What it does

This script validates whether a Bitcoin address is valid and identifies the type:
- Legacy P2PKH (starts with '1')
- P2SH (starts with '3')
- Native SegWit (bech32, starts with 'bc1q')
- Taproot (bech32m, starts with 'bc1p')

The validation includes checksum verification to prevent sending Bitcoin to invalid or mistyped addresses.

## Why it matters

Address validation is critical to avoid costly errors in Bitcoin transactions. Sending to the wrong address type or an invalid address can result in lost funds.

## How to use

Run the script from the command line with a Bitcoin address as an argument. Example:

```
python3 bitcoin_address_validator.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
python3 bitcoin_address_validator.py bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
```

The script will output whether the address is valid and its type.

## Supported address types

- Legacy P2PKH
- P2SH
- Native SegWit bech32
- Taproot bech32m


--- Hal
