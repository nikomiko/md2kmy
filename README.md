# md2kmy — Moneydance → KMyMoney converter

Converts a [Moneydance](https://moneydance.com/) `.moneydance` data directory into a
[KMyMoney](https://kmymoney.org/) `.kmy` file (gzipped XML) that opens directly — no
import wizard, no manual re-entry.

## What gets converted

| Moneydance | KMyMoney |
|---|---|
| All account types (bank, credit card, asset, liability, loan, investment, expense, income) | Native account hierarchy |
| Opening balances (`sbal`) | Opening Balance transactions |
| All transactions with splits | Transactions with SPLITS |
| Cross-currency & investment transactions | Correct share/value sign convention |
| Payees | PAYEES section |
| Securities (stocks) | SECURITIES with E###### IDs, `trading-currency`, price precision |
| Currencies | CURRENCIES with exchange-rate attributes |
| First-transaction prices | PRICES section (securities + foreign currencies) |
| Account opening dates | Derived from first transaction or `sbal` date |

## Requirements

- Python 3.8+
- [`cryptography`](https://pypi.org/project/cryptography/) library

```bash
pip install cryptography
```

## Usage

```bash
python3 md_to_kmy.py [data_dir] [output.kmy]
```

**Arguments** (both optional, positional):

| Argument | Default | Description |
|---|---|---|
| `data_dir` | hardcoded path | Path to the `.moneydance` directory |
| `output` | `comptesv7.kmy` | Output `.kmy` file |

**Example:**

```bash
python3 md_to_kmy.py ~/Documents/MyFinances.moneydance finances.kmy
kmymoney finances.kmy
```

## Moneydance encryption

Moneydance stores data in `safe/tiksync/trunk`, encrypted with AES-128/CBC using a
two-layer key derivation:

1. A meta-key is derived from a hardcoded passphrase via PBKDF2-HMAC-SHA512
2. The meta-key decrypts the actual AES-128 data key stored in the `key` file
3. The data key decrypts the `trunk` file (newline-separated `tiksync` records)

The passphrase and KDF parameters were extracted from `moneydance.jar` bytecode and
are the same for all Moneydance installations.

## Limitations & known gaps

- **Loan amortization schedules** — loan account fields (`init_principal`, `int_rate`,
  `num_payments`…) are read but KMyMoney `SCHEDULE` elements are not yet generated.
- **Online quote sources** — French stocks need the `.PA` Yahoo Finance suffix (e.g.
  `BNP.PA`). Set these manually in KMyMoney after import.
- **Single passphrase** — only the default Moneydance encryption passphrase is
  supported. Custom passphrases are not yet handled.
- **Attachments** — transaction attachments are not migrated.

## File format notes

- The `.kmy` format is a gzipped XML file consumed by KMyMoney 5.x / 6.x.
- Security IDs follow the KMyMoney `E######` convention so they are editable after import.
- `PRICEPAIR` entries use the first real buy/sell transaction price as the opening price,
  satisfying KMyMoney's "opening date price" check.

## License

MIT
