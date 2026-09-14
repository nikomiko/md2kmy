#!/usr/bin/env python3
"""
md_to_kmy.py — Moneydance → KMyMoney native file converter

Decrypts a Moneydance .moneydance package and writes a KMyMoney .kmy file
(gzipped XML) that can be opened directly without any import wizard.

Usage:
    python3 md_to_kmy.py <moneydance_dir> <output.kmy>

Defaults:
    moneydance_dir = /nas/commun/Administratif/Finances/MoneydanceData/Comptesv7.moneydance
    output.kmy     = ./comptesv7.kmy

Dependencies:
    pip install cryptography
"""

import argparse
import collections
import gzip
import os
import sys
import urllib.parse
import uuid
from datetime import date, datetime
from math import gcd
from xml.etree import ElementTree as ET

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Moneydance encryption constants (extracted from moneydance.jar bytecode) ──
_PBE_SALT     = bytes.fromhex("6d64585870626541696e736c6965")
_AES_IV       = bytes.fromhex("4deadbef8120189f81c54d0b3766e48b")
_DEFAULT_PASS = "Microph0ne Check Micr0phone Check, baby one 2 1 two"

# ── Moneydance account type char → KMyMoney account type int ─────────────────
# Source: Account$AccountType.class <clinit> bytecode (accountTypeChar field)
MD_TO_KMM_TYPE = {
    'b': 1,   # BANK       → Checkings
    'c': 4,   # CREDIT_CARD→ CreditCard
    'a': 9,   # ASSET      → Asset
    'l': 10,  # LIABILITY  → Liability
    'o': 5,   # LOAN       → Loan
    'v': 7,   # INVESTMENT → Investment
    's': 15,  # SECURITY   → Stock
    'e': 13,  # EXPENSE    → Expense
    'i': 12,  # INCOME     → Income
}

# KMyMoney standard top-level parent for each Moneydance account type
MD_DEFAULT_PARENT = {
    'b': 'AStd::Asset',
    'c': 'AStd::Liability',
    'a': 'AStd::Asset',
    'l': 'AStd::Liability',
    'o': 'AStd::Liability',
    'v': 'AStd::Asset',
    's': 'AStd::Asset',
    'e': 'AStd::Expense',
    'i': 'AStd::Income',
}

REAL_TYPES = set(MD_TO_KMM_TYPE.keys())
STD_IDS    = {'AStd::Asset', 'AStd::Liability', 'AStd::Expense',
              'AStd::Income', 'AStd::Equity'}

# ─────────────────────────────────────────────────────────────────────────────
# Crypto
# ─────────────────────────────────────────────────────────────────────────────

def _aes_cbc_decrypt(key, iv, ciphertext):
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()
    return d.update(ciphertext) + d.finalize()

def _derive_main_key(enc_key_hex):
    """Unwrap the AES-128 main key stored in the Moneydance key file."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=16, salt=_PBE_SALT,
                     iterations=1024, backend=default_backend())
    meta_key = kdf.derive(_DEFAULT_PASS.encode())
    raw = _aes_cbc_decrypt(meta_key, _AES_IV, bytes.fromhex(enc_key_hex))
    pad = raw[-1]  # PKCS5 padding byte
    return raw[:-pad]

def _decrypt_file(path, main_key):
    """Decrypt a Moneydance AES-CBC file and strip PKCS5 padding."""
    with open(path, 'rb') as f:
        enc = f.read()
    plain = _aes_cbc_decrypt(main_key, _AES_IV, enc)
    pad = plain[-1]
    if 1 <= pad <= 16 and all(b == pad for b in plain[-pad:]):
        plain = plain[:-pad]
    return plain

# ─────────────────────────────────────────────────────────────────────────────
# Moneydance data loading
# ─────────────────────────────────────────────────────────────────────────────

def _parse_tiksync_line(line):
    """Parse one tiksync KV line → (op, obj_type, {key: value})."""
    line = line.strip()
    if not line:
        return None, None, None
    colon = line.find(':')
    if colon < 0:
        return None, None, None
    op, _, obj_type = line[:colon].partition('.')
    kvs = {}
    for pair in line[colon + 1:].split('&'):
        if '=' in pair:
            k, _, v = pair.partition('=')
            kvs[k] = urllib.parse.unquote(v)
    return op, obj_type, kvs

def load_moneydance(data_dir):
    """
    Decrypt and parse a Moneydance .moneydance directory.
    Returns (accounts, currencies, transactions) — each a dict of id → kvs.
    """
    key_path = os.path.join(data_dir, 'key')
    with open(key_path) as f:
        key_line = f.read().strip().lstrip(':')
    kv = dict(p.split('=', 1) for p in key_line.split('&') if '=' in p)
    main_key = _derive_main_key(kv['key'])

    trunk_path = os.path.join(data_dir, 'safe', 'tiksync', 'trunk')
    size_kb = os.path.getsize(trunk_path) // 1024
    print(f"Decrypting trunk ({size_kb} KB)…")
    text = _decrypt_file(trunk_path, main_key).decode('utf-8', errors='replace')

    accounts, currencies, transactions = {}, {}, {}
    for line in text.split('\n'):
        op, obj_type, kvs = _parse_tiksync_line(line)
        if op != 'mod' or not kvs:
            continue
        oid = kvs.get('id')
        if not oid:
            continue
        if obj_type == 'acct':
            accounts[oid] = kvs
        elif obj_type == 'curr':
            currencies[oid] = kvs
        elif obj_type == 'txn':
            transactions[oid] = kvs

    print(f"Loaded: {len(accounts)} accounts, {len(currencies)} currencies,"
          f" {len(transactions)} transactions")
    return accounts, currencies, transactions

# ─────────────────────────────────────────────────────────────────────────────
# Amount & date helpers
# ─────────────────────────────────────────────────────────────────────────────

def to_rational(subunits, dec):
    """Convert integer subunits to a GCD-simplified 'num/den' string."""
    try:
        n = int(subunits)
    except (TypeError, ValueError):
        return '0/1'
    if n == 0:
        return '0/1'
    d = 10 ** int(dec)
    g = gcd(abs(n), d)
    return f"{n // g}/{d // g}"

def md_to_iso_date(s):
    """Convert Moneydance YYYYMMDD to YYYY-MM-DD, or '' if invalid."""
    s = (s or '').strip()
    if len(s) == 8 and s.isdigit():
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    return ''

def reconcile_flag(stat):
    """Map Moneydance stat field to KMyMoney reconcileflag integer string."""
    s = (stat or '').strip()
    if s in ('X', 'x'):
        return '2'  # reconciled
    if s in ('c', 'C', 'y', 'Y'):
        return '1'  # cleared
    return '0'     # unreconciled

# ─────────────────────────────────────────────────────────────────────────────
# XML helpers
# ─────────────────────────────────────────────────────────────────────────────

def xml_sub(parent, tag, **attrs):
    el = ET.SubElement(parent, tag)
    for k, v in attrs.items():
        el.set(k, str(v))
    return el

def xml_kvpairs(parent, pairs):
    if not pairs:
        return
    kv = ET.SubElement(parent, 'KEYVALUEPAIRS')
    for k, v in pairs.items():
        xml_sub(kv, 'PAIR', key=k, value=v)

# ─────────────────────────────────────────────────────────────────────────────
# Index builders
# ─────────────────────────────────────────────────────────────────────────────

def build_currency_index(currencies):
    """
    Build {md_currency_id: info_dict} where info_dict has:
      iso, dec, name, prefix, suffix, type ('c'=fiat, 's'=security)
    """
    index = {}
    for cid, c in currencies.items():
        iso = c.get('currid', '') or c.get('ticker', '') or cid[:3].upper()
        index[cid] = {
            'iso':    iso,
            'dec':    int(c.get('dec', 2)),
            'name':   c.get('name', iso),
            'prefix': c.get('pref', ''),
            'suffix': c.get('suff', ''),
            'type':   c.get('type', 'c'),
        }
    return index

def build_earliest_txn_dates(transactions):
    """
    Return {md_account_id: 'YYYY-MM-DD'} with the earliest transaction date
    for each account (checked on both the parent and split accounts).
    Used to ensure account opening dates never postdate their transactions.
    """
    earliest = collections.defaultdict(lambda: '9999-99-99')

    def _update(aid, dt):
        if aid and dt and dt < earliest[aid]:
            earliest[aid] = dt

    for txn in transactions.values():
        dt = md_to_iso_date(txn.get('dt', ''))
        if not dt:
            continue
        _update(txn.get('acctid', ''), dt)
        i = 0
        while txn.get(f'{i}.pamt') is not None:
            _update(txn.get(f'{i}.acctid', ''), dt)
            i += 1

    return earliest

def account_opening_date(acct, md_id, earliest_txn_dates):
    """
    Return the best opening date for an account:
      1. Explicit 'opened' field from Moneydance
      2. Earliest transaction date referencing this account
      3. '1900-01-01' as a safe universal fallback
    """
    explicit = md_to_iso_date(acct.get('opened', ''))
    if explicit:
        return explicit
    earliest = earliest_txn_dates.get(md_id, '9999-99-99')
    if earliest != '9999-99-99':
        return earliest
    return '1900-01-01'

def build_id_maps(accounts, transactions):
    """
    Assign deterministic KMyMoney IDs to accounts, transactions, and payees.
    Returns (acct_id_map, payee_id_map) where each is {source_key: kmm_id}.
    Accounts are sorted by name for stability across re-runs.
    """
    real = [(aid, a) for aid, a in accounts.items()
            if a.get('type') in REAL_TYPES]
    real.sort(key=lambda x: x[1].get('name', ''))
    acct_id_map = {aid: f"A{i+1:06d}" for i, (aid, _) in enumerate(real)}

    payee_names = sorted({
        txn.get('desc', '').strip()
        for txn in transactions.values()
        if txn.get('desc', '').strip()
    })
    payee_id_map = {name: f"P{i+1:06d}" for i, name in enumerate(payee_names)}

    return acct_id_map, payee_id_map

# ─────────────────────────────────────────────────────────────────────────────
# KMyMoney XML generation
# ─────────────────────────────────────────────────────────────────────────────

def _write_account_el(parent_el, acct_id, name, kmm_type, parent_acct_id,
                      currency_iso, opened='', description='',
                      child_ids=None, number=''):
    el = xml_sub(parent_el, 'ACCOUNT',
                 id=acct_id, name=name, type=str(kmm_type),
                 parentaccount=parent_acct_id, currency=currency_iso,
                 description=description, opened=opened, number=number,
                 lastmodified='', lastreconciled='', institution='')
    if child_ids:
        subs_el = ET.SubElement(el, 'SUBACCOUNTS')
        for cid in child_ids:
            xml_sub(subs_el, 'SUBACCOUNT', id=cid)
    xml_kvpairs(el, {'lastStatementDate': ''})
    return el

def _write_split_el(parent_el, split_id, account_id, shares, value,
                    payee_id='', price='1/1', memo='', number='',
                    reconcile_flag_val='0'):
    xml_sub(parent_el, 'SPLIT',
            id=split_id, account=account_id,
            shares=shares, value=value, price=price,
            payee=payee_id, memo=memo, number=number,
            reconcileflag=reconcile_flag_val,
            reconciledate='', action='', bankid='')

def build_kmy_xml(accounts, currencies, transactions,
                  acct_id_map, payee_id_map, curr_index, earliest_dates):
    """
    Build and return the KMYMONEY-FILE ElementTree root.
    All logic about mapping, ordering and balancing lives here.
    """
    real_accounts = {aid: a for aid, a in accounts.items()
                     if a.get('type') in REAL_TYPES}
    root_ids      = {aid for aid, a in accounts.items() if a.get('type') == 'r'}

    # Assign E###### IDs to securities (KMyMoney requires this format)
    _sec_counter = [0]
    def _next_sec_id():
        _sec_counter[0] += 1
        return f"E{_sec_counter[0]:06d}"

    _sec_e_ids = {}  # cid → E######
    for cid, ci in sorted(curr_index.items()):
        if ci.get('type') == 's' and ci.get('name'):
            _sec_e_ids[cid] = _next_sec_id()

    # sym → E###### (ticker/iso → E-ID, for price lookups)
    _sym_to_eid = {
        (ci.get('iso') or ci.get('name','')[:6].upper()): eid
        for cid, ci in curr_index.items()
        if ci.get('type') == 's' and ci.get('name')
        for eid in [_sec_e_ids.get(cid)]
        if eid
    }

    def acct_iso(acct):
        return curr_index.get(acct.get('currid', ''), {}).get('iso', 'EUR')

    def acct_currency_id(acct):
        """Like acct_iso but returns E-ID for security (stock) accounts."""
        cid = acct.get('currid', '')
        ci  = curr_index.get(cid, {})
        if ci.get('type') == 's':
            return _sec_e_ids.get(cid, ci.get('iso', 'EUR'))
        return ci.get('iso', 'EUR')

    def acct_dec(acct):
        return curr_index.get(acct.get('currid', ''), {}).get('dec', 2)

    def kmm_acct_id(md_id):
        return acct_id_map.get(md_id, 'AStd::Expense')

    def kmm_parent(acct):
        pid = acct.get('parentid', '')
        if pid in root_ids or pid not in accounts:
            return MD_DEFAULT_PARENT.get(acct.get('type', ''), 'AStd::Asset')
        if accounts[pid].get('type') in REAL_TYPES:
            return kmm_acct_id(pid)
        return MD_DEFAULT_PARENT.get(acct.get('type', ''), 'AStd::Asset')

    # Base currency = most-used currency among bank/asset accounts
    curr_freq = collections.Counter(
        a.get('currid', '')
        for a in real_accounts.values()
        if a.get('type') in ('b', 'a')
    )
    base_cid = curr_freq.most_common(1)[0][0] if curr_freq else ''
    base_iso = curr_index.get(base_cid, {}).get('iso', 'EUR')

    # Children map: md_parent_id → [md_child_id] (real accounts only)
    children_of = collections.defaultdict(list)
    for aid, acct in real_accounts.items():
        children_of[acct.get('parentid', '')].append(aid)

    # ── Root element ──────────────────────────────────────────────────────────
    root = ET.Element('KMYMONEY-FILE')

    # FILEINFO
    fi = ET.SubElement(root, 'FILEINFO')
    xml_sub(fi, 'CREATION_DATE',      date=date.today().isoformat())
    xml_sub(fi, 'LAST_MODIFIED_DATE', date=date.today().isoformat())
    xml_sub(fi, 'VERSION',    id='1')
    xml_sub(fi, 'FIXVERSION', id='4')

    xml_sub(root, 'USER', name='', email='')
    xml_sub(root, 'INSTITUTIONS', count='0')

    # ── PAYEES ────────────────────────────────────────────────────────────────
    payees_el = xml_sub(root, 'PAYEES', count=str(len(payee_id_map)))
    for name, pid in sorted(payee_id_map.items(), key=lambda x: x[1]):
        xml_sub(payees_el, 'PAYEE',
                id=pid, name=name, type='', reference='',
                email='', notes='', matchingenabled='0',
                usingmatchkey='0', matchignorecase='0', matchkey='',
                defaultaccountid='', street='', city='',
                postcode='', state='', telephone='', country='')

    xml_sub(root, 'TAGS', count='0')

    # ── ACCOUNTS ─────────────────────────────────────────────────────────────
    accts_el = xml_sub(root, 'ACCOUNTS',
                       count=str(6 + len(real_accounts)))  # 5 std + Opening Balances + real

    # Children of each standard account
    std_children = collections.defaultdict(list)
    for aid, acct in real_accounts.items():
        p = kmm_parent(acct)
        if p in STD_IDS:
            std_children[p].append(kmm_acct_id(aid))

    _write_account_el(accts_el, 'AStd::Asset',     'Asset',     9,  '',
                      base_iso, child_ids=sorted(std_children['AStd::Asset']))
    _write_account_el(accts_el, 'AStd::Liability', 'Liability', 10, '',
                      base_iso, child_ids=sorted(std_children['AStd::Liability']))
    _write_account_el(accts_el, 'AStd::Expense',   'Expense',   13, '',
                      base_iso, child_ids=sorted(std_children['AStd::Expense']))
    _write_account_el(accts_el, 'AStd::Income',    'Income',    12, '',
                      base_iso, child_ids=sorted(std_children['AStd::Income']))
    # AStd::Equity gets one real child: the Opening Balances account.
    # KMyMoney won't accept AStd::Equity directly in transaction splits,
    # so all opening balance transactions post against this child account.
    OB_ACCT_ID = 'A000000'
    _write_account_el(accts_el, 'AStd::Equity', 'Equity', 16, '',
                      base_iso, child_ids=[OB_ACCT_ID])
    _write_account_el(accts_el, OB_ACCT_ID, 'Opening Balances', 16,
                      'AStd::Equity', base_iso)

    for aid in sorted(real_accounts, key=kmm_acct_id):
        acct      = real_accounts[aid]
        child_ids = sorted(
            kmm_acct_id(c) for c in children_of.get(aid, [])
            if accounts[c].get('type') in REAL_TYPES
        )
        _write_account_el(
            accts_el,
            kmm_acct_id(aid),
            acct.get('name', ''),
            MD_TO_KMM_TYPE[acct.get('type')],
            kmm_parent(acct),
            acct_currency_id(acct),
            opened=account_opening_date(acct, aid, earliest_dates),
            description=acct.get('desc', ''),
            child_ids=child_ids or None,
            number=acct.get('number', ''),
        )

    # ── TRANSACTIONS ──────────────────────────────────────────────────────────
    txn_counter = [0]

    def next_txn_id():
        txn_counter[0] += 1
        return f"T{txn_counter[0]:018d}"

    txns_el = ET.SubElement(root, 'TRANSACTIONS')
    written = skipped = 0

    # Opening balance transactions (sbal ≠ 0), sorted by date
    opening_balances = []
    for aid, acct in real_accounts.items():
        try:
            sbal = int(acct.get('sbal', '0'))
        except (ValueError, TypeError):
            continue
        if sbal == 0:
            continue
        opening_balances.append((
            account_opening_date(acct, aid, earliest_dates),
            kmm_acct_id(aid),
            sbal,
            acct_dec(acct),
            acct_iso(acct),
        ))
    opening_balances.sort()

    for opened, kmm_id, sbal, dec, iso in opening_balances:
        tx_el = xml_sub(txns_el, 'TRANSACTION',
                        id=next_txn_id(), postdate=opened,
                        memo='Opening Balance', entrydate=opened,
                        commodity=iso, posttime='', entrytime='')
        sp_el = ET.SubElement(tx_el, 'SPLITS')
        _write_split_el(sp_el, 'S0001', kmm_id,
                        to_rational(sbal, dec), to_rational(sbal, dec),
                        memo='Opening Balance')
        _write_split_el(sp_el, 'S0002', OB_ACCT_ID,
                        to_rational(-sbal, dec), to_rational(-sbal, dec),
                        memo='Opening Balance')
        written += 1

    # Opening prices: first transaction price per security/currency pair
    # sec_prices[from_iso] = (date, price_rational, to_iso)
    sec_prices  = {}
    curr_prices = {}

    # Regular transactions sorted by date for ordered registers
    for txn in sorted(transactions.values(),
                      key=lambda t: (t.get('dt', ''), t.get('id', ''))):
        parent_acct_id = txn.get('acctid', '')
        if parent_acct_id not in real_accounts:
            skipped += 1
            continue

        postdate = md_to_iso_date(txn.get('dt', ''))
        if not postdate:
            skipped += 1
            continue

        parent_acct   = real_accounts[parent_acct_id]
        parent_dec    = acct_dec(parent_acct)
        parent_iso    = acct_iso(parent_acct)
        parent_kmm_id = kmm_acct_id(parent_acct_id)

        # Gather split lines from Moneydance (0.pamt, 1.pamt, …)
        splits = []
        i = 0
        while txn.get(f'{i}.pamt') is not None:
            sp_acct_id = txn.get(f'{i}.acctid', '')
            sp_acct    = real_accounts.get(sp_acct_id)
            splits.append({
                'acctid': sp_acct_id,
                'pamt':   int(txn[f'{i}.pamt']),
                'samt':   int(txn.get(f'{i}.samt', txn[f'{i}.pamt'])),
                'dec':    acct_dec(sp_acct) if sp_acct else parent_dec,
                'iso':    acct_iso(sp_acct) if sp_acct else parent_iso,
                'desc':   txn.get(f'{i}.desc', ''),
            })
            i += 1

        if not splits:
            skipped += 1
            continue

        desc     = txn.get('desc', '')
        memo     = txn.get('memo', '')
        chk      = txn.get('chk', '')
        stat     = txn.get('stat', '')
        payee_id = payee_id_map.get(desc.strip(), '')
        total    = sum(s['pamt'] for s in splits)

        tx_el = xml_sub(txns_el, 'TRANSACTION',
                        id=next_txn_id(), postdate=postdate,
                        memo=memo, entrydate=postdate,
                        commodity=parent_iso, posttime='', entrytime='')
        sp_el = ET.SubElement(tx_el, 'SPLITS')

        # Parent account split (the bank/credit side)
        _write_split_el(sp_el, 'S0001', parent_kmm_id,
                        to_rational(total, parent_dec),
                        to_rational(total, parent_dec),
                        payee_id=payee_id, memo=memo, number=chk,
                        reconcile_flag_val=reconcile_flag(stat))

        # Category / transfer splits (one per Moneydance split line)
        for j, sp in enumerate(splits):
            sp_kmm_id = (kmm_acct_id(sp['acctid'])
                         if sp['acctid'] in real_accounts
                         else 'AStd::Expense')
            neg_pamt  = -sp['pamt']

            if sp['iso'] != parent_iso:
                # Cross-currency: shares in split's currency, value in parent's currency.
                # MD convention: samt > 0 = receiving (buy), samt < 0 = sending (sell).
                # KMyMoney expects the same sign: positive = entering the account.
                sp_shares = to_rational(sp['samt'], sp['dec'])
                sp_value  = to_rational(neg_pamt, parent_dec)
                g         = gcd(abs(sp['samt']), abs(sp['pamt'])) if sp['pamt'] else 1
                sp_price  = (f"{abs(sp['samt'])//g}/{abs(sp['pamt'])//g}"
                             if sp['pamt'] else '1/1')

                # Collect first price for PRICES section
                # price = |pamt| × 10^sp_dec / (|samt| × 10^parent_dec)
                # (converts raw smallest-unit ratio to full-unit price)
                if sp['pamt'] and sp['samt']:
                    num_p = abs(sp['pamt']) * (10 ** sp['dec'])
                    den_p = abs(sp['samt']) * (10 ** parent_dec)
                    g_p   = gcd(num_p, den_p)
                    price_r = f"{num_p//g_p}/{den_p//g_p}"
                    # Determine if security (stock) or currency
                    sp_cid  = next((cid for cid, ci in curr_index.items()
                                    if ci['iso'] == sp['iso']), None)
                    sp_type = curr_index.get(sp_cid, {}).get('type', 'c')
                    if sp_type == 's':
                        if sp['iso'] not in sec_prices:
                            sec_prices[sp['iso']] = (postdate, price_r, parent_iso)
                    else:
                        if sp['iso'] not in curr_prices:
                            curr_prices[sp['iso']] = (postdate, price_r, parent_iso)
            else:
                sp_shares = to_rational(neg_pamt, parent_dec)
                sp_value  = sp_shares
                sp_price  = '1/1'

            sp_memo = sp['desc'] if sp['desc'] and sp['desc'] != desc else memo
            _write_split_el(sp_el, f'S{j+2:04d}', sp_kmm_id,
                            sp_shares, sp_value, price=sp_price, memo=sp_memo)

        written += 1

    txns_el.set('count', str(written))

    # ── Global key-value pairs ────────────────────────────────────────────────
    xml_kvpairs(root, {
        'kmm-baseCurrency':     base_iso,
        'kmm-id':               '{' + str(uuid.uuid4()) + '}',
        'LastModificationDate': datetime.now().astimezone().isoformat(timespec='seconds'),
    })

    # ── SCHEDULES / SECURITIES / CURRENCIES / PRICES / REPORTS / BUDGETS ─────
    xml_sub(root, 'SCHEDULES', count='0')

    # trading_currency[sym] = iso of currency in which the security is priced
    trading_currency = {iso: to_iso for iso, (_, _, to_iso) in sec_prices.items()}

    stock_currs = {cid: c for cid, c in curr_index.items()
                   if c['type'] == 's' and c['name']}
    secs_el = xml_sub(root, 'SECURITIES', count=str(len(stock_currs)))
    for cid, c in sorted(stock_currs.items(), key=lambda x: x[1]['name']):
        sym    = c['iso'] or c['name'][:6].upper()
        eid    = _sec_e_ids.get(cid, sym)
        trade_iso = trading_currency.get(sym, base_iso)
        # Use attrib dict so hyphenated names are preserved correctly
        sec_el = ET.SubElement(secs_el, 'SECURITY', attrib={
            'id': eid, 'name': c['name'], 'symbol': sym,
            'type': '0', 'saf': '1', 'pp': '4',
            'trading-currency': trade_iso,
            'trading-market': '',
            'rounding-method': '7',
        })
        xml_kvpairs(sec_el, {'kmm-online-source': 'Yahoo Finance (Stock)'})

    used_isos = ({curr_index[a.get('currid', '')]['iso']
                  for a in real_accounts.values()
                  if a.get('currid', '') in curr_index
                  and curr_index[a.get('currid', '')]['type'] == 'c'}
                 | {base_iso})
    used_currs = {ci['iso']: ci
                  for ci in curr_index.values()
                  if ci['type'] == 'c' and ci['iso'] in used_isos}

    # Find floatrates source name (alkimia-based) for currency exchange rates
    floatrates_source = next(
        (n.replace('.txt', '') for n in [
            'alkimia-floatrates-com-2025-02-12',
            'floatrates',
        ]), 'alkimia-floatrates-com-2025-02-12'
    )

    currs_el = xml_sub(root, 'CURRENCIES', count=str(len(used_currs)))
    for iso in sorted(used_currs):
        ci  = used_currs[iso]
        scf = 10 ** ci['dec']
        curr_el = ET.SubElement(currs_el, 'CURRENCY', attrib={
            'id': iso, 'name': ci['name'],
            'symbol': ci['prefix'] or ci['suffix'] or iso,
            'type': '3', 'saf': str(scf), 'scf': str(scf),
            'pp': '4', 'rounding-method': '0',
            'ppu': str(scf) if iso == base_iso else '0',
        })
        if iso != base_iso:
            xml_kvpairs(curr_el, {'kmm-online-source': floatrates_source})

    # Build PRICES section.
    # Security prices: from=E-ID to=trading_iso (e.g. E000001→EUR, E000002→USD).
    # Currency prices: KMyMoney expects from=foreign to=base (e.g. USD→EUR).
    # Our curr_prices collected (sp_iso→parent_iso) where price = parent/sp.
    # If sp_iso==base: direction is base→foreign → invert to get foreign→base.
    all_price_pairs = []
    for sym, (dt, price_r, to_iso) in sec_prices.items():
        eid = _sym_to_eid.get(sym, sym)
        all_price_pairs.append((eid, to_iso, dt, price_r))

    for sp_iso, (dt, price_r, parent_iso) in curr_prices.items():
        if sp_iso == base_iso:
            # price_r = base/foreign → invert for foreign→base direction
            n, d = price_r.split('/')
            g = gcd(int(d), int(n))
            inv_price = f"{int(d)//g}/{int(n)//g}"
            all_price_pairs.append((parent_iso, sp_iso, dt, inv_price))
        else:
            all_price_pairs.append((sp_iso, parent_iso, dt, price_r))

    prices_el = xml_sub(root, 'PRICES', count=str(len(all_price_pairs)))
    for from_iso, to_iso, dt, price_r in sorted(all_price_pairs):
        pp_el = ET.SubElement(prices_el, 'PRICEPAIR',
                              attrib={'from': from_iso, 'to': to_iso, 'count': '1'})
        xml_sub(pp_el, 'PRICE', date=dt, price=price_r, source='Transaction')
    xml_sub(root, 'REPORTS', count='0')
    xml_sub(root, 'BUDGETS', count='0')

    print(f"Transactions: {written} written ({len(opening_balances)} opening"
          f" balances), {skipped} skipped")
    print(f"Accounts:     {len(real_accounts)} real + 5 standard")
    print(f"Payees:       {len(payee_id_map)}")

    return root

# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

def write_kmy(xml_root, out_path):
    """Serialise the XML tree and write a gzip-compressed .kmy file."""
    ET.indent(xml_root, space=' ')
    xml_bytes = (
        b'<?xml version="1.0" encoding="utf-8"?>\n'
        b'<!DOCTYPE KMYMONEY-FILE>\n'
        + ET.tostring(xml_root, encoding='unicode').encode('utf-8')
    )
    with gzip.open(out_path, 'wb') as f:
        f.write(xml_bytes)
    print(f"Output:       {out_path} ({os.path.getsize(out_path)//1024} KB)")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Convert a Moneydance .moneydance directory to a KMyMoney .kmy file.')
    parser.add_argument(
        'data_dir', nargs='?',
        default='/nas/commun/Administratif/Finances/MoneydanceData/Comptesv7.moneydance',
        help='Path to the .moneydance directory')
    parser.add_argument(
        'output', nargs='?',
        default='comptesv7.kmy',
        help='Output .kmy file path')
    args = parser.parse_args()

    accounts, currencies, transactions = load_moneydance(args.data_dir)

    curr_index     = build_currency_index(currencies)
    earliest_dates = build_earliest_txn_dates(transactions)
    acct_id_map, payee_id_map = build_id_maps(accounts, transactions)

    xml_root = build_kmy_xml(
        accounts, currencies, transactions,
        acct_id_map, payee_id_map, curr_index, earliest_dates,
    )

    write_kmy(xml_root, args.output)
    print(f"\nOpen with: kmymoney {args.output}")

if __name__ == '__main__':
    main()
