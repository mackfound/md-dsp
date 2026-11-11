#!/usr/bin/env python3
# ppid_map.py: read runs/<name>/quote.bin and write ppid_map.csv
# (name, instance_id, ppid, platform_instance_id, fmspc).
# The values come from the SGX extension of the PCK leaf certificate inside each quote.
# Signatures are not verified.
#   pip install cryptography
#   python3 ppid_map.py runs data/tdx_cycles_10_28_raw.csv > data/ppid_map.csv
import csv, glob, os, re, sys
from cryptography import x509

SGX = "1.2.840.113741.1.13.1"
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)

def tlv(b, i):
    t, l = b[i], b[i + 1]; i += 2
    if l & 0x80:
        n = l & 0x7F; l = int.from_bytes(b[i:i + n], "big"); i += n
    return t, b[i:i + l], i + l

def oid(o):
    out, x = [o[0] // 40, o[0] % 40], 0
    for c in o[1:]:
        x = (x << 7) | (c & 0x7F)
        if not c & 0x80: out.append(x); x = 0
    return ".".join(map(str, out))

def sgx_fields(der, out):
    i = 0
    while i < len(der):
        t, v, i = tlv(der, i)
        if t != 0x30: continue
        t1, o, j = tlv(v, 0)
        if t1 != 0x06: sgx_fields(v, out); continue
        t2, val, _ = tlv(v, j)
        if t2 == 0x30: sgx_fields(val, out)
        else: out[oid(o)] = val
    return out

def fields(path):
    pems = PEM.findall(open(path, "rb").read())
    if not pems: return None
    leaf = x509.load_pem_x509_certificate(pems[0])
    f = sgx_fields(leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(SGX)).value.value, {})
    return [f.get(SGX + s, b"").hex() for s in (".1", ".6", ".4")]

runs, csvp = sys.argv[1], sys.argv[2]
iid = {r["name"]: r["instance_id"] for r in csv.DictReader(open(csvp))}
w = csv.writer(sys.stdout)
w.writerow(["name", "instance_id", "ppid", "platform_instance_id", "fmspc"])
for q in sorted(glob.glob(os.path.join(runs, "*", "quote.bin"))):
    name = os.path.basename(os.path.dirname(q))
    f = fields(q)
    if f is None: print(f"no cert chain: {q}", file=sys.stderr); continue
    w.writerow([name, iid.get(name, "-"), *f])
missing = set(iid) - {os.path.basename(os.path.dirname(q)) for q in glob.glob(os.path.join(runs, "*", "quote.bin"))}
for m in sorted(missing): print(f"in CSV, no quote.bin: {m}", file=sys.stderr)
