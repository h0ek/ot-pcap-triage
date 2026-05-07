from __future__ import annotations
import hashlib, ipaddress, re
from pathlib import Path

def sha256_file(path: Path, chunk_size: int = 1024*1024) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()

def safe_int(v, default=0):
    try: return int(float(v)) if v not in (None,'') else default
    except Exception: return default

def safe_float(v, default=0.0):
    try: return float(v) if v not in (None,'') else default
    except Exception: return default

def first_nonempty(*vals):
    for v in vals:
        if v: return v
    return ''

def is_public_ip(v):
    if not v: return False
    try:
        ip=ipaddress.ip_address(v)
        return ip.version==4 and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except Exception:
        return False

def redact(v):
    if v is None: return ''
    v=str(v)
    if not v: return ''
    if len(v)<=4: return 'REDACTED'
    if len(v)<=8: return v[0]+'*'*(len(v)-2)+v[-1]
    return v[:4]+'*'*max(4,len(v)-8)+v[-4:]

def normalize_protocol_name(v):
    return re.sub(r'[^a-z0-9_./+-]+','_', (v or 'unknown').strip().lower())
