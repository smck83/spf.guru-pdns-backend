#!/usr/bin/env python
# -*- coding: utf-8 -*-
import dns.name
import re
import os
from fastapi import FastAPI
import ipaddress
import json
from typing import Optional, List
from aiocache import Cache
import re
from starlette.concurrency import run_in_threadpool
import ipaddress
UNAUTH_SENTINEL = "v=spf1 ?all"



# ─── Precompile regexes ────────────────────────────────────────
#  IPv4: four octets 0–255, separated by dots
_RE_IPV4 = re.compile(
    r'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$'
)

#  IPv6 nibble-dot: 32 hex digits (0–9, a–f), each separated by a dot (31 dots total)
_RE_IPV6_NIBBLE = re.compile(r'^(?:[0-9A-Fa-f]\.){31}[0-9A-Fa-f]$')
def ensure_dot(s: str) -> str:
    s = s.strip()
    if not s.endswith('.'):
        s += '.'
    return s

SOA_SERIAL = os.environ.get("SOA_SERIAL", "2025080300")
if "ZONE" in os.environ:
    ZONE = os.environ['ZONE'].lower()
else:
    ZONE = 'my.spf.guru'

MY_DOMAINS = set ()
if "MY_DOMAINS" in os.environ: # set for control over domains - Domain Control List (DCL)
    MY_DOMAINS = set(os.environ["MY_DOMAINS"].lower().split())


if 'SPF_MACRO_RECORD' in os.environ:
    SPECIAL_SPF_RECORD = os.environ['SPF_MACRO_RECORD']
else:
    SPECIAL_SPF_RECORD = "i.%{ir}._d.%{d}." + ZONE
print("SPECIAL_SPF_RECORD:",SPECIAL_SPF_RECORD)

FSPECIAL_SPF_RECORD = "f.%{ir}._d.%{d}." + ZONE
SPF_RECORD_MODE = int(os.environ.get('SPF_RECORD_MODE', 0))


if "SOA_HOSTMASTER" in os.environ:
    SOA_HOSTMASTER = os.environ['SOA_HOSTMASTER'].lower().replace('@','.')
    SOA_HOSTMASTER = ensure_dot(SOA_HOSTMASTER)
else:
    SOA_HOSTMASTER = f"hostmaster@example.com."

SOA_SERIAL = os.environ.get("SOA_SERIAL", "2025080300")
ZONE = ensure_dot(ZONE)

if "NS_RECORDS" in os.environ:
    NS_RECORDS = os.environ['NS_RECORDS'].lower().split()
    NS_RECORD = ensure_dot(NS_RECORDS[0])
else:
    NS_RECORDS = []
    NS_RECORD = ensure_dot("ns-" + ZONE)
    NS_RECORDS.append(NS_RECORD)

# compile once
# VENDOR_PATTERN = {d}._i.%{ir}.my.spf.guru.
VENDOR_PATTERN = r'^(([a-zA-Z0-9\-_]{1,63}\.){1,5}[a-zA-Z0-9\-_]{2,24}\.)_([izf])\.(([\d]{1,3}.){3}\d{1,3}|([\da-fA-F]{1}\.){31}[\da-fA-F]{1})\.(' + ZONE + ')$'
VENDOR_REGEX = re.compile(VENDOR_PATTERN, re.IGNORECASE | re.VERBOSE)

# MIMECAST_PATTERN = {d}._i.%{ir}.my.spf.guru.
MIMECAST_PATTERN = r'^([a-z\d]{8}\.)_([izf])\.(([\d]{1,3}.){3}\d{1,3}|([\da-fA-F]{1}\.){31}[\da-fA-F]{1})\.(' + ZONE + ')$'
MIMECAST_REGEX = re.compile(MIMECAST_PATTERN, re.IGNORECASE | re.VERBOSE)

# D_PATTERN = i.{ir}._d.%{d}.my.spf.guru.
D_PATTERN = r'^[ifz]\.(([\d]{1,3}\.){3}\d{1,3}|([\da-fA-F]{1}\.){31}[\da-fA-F]{1})\._d\.(([a-zA-Z0-9.\-_]{1,255})\.([a-zA-Z0-9.\-_]{2,255}))\.(' + ZONE + ')$'
D_REGEX = re.compile(D_PATTERN, re.IGNORECASE | re.VERBOSE)

# RBLDNSD_PATTERN = %{ir}.%{d}.my.spf.guru.
RBLDNSD_PATTERN = r'^(((\d{1,3}\.){3}\d{1,3})|(([\da-fA-F]{1}\.){31}[\da-fA-F]{1}))\.(([a-zA-Z0-9\-_]{2,63}\.){1,5}[a-zA-Z0-9\-_]{2,24})\.(' + ZONE + ')$'
RBLDNSD_REGEX = re.compile(RBLDNSD_PATTERN, re.IGNORECASE | re.VERBOSE)



def dot2std(ptr: str) -> str:
    # handle optional PTR suffixes
    s = ptr.removesuffix('.').removesuffix('ip6.arpa').removesuffix('.')
    parts = s.split('.')
    if len(parts) != 32 or any(len(p) != 1 for p in parts):
        raise ValueError("Expect 32 dot-separated hex nibbles (optionally ending with .ip6.arpa.)")
    # validate hex and build hex string in correct order
    # (reversing *nibbles*, not characters)
    for p in parts:
        if p not in '0123456789abcdefABCDEF':
            raise ValueError(f"Invalid hex nibble: {p!r}")
    hexstr = ''.join(reversed(parts))
    # build IPv6Address and return compressed form
    return str(ipaddress.IPv6Address(int(hexstr, 16)))

def sanitize_spf_record(spf_record: str) -> str:

    #print("Sanitizing SPF Record")
    tokens: List[str] = spf_record.split()
    prefixes = ("include", "exists")

    # build the exact strings you want to strip out
    to_strip = {f"{p}:{SPECIAL_SPF_RECORD}" for p in prefixes}
    fto_strip = {f"~{p}:{FSPECIAL_SPF_RECORD}" for p in prefixes}
   
    if any(tok in fto_strip for tok in tokens):
        # Remove any include: or exists: token for the special record
        tokens = [tok for tok in tokens if tok not in fto_strip]
        

    if any(tok in to_strip for tok in tokens):
        # Remove any include: or exists: token for the special record
        filtered = [tok for tok in tokens if tok not in to_strip]
        return " ".join(filtered)
    else:
        # No EHLO include found → hard‑fail
        return UNAUTH_SENTINEL

def get_spf_record(domain: str, timeout: float = 4.0) -> Optional[str]:
    """
    Retrieve the SPF record (TXT) for the given domain.
    
    Args:
        domain: The domain to query (e.g. "example.com").
        timeout: How many seconds to wait for the DNS resolver before giving up.
        
    Returns:
        The SPF string (starting with "v=spf1 ") if found, otherwise None.
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(domain, 'TXT')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return None

    for txt_rec in answers:
        # Each txt_rec.strings is a list of byte-strings; join and decode them:
        spf = ''.join(part.decode('utf-8') for part in txt_rec.strings)
        if spf.startswith('v=spf1 '):
            return spf

    return None
    """

def dotCount(s:str) -> int:
    if _RE_IPV4.match(s):
        return 4
    if _RE_IPV6_NIBBLE.match(s):
        return 6
    return 0

def isIPv6(input_string):
    # Count the number of dots in the input string using the count() method.
    # Check if the count is equal to 31.
    #pattern=r'^([\da-fA-F]\.){31}([\da-fA-F])$' # match dot version of ip6 address
    # pattern=r'([\dabcdef]\.){31}'
    match = _RE_IPV6_NIBBLE.fullmatch(input_string)
    #match = re.search(pattern, input_string, re.IGNORECASE)
    if match:
        try:
            result = str(ipaddress.ip_address(dot2std(input_string)))
        except:
            print("Invalid IPv6 address")
            return False
        
        else:

            #print("Returning IPv6:",result)
            return result
    else:
        return False

def reverseIt(ip):
    # pdns auth sends many lookups for 1 request. In an effort to handle these redundant lookups more efficiently, the IP is reversed
    # this means %{ir} needs to be used in the spf record, instead of %{i}
    
    result = ip.split('.') # split into a list
    result.reverse() #put my thing down, flip it, and reverse it - ir becomes i 
    result = str('.'.join(result)) # convert back to string with . in between chars
    return result

def isIPv4(input_string):
    # Count the number of dots in the input string using the count() method.
    # pattern=r'(?:\b|^)((?:(?:(?:\d)|(?:\d{2})|(?:1\d{2})|(?:2[0-4]\d)|(?:25[0-5]))\.){3}(?:(?:(?:\d)|(?:\d{2})|(?:1\d{2})|(?:2[0-4]\d)|(?:25[0-5]))))(?:\b|$)' # match dot version of ip6 address
    # pattern=r'([\dabcdef]\.){31}'
   
    match = _RE_IPV4.fullmatch(input_string)
    #match = re.search(pattern, input_string, re.IGNORECASE)
    if match:
    # Check if the count is equal to 31.
        try:
            result = str(ipaddress.ip_address(input_string))
        except:
            print("Invalid ip4 address")
            return False
        
        else:
            result = reverseIt(result)
            return result
    else:
        print("Invalid ip4 address")
        return False

async def extract_info(input_string):
    match = vendormatch = rbldnsdmatch = mimecastmatch = None
    if not input_string:
        return match, vendormatch, rbldnsdmatch, mimecastmatch

    mode = SPF_RECORD_MODE
    firsttwo = input_string[:2]
    firsteight = input_string[:8] 
    has_dotunderscore_at_nine_ten = "._" in input_string[8:10]

    has_d = "._d." in input_string
    has_i = "._i." in input_string
    has_f = "._f." in input_string
    has_z = "._z." in input_string
    

    D_full = D_REGEX.fullmatch
    V_full = VENDOR_REGEX.fullmatch
    R_full = RBLDNSD_REGEX.fullmatch
    M_full = MIMECAST_REGEX.fullmatch

    if firsttwo in {"i.", "z.", "f."} and has_d and mode == 0:
        match = D_full(input_string)  # i.%{ir}._d.%{d}.my.spf.guru.
    elif "." not in firsteight and has_dotunderscore_at_nine_ten and (has_i or has_z or has_f) and mode == 0:
        mimecastmatch = M_full(input_string)  # <8-id>._i.%{ir}.my.spf.guru.
    elif (has_i or has_z or has_f) and mode == 0:
        vendormatch = V_full(input_string)  # %{d}._i.%{ir}.my.spf.guru.
    elif mode ==1:
        rbldnsdmatch = R_full(input_string)  # %{ir}.%{d}.my.spf.guru.
    else:
        return False
    
    check4fail = False
    if match: 
        if input_string[0].lower() == "f" or input_string[0].lower() == "z":
            check4fail = True
        ipAddress = match.group(1)
        domain = match.group(4)
        zone = match.group(7)    
    elif vendormatch:   
        if vendormatch.group(3).lower() == "f" or vendormatch.group(3).lower() == "z":
            check4fail = True
        ipAddress = vendormatch.group(4)
        domain = vendormatch.group(1)
        zone = vendormatch.group(7)
    elif mimecastmatch:   
        if mimecastmatch.group(2).lower() == "f" or mimecastmatch.group(2).lower() == "z":
            check4fail = True
        ipAddress = mimecastmatch.group(3)
        domain = mimecastmatch.group(1) + "_spf._d.mim.ec."
        zone = mimecastmatch.group(6)
    elif rbldnsdmatch:   
        ipAddress = rbldnsdmatch.group(2) or rbldnsdmatch.group(4) # ip4 or ip6
        domain = rbldnsdmatch.group(6)
        zone = rbldnsdmatch.group(8)
    else:
        return False
    if MY_DOMAINS and domain not in MY_DOMAINS: # domain control list 
        return False   

    ipVersion = dotCount(ipAddress)   
    if ipVersion == 4:
        IP = isIPv4(ipAddress)
    elif ipVersion == 6:
        IP = isIPv6(ipAddress)
    else:
        return False

        
    out = {"ipAddress": IP,
            "domain": domain,
            "zone": zone,
            "ipVersion": ipVersion,
            #"intputDomain": domain,
            "failCheck":check4fail}
    return out

def returnSOA(qname,auth=True):
    soa_serial = os.environ.get("SOA_SERIAL", "2025080223")
    output = [
        { "qname"     : qname,
            "qtype"     : "SOA",
            "content"   : f"{ensure_dot(NS_RECORD)} {ensure_dot(SOA_HOSTMASTER)} {soa_serial} 1800 900 1209600 120",
            "ttl"       : 3600,
            "auth"     : auth }]
    return output

def returnNS(qname: str):
    """Return a list of NS record dicts for a given qname."""
    output = []
    for ns in NS_RECORDS:
        output.append({
            "qname": ensure_dot(qname.lower()),
            "qtype": "NS",
            "content": ensure_dot(ns),
            "ttl": 3600,
            "auth": True
        })
    return output

if __name__ == "__main__":
    print(extract_info("i.167.67.89.167._d.toomany.spf.guru.my.spf.guru."))
    print(extract_info("f.167.67.89.167._d.toomany.spf.guru.my.spf.guru."))
