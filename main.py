# main.py
import ipaddress
import hashlib
from typing import Dict, List, Tuple
import json
import asyncio
from fastapi import FastAPI, HTTPException
import dns.asyncresolver
import dns.exception
import spfGuruBackend
import os
import re
import random
import sys
import dbInsert
in_flight: dict[str, asyncio.Future] = {}
app = FastAPI()
resolver = dns.asyncresolver.Resolver()
useRedis = False

ZONE_BASE = "zen.spf.guru"          
TXT_SEG_LIMIT = 500                   # per-string limit
SPF_PREFIX = "v=spf1"
SPF_SUFFIX = " ~all"
MAX_CHAIN = 9

if 'REDIS_PORT' in os.environ:
    redisport = int(os.environ['REDIS_PORT'])
else:
    redisport = 6379

if 'SOURCE_PREFIX' in os.environ:
    SOURCE_PREFIX = str(os.environ['SOURCE_PREFIX'])
else:
    SOURCE_PREFIX = None

if 'REDIS_IP' in os.environ:
    import redis.asyncio as aioredis
    redisip = os.environ['REDIS_IP']
    useRedis = True

ZONE = spfGuruBackend.ZONE

DEFAULT_TTL = 14400

if useRedis:
    cache = aioredis.from_url(
        f"redis://{redisip}:{redisport}/0",
        encoding="utf-8",
        decode_responses=True
    )
else:
    # Fallback to in-memory async cache with TTL
    from aiocache import Cache
    # Simple memory backend
    cache = Cache(Cache.MEMORY)

async def output_log(message):
    sys.stdout.write(f"{message}\n") # Add '\n' manually sys.stdout.flush() # Optional for immediate output
    #sys.stdout.flush()

async def cache_set(key: str, value: str, ttl: int, log: bool = False):
    if useRedis:
        # redis.asyncio accepts `ex=` (seconds)
        await cache.set(key, value, ex=ttl)
    else:
        # aiocache MEMORY backend accepts `ttl=` (seconds)
        await cache.set(key, value, ttl=ttl)
    if log:
        await output_log(f"{key} added to cache.")
async def cache_get(key: str):
        return await cache.get(key)
def _id_base(domain: str, *_unused) -> str:
    """
    Stable ID based ONLY on the domain (case-insensitive, trailing dot ignored).
    This keeps labels constant even if IPs/macros change.
    """
    norm = domain.rstrip(".").lower().encode("utf-8")
    return hashlib.sha1(norm).hexdigest()[:8]   # short and stable (e.g. '78eeb932')

def _normalise_and_sort(ips: List[str]) -> List[str]:
    """
    Convert IPs/CIDRs into 'ip4:'/'ip6:' mechanisms, sorted:
    IPv4 first then IPv6, by network address then prefix length.
    Bare addresses become /32 (v4) or /128 (v6).
    """
    nets: List[Tuple[int, ipaddress._BaseNetwork]] = []
    for raw in ips or []:
        s = (raw or "").strip()
        if not s:
            continue
        try:
            if "/" in s:
                net = ipaddress.ip_network(s, strict=False)
            else:
                ip = ipaddress.ip_address(s)
                net = ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}", strict=False)
            nets.append((net.version, net))
        except ValueError:
            continue

    nets.sort(key=lambda t: (t[0], int(t[1].network_address), t[1].prefixlen))
    return [f"ip{fam}:{net.with_prefixlen}" for fam, net in nets]

def _calc_capacity(include_token: str = "") -> int:
    """
    How many characters we can spend on tokens in this TXT segment,
    after accounting for prefix, suffix, and optional include token.
    """
    base_len = len(SPF_PREFIX)     # 'v=spf1'
    suffix_len = len(SPF_SUFFIX)   # ' ~all'
    include_len = (1 + len(include_token)) if include_token else 0
    return TXT_SEG_LIMIT - base_len - suffix_len - include_len

def _tokens_len_with_spaces(tokens: List[str]) -> int:
    """Length of tokens joined with single spaces (no prefix/suffix)."""
    if not tokens:
        return 0
    return sum(len(t) for t in tokens) + (len(tokens) - 1)

def _pack_chunks(tokens: List[str], idbase: str, macros: List[str]) -> Dict[str, str]:
    """
    Pack mechanisms into multiple TXT records (≤255 chars each).
    Chain via include:<id>-<n+1>.<ZONE_BASE>. End each with ' ~all'.
    Returns { "<id>-0.ZONE_BASE": "v=spf1 ... ~all", ... }.
    """
    queue: List[str] = list(tokens or []) + list(macros or [])
    records: Dict[str, str] = {}

    # Pre-check: any single (non-include) token too long to ever fit?
    for tok in queue:
        if len(SPF_PREFIX) + 1 + len(tok) + len(SPF_SUFFIX) > TXT_SEG_LIMIT:
            raise ValueError(f"Single SPF token too long to fit in one TXT string: {tok}")

    part = 0
    while queue:
        label = f"{idbase}-{part}.{ZONE_BASE}"

        # Assume there WILL be another record if more than one token remains,
        # so we reserve space for include from the start.
        more_after_this = len(queue) > 1
        include_token = f"include:{idbase}-{part+1}.{ZONE_BASE}" if more_after_this else ""
        capacity = _calc_capacity(include_token if more_after_this else "")

        current_tokens: List[str] = []
        used_len = 0

        # Greedily pack tokens into available capacity
        while queue:
            candidate = queue[0]
            extra_space = 1 if current_tokens else 0
            if used_len + extra_space + len(candidate) <= capacity:
                current_tokens.append(candidate)
                used_len += extra_space + len(candidate)
                queue.pop(0)
            else:
                break

        # If there are still tokens left, we MUST add include to point to the next label
        if queue:
            if not include_token:
                include_token = f"include:{idbase}-{part+1}.{ZONE_BASE}"

            # If an include-only record cannot fit, that's a config problem (zone/label too long)
            only_include_len = len(SPF_PREFIX) + 1 + len(include_token) + len(SPF_SUFFIX)
            if only_include_len > TXT_SEG_LIMIT:
                raise ValueError(
                    "Include label too long to fit in one TXT string. "
                    f"Length={only_include_len} > {TXT_SEG_LIMIT}. "
                    "Shorten ZONE_BASE or the ID length."
                )

            # Ensure include fits: if not, push tokens to next record
            capacity_with_include = _calc_capacity(include_token)
            while _tokens_len_with_spaces(current_tokens) > capacity_with_include and current_tokens:
                queue.insert(0, current_tokens.pop())

            # If nothing fits alongside include, emit include-only
            if not current_tokens:
                current_tokens = [include_token]
            else:
                # Double-check include fits beside current tokens
                if _tokens_len_with_spaces(current_tokens) + 1 + len(include_token) > capacity_with_include:
                    # Push one more token if needed
                    if current_tokens:
                        queue.insert(0, current_tokens.pop())
                    if not current_tokens:
                        current_tokens = [include_token]
                    else:
                        current_tokens.append(include_token)
                else:
                    current_tokens.append(include_token)

        # Build value
        value = f"{SPF_PREFIX}"
        if current_tokens:
            value += " " + " ".join(current_tokens)
        value += SPF_SUFFIX

        if len(value) > TXT_SEG_LIMIT:
            raise ValueError("Internal packing error: TXT exceeded 255 characters.")

        records[label] = value
        part += 1

    return records

async def build_spf_chain(domain: str) -> Dict[str, Dict[str, str]]:
    """
    Uses your cache + extractor, returns:
    { "expandedRecords": { "<id>-0.zen.spf.guru": "v=spf1 ... ~all", ... } }
    """
    d = domain.rstrip(".").lower()
    cache_key = f"spf:{d}"

    # Pull from your cache/extractor
    if cached := await cache_get(cache_key):
        payload = json.loads(cached)
    else:
        await output_log(f"{cache_key} not in cache")
        ips, macros, ttls, invalid_addr = await extract_spf(d, set())
        positive_ttls = [t for t in ttls if t > 0]
        base_ttl = min(positive_ttls) if positive_ttls else 0
        effective_ttl = max(base_ttl, DEFAULT_TTL)
        payload = {"domain": domain, "ips": ips, "macroRecords": macros, "invalidAddr": invalid_addr}
        await cache_set(cache_key, json.dumps(payload), effective_ttl, True)

    tokens = _normalise_and_sort(payload.get("ips", []))
    macros = payload.get("macroRecords", []) or []
    idbase = _id_base(d)  # <-- domain-only ID

    records = _pack_chunks(tokens, idbase, macros)
    hash = canonical_hash(records)
    return {"hash": hash,"expandedRecords": records}

IDX_RE = re.compile(rf"^(?P<prefix>.+?)-(?P<idx>\d+)\.{re.escape(ZONE_BASE)}\.?$", re.IGNORECASE)

def _idx_of(label: str) -> Tuple[str, int]:
    m = IDX_RE.match(label)
    if not m:
        # fallback: put unknowns at the end, stable sort by label
        return (label, 1_000_000)
    return (m.group("prefix"), int(m.group("idx")))

def canonical_hash(expanded: Dict[str, str]) -> str:
    # Normalise values: collapse whitespace, (optionally lower-case)
    norm = {k: re.sub(r"\s+", " ", v.strip()) for k, v in expanded.items()}
    # Order deterministically by numeric -N suffix
    items = sorted(norm.items(), key=lambda kv: _idx_of(kv[0])[1])
    # Enforce MAX_CHAIN (same policy your writer/enforcer uses)
    items = items[:MAX_CHAIN]
    # Serialise deterministically
    blob = json.dumps(dict(items), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def returnBanner(specificResult):
    """
    Return a fortune-telling–style SPF banner based on the specificResult ('PASS' or 'FAIL').

    Args:
        specificResult (str): The SPF result, e.g., 'PASS' or 'FAIL'.

    Returns:
        str: A randomly selected mystical banner with the result interpolated.
    """
    pass_banners = [
        "The SPF Guru's tarot reveals '{result}' as The Star - hope guides this message.",
        "The SPF Guru's crystal whispers '{result}' into the ethers of deliverability.",
        "From the Guru's cards emerges '{result}' beneath The Sun - clarity shines.",
        "The SPF Guru's I Ching hexagram speaks '{result}' - harmony blesses this mail.",
        "The Guru's pendulum swings to '{result}' - fate smiles upon your e-mail.",
        "Runes inscribed by the SPF Guru etch '{result}' on the scroll of destiny.",
        "Under the Guru's moonlight gaze, '{result}' unfolds - intuition vindicates.",
        "Tea leaves read by the Guru form the symbol '{result}' - prophecy confirmed.",
        "The Guru's astrolabe charts a path marked '{result}' - cosmic winds align.",
        "In the Guru's scrying pool, '{result}' shimmers - mystical forces decree."
    ]

    fail_banners = [
        "The SPF Guru's tarot reveals '{result}' as The Tower - caution beckons.",
        "The Guru's crystal cracks with '{result}' - obstacles guard this mail.",
        "From the cards emerges '{result}' under The Moon - shadows heed your caution.",
        "The SPF Guru's I Ching hexagram speaks '{result}' - discord stirs the realm.",
        "The Guru's pendulum swings to '{result}' - fate warns of blocked passage.",
        "Runes inscribed by the SPF Guru carve '{result}' into the dark scroll.",
        "Under the Guru's moonlit scrutiny, '{result}' collapses - intuition urges retreat.",
        "Tea leaves read by the Guru form the omen '{result}' - prophecy halts deliverability.",
        "The Guru's astrolabe indicates '{result}' - cosmic currents oppose this mail.",
        "In the Guru's scrying pool, '{result}' darkens - mystical forces decree rebuke."
    ]

    key = specificResult.strip().upper()
    if key == "PASS":
        return random.choice(pass_banners).format(result=specificResult)
    else:
        return random.choice(fail_banners).format(result=specificResult)



def ip_version(addr: str) -> int:
    """
    Given a string IP address, return 4 if it’s IPv4, 6 if it’s IPv6.
    Raises ValueError on invalid input.
    """
    return ipaddress.ip_address(addr).version

async def get_or_compute_spf(domain: str):
    cache_key = f"spf:{domain}"

    # 1) Try cache normally
    if cached := await cache_get(cache_key):
        return json.loads(cached)

    # 2) In-flight protection
    if domain in in_flight:
        return await in_flight[domain]  # wait for first request’s result

    # 3) We are the first ⇒ create a shared future and store it
    fut = asyncio.get_running_loop().create_future()
    #fut = asyncio.get_event_loop().create_future()
    in_flight[domain] = fut

    try:
        # Perform extraction
        ips, macros, ttls, invalid_addr = await extract_spf(domain, set())
        positive_ttls = [t for t in ttls if t > 0]
        base_ttl = min(positive_ttls) if positive_ttls else 0
        effective_ttl = max(base_ttl, DEFAULT_TTL)
        result = {
            "domain": domain,
            "ips": ips,
            "macroRecords": macros,
            "invalidAddr": invalid_addr
        }
        
        # Write to cache
        await cache_set(cache_key, json.dumps(result), effective_ttl, log=True)
        
        # Resolve the future for any waiters
        fut.set_result(result)
        return result

    except Exception as e:
        fut.set_exception(e)
        raise

    finally:
        # cleanup: ensure future is removed after completion
        in_flight.pop(domain, None)

async def get_txt_records(domain: str) -> tuple[list[str], int]:
    """
    Returns (list of full TXT strings, ttl).
    Joins any <255-char> segments into their logical whole.
    """
    try:
        answer = await resolver.resolve(domain, "TXT")
        full_texts: list[str] = []

        for rdata in answer:
            joined = b"".join(rdata.strings).decode("utf-8")
            full_texts.append(joined)

        return full_texts, answer.rrset.ttl

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return [], 0


async def resolve_a(hostname: str) -> tuple[list[str], int]:
    try:
        ans = await resolver.resolve(hostname, "A")
        return [r.address for r in ans], ans.rrset.ttl
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return [], 0


async def resolve_aaaa(hostname: str) -> tuple[list[str], int]:
    try:
        ans = await resolver.resolve(hostname, "AAAA")
        return [r.address for r in ans], ans.rrset.ttl
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return [], 0

async def get_mx_ips(mx_domain: str) -> tuple[list[str], list[int]]:
    ips: list[str] = []
    ttls: list[int] = []

    try:
        mx_ans = await resolver.resolve(mx_domain, "MX")
        ttls.append(mx_ans.rrset.ttl)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return ips, ttls

    tasks = []
    for r in mx_ans:
        exch = r.exchange.to_text().rstrip(".")
        tasks.append(asyncio.create_task(resolve_a(exch)))
        tasks.append(asyncio.create_task(resolve_aaaa(exch)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, Exception):
            continue
        sub_ips, sub_ttl = res
        ips.extend(sub_ips)
        if sub_ttl:
            ttls.append(sub_ttl)

    return ips, ttls


async def extract_spf(
    domain: str,
    seen: set[str],
) -> tuple[list[str], list[str], list[int], list[str]]:
    """
    Returns: (ips, macro_mechanisms, all_ttls_seen, invalid_ips)
    """
    if domain in seen:
        return [], [], [], []
    seen.add(domain)

    txts, txt_ttl = await get_txt_records(domain)
    spfs = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spfs:
        return [], [], [], []

    ips: list[str] = []
    macros: list[str] = []
    includes: list[str] = []
    all_ttls: list[int] = []
    invalid_ips: list[str] = []

    if txt_ttl:
        all_ttls.append(txt_ttl)

    mx_tasks: list[asyncio.Task] = []
    a_tasks: list[asyncio.Task] = []

    for spf in spfs:
        for mech in spf.split()[1:]:
            mech_clean = mech.lstrip('+-~?')  # handle qualifiers
            mech_l = mech_clean.lower()
            zone_l = ZONE.rstrip('.').lower()

            # --- MACROS: don't add to recurse
            if "%{" in mech_clean:
                if zone_l in mech_l:
                    # These are spf guru macro tokens.
                    # Ignore
                    continue
                else:
                    fixup_macros = mech.replace("%{d}", "%{o}")
                    macros.append(fixup_macros)  # keep original casing
                    continue

            # --- ip4/ip6 with validation
            if mech_l.startswith(("ip4:", "ip6:")):
                _, net = mech_clean.split(":", 1)
                try:
                    if mech_l.startswith("ip4:"):
                        ipaddress.IPv4Network(net)
                    else:
                        ipaddress.IPv6Network(net)
                    ips.append(net)
                except ValueError:
                    invalid_ips.append(net)
                continue

            # --- A / MX (optionally with domain)
            if mech_l == "a" or mech_l.startswith("a:"):
                a_dom = domain if mech_clean == "a" else mech_clean.split(":", 1)[1]
                a_tasks.append(asyncio.create_task(resolve_a(a_dom)))
                a_tasks.append(asyncio.create_task(resolve_aaaa(a_dom)))
                continue

            if mech_l == "mx" or mech_l.startswith("mx:"):
                mx_dom = domain if mech_clean == "mx" else mech_clean.split(":", 1)[1]
                mx_tasks.append(asyncio.create_task(get_mx_ips(mx_dom)))
                continue

            # --- include / redirect (only static)
            if mech_l.startswith("include:") and "%{" not in mech_clean:
                includes.append(mech_clean.split(":", 1)[1])
                continue

            if mech_l.startswith("redirect=") and "%{" not in mech_clean:
                includes.append(mech_clean.split("=", 1)[1])
                continue

            # --- exists:/ptr and leftovers (non-flattenable but no macros)
            if mech_l.startswith("exists:") or mech_l.startswith("ptr"):
                # Up to you: either track as non-flattenable or mark invalids
                invalid_ips.append(mech)  # or non_flattenable.append(mech)
                continue

            # all/~all/?all: nothing to collect
            if mech_l.endswith("all"):
                continue

            # invalid
            invalid_ips.append(mech)
    # process MX tasks
    if mx_tasks:
        mx_results = await asyncio.gather(*mx_tasks, return_exceptions=True)
        for res in mx_results:
            if isinstance(res, Exception):
                continue
            sub_ips, sub_ttls = res
            ips.extend(sub_ips)
            all_ttls.extend(t for t in sub_ttls if t)

    # process A/AAAA tasks
    if a_tasks:
        a_results = await asyncio.gather(*a_tasks, return_exceptions=True)
        for res in a_results:
            if isinstance(res, Exception):
                continue
            sub_ips, sub_ttl = res
            ips.extend(sub_ips)
            if sub_ttl:
                all_ttls.append(sub_ttl)

    # recurse includes
    for inc in includes:
        sub_ips, sub_macros, sub_ttls, sub_invalids = await extract_spf(inc, seen)
        ips.extend(sub_ips)
        macros.extend(sub_macros)
        all_ttls.extend(t for t in sub_ttls if t)
        invalid_ips.extend(sub_invalids)

    return list(set(ips)), macros, all_ttls, invalid_ips

@app.get("/spf/{domain}")
async def get_spf(domain: str):
    d = domain.rstrip(".").lower()
    return await get_or_compute_spf(d)


@app.get("/spfCheck/{domain}/{ipAddress}")
async def spf_check(domain: str, ipAddress: str):
    # try cache
    if cachedSPFResult := await cache_get(f"spf-result:{domain}-{ipAddress}"):
        cachedSPFResult = json.loads(cachedSPFResult)
        cachedSPFResult["cached"] = True
        return cachedSPFResult
    
    # 1) call get_spf() – it will hit Redis if cached, or do a fresh DNS walk + cache if not
    try:
        spf_data = await get_spf(domain)
    except HTTPException as e:
        # pass through the 404 from get_spf → domain has no SPF
        raise

    ips    = spf_data["ips"]
    macros = spf_data.get("macroRecords", [])

    # 2) validate the IP
    try:
        ip_obj = ipaddress.ip_address(ipAddress)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ipAddress}")

    # 3) check membership
    networks = []
    for net in ips:
        try:
            networks.append(ipaddress.ip_network(net))
        except ValueError:
            continue



    allowed = any(ip_obj in n for n in networks)
    #print("fresh SPF result")
    # 4) build response, include macros on fail
    resp = {"domain": domain, "ip": ipAddress, "pass": allowed}

    # 5) spf guru magic happens
#    if allowed:
    resp["spfPassResponse"] = f"v=spf1 ip{ip_version(ipAddress)}:{ipAddress} ~all"
    if len(macros) > 0:
        resp["spfFailResponse"] = f"v=spf1 " + " ".join(macros[:MAX_CHAIN]) + " ~all"
    else:
        resp["spfFailResponse"] = f"v=spf1 ~all"
    await cache_set(f"spf-result:{domain}-{ipAddress}", json.dumps(resp), DEFAULT_TTL,False)
    result_label = "pass" if allowed else "fail"
    if dbInsert.DB_URL and dbInsert.DB_TOKEN:
        try:      
            await dbInsert.log_spf_result(domain, ipAddress, result_label, ip_version(ipAddress))

        except Exception as e:
            print(e)
    else:
        pass
    resp["cached"] = False
    return resp

## Add spfGuruBackend. before all failing functions
@app.get("/lookup/{qname}/{qtype}")
async def lookup(qname, qtype):
    """    
    if qname == ZONE and (qtype == "NS"):
        return {"result": [returnNS(qname)]}
    if qname == ZONE and (qtype == "SOA"):
        return {"result": [returnSOA(qname)]}
    """
    qname = qname.lower() # normalize

    try: 
        info = await spfGuruBackend.extract_info(qname)
    except Exception as e:
        print(e)
        info = False
 
    responses = []
      
    if info == False: 
        if ZONE.lower() == qname.lower():
            if (qtype == "ANY" or qtype =="NS"):
                responses.extend(spfGuruBackend.returnNS(ZONE))
            if (qtype == "ANY" or qtype =="SOA"):
                responses.extend(spfGuruBackend.returnSOA(ZONE))
        return {"result": responses}


    z = dns.name.from_text(ZONE)
    n = dns.name.from_text(qname)
    query = n - z
    querystring = query.to_text()

    if info != False and querystring != '@' and (qtype == 'TXT' or qtype == 'ANY'):
        if len(spfGuruBackend.MY_DOMAINS) > 0 and SOURCE_PREFIX: 
            domainPart = SOURCE_PREFIX + "." + info["domain"]
        else:
            domainPart = info["domain"]
        ipPart = info["ipAddress"]
        checkForFail = info["failCheck"]
        
        try:
            #print(domainPart,ipPart)
            spfOutput = await spf_check(domainPart,ipPart)

            
        except Exception as e:
            print("Error:",e)
        else:
            if spfOutput['pass'] == True: 
                responseBanner = returnBanner("PASS")
            else:
                responseBanner = returnBanner("FAIL")
            if checkForFail == True:
                if spfOutput['pass'] == False:     
                    content = spfOutput["spfPassResponse"]
                    responses.append({
                                        "qname"     : qname,            # allows the use of exists: instead of include: for ipv4
                                        "qtype"     : "A",
                                        "content"    : "127.0.0.2",
                                        "ttl"       : DEFAULT_TTL,
                                        "auth"      : True, 
                                    })
                    responses.append({                                  # allows the use of exists: instead of include: for ipv6
                                        "qname"     : qname,
                                        "qtype"     : "AAAA",
                                        "content"    : "fe80::2",
                                        "ttl"       : DEFAULT_TTL,
                                        "auth"      : True, 
                                    })
                else:
                    content = "v=spf1 ~all" #spfOutput["spfFailResponse"]
                

            elif checkForFail == False:
                if spfOutput['pass'] == True:
                    content = spfOutput["spfPassResponse"]
                    responses.append({
                                        "qname"     : qname,            # allows the use of exists: instead of include: for ipv4
                                        "qtype"     : "A",
                                        "content"    : "127.0.0.2",
                                        "ttl"       : DEFAULT_TTL,
                                        "auth"      : True, 
                                    })
                    responses.append({                                  # allows the use of exists: instead of include: for ipv6
                                        "qname"     : qname,
                                        "qtype"     : "AAAA",
                                        "content"    : "fe80::2",
                                        "ttl"       : DEFAULT_TTL,
                                        "auth"      : True, 
                                    })
                else:
                    content = spfOutput["spfFailResponse"]

                
            else:
                content = "v=spf1 ?all"
            responses.append({
                "qname"     : qname,
                "qtype"     : "TXT",
                "content"    : content,
                "ttl"       : DEFAULT_TTL,
                "auth"      : True, 
            })
            responses.append({
                "qname"     : qname,
                "qtype"     : "TXT",
                "content"   : responseBanner,
                #"content"    : f"powered by Expurgate https://xpg8.ehlo.email/spf?r={encodeResult}",
                #"content"    : f"powered by Expurgate (https://xpg8.ehlo.email/?d={info[4]}&ip={info[0]})",
                "ttl"       : DEFAULT_TTL,
                "auth"      : True, 
            })
            return dict(result=responses)

    else: 
        return dict(result=responses)

@app.get("/getAllDomains")
async def getdomaininfo():
    return dict(result=[{
        'id'        : 1,
        'zone'      : ZONE,  
        'kind'      : "NATIVE",
        'serial'    : 11,
        }])


@app.get("/getDomainInfo/{zone}")
async def getdomaininfo(zone):
    if zone == ZONE:
        return dict(result={
            'id'        : 1,
            'zone'      : ZONE,
            'kind'      : "NATIVE",
        'serial'    : 11,
            'auth'  : True
            })
    else:
        return dict(result=False, log="I don't serve " + zone)
    
@app.get("/getAllDomainMetadata/{zone}")
async def getAllDomainMetaData(zone):
        output = {"result" : {"PRESIGNED" : ["0"]}}
        return dict(output)

@app.get("/getDomainMetadata/{zone}/PRESIGNED")
async def getDomainMetadata(zone):
        output = {"result" : ["0"]}
        return dict(output)

        
@app.post("/startTransaction/-1/{zone}/{epoch}")
async def postStartTransaction(zone,epoch):
        output = {"result" : False}
        return dict(output)   



@app.get("/spfExpanded/{domain}")
async def get_spf_expanded(domain: str):
    return await build_spf_chain(domain)
