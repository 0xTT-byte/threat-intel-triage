#!/usr/bin/env python3
"""
threat_intel.py - Multi-source IOC triage tool 
supports: IP addresses, domains, file hashes (MD5/SHA1/SHA256)
Source: VirusTotal v3, AlienVault OTX
"""

import requests
import json 
import sys
import argparse
import re
import os 
from datetime import datetime, timezone 

# CONFIG
VT_API_KEY = os.environ.get("VT_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

VT_BASE = "https://www.virusetotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"

LOG_FILE = "investigation_log.txt"

# IOC CLASSIFICATION 
def classify_ioc(ioc: str) -> str: 
    """Return 'ip', 'domain', or 'hash' based on IOC format."""
    ip_pattern     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    hash_pattern   = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

    if ip_pattern.match(ioc):
        return "ip"
    elif hash_pattern.match(ioc):
        return "hash"
    elif domain_pattern.match(ioc):
        return "domain"
    else: 
        return "unknown"

# VIRUSTOTAL

def vt_lookup(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal v3 for an IP, domain, or file hash."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    
    endpoint_map = {
    "ip":       f"{VT_BASE}/ip_addresses/{ioc}",
    "domain":   f"{VT_BASE}/domains/{ioc}",
    "hash":     f"{VT_BASE}/files/{ioc}",
    }

    url = endpoint_map.get(ioc_type)
    if not url: 
        return {"error": f"Unsupported IOC type: {ioc_type}"}
    
    try: 
        resp = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {resp.status_code}: {e}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    result = {
        "malicious":    stats.get("malicious", 0),
        "suspicious":   stats.get("suspicious", 0),
        "undetected":   stats.get("undetected", 0),
        "harmless":     stats.get("harmless", 0),
        "total":        sum(stats.values())
    }

    # Type-specific extra context
    if ioc_type == "ip":
        result["country"]   = attrs.get("country", "N/A")
        result["asn"]       = attrs.get("asn", "N/A")
        result["as_owner"]  = attrs.get("as_owner", "N/A")
    
    elif ioc_type == "domain":
        result["registrar"]     = attrs.get("registrar", "N/A")
        result["creation_date"] = attrs.get("creation_date", "N/A")
        result["categories"]    = attrs.get("categories", {})
    
    elif ioc_type == "hash":
        result["file_name"] = attrs.get("meaningful_name", "N/A")
        result["file_type"] = attrs.get("type_description", "N/A")
        result["file_size"] = attrs.get("size", "N/A")
        result["tags"]      = attrs.get("tags", [])
    
    return result


# ALIENVAULT OTX    

def otx_lookup(ioc: str, ioc_type: str) -> dict:
    """Query AlienVault OTX for an IP, domain, or file hash."""

    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not set"}
    section_map = {
        "ip":       ("IPv4",    "general"),
        "domain":   ("domain",  "general"),
        "hash":     ("file",    "general"),
    }
    otx_type, section = section_map.get(ioc_type, (None, None))
    if not otx_type:
        return {"error": f"Unsupported IOC type: {ioc_type}"}
    
    url = f"{OTX_BASE}/indicators/{otx_type}/{ioc}/{section}"

    try: 
        resp = requests.get(
            url, 
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ReadException as e:
        return {"error": str(e)}
    
    pulse_info = data.get("pulse_info", {})
    result = {
        "pulse_count":  pulse_info.get("count", 0),
        "pulse":        [p.get("name") for p in pulse_info.get("pulses", [])[:5]],
        "reputation":   data.get("reputation", "N/A"),
        "country":      data.get("country_name", "N/A"),
        "asn":          data.get("asn", "N/A"),
    }
    return result

# VERDICT

def verdict(vt: dict, otx: dict) -> str:
    """Derive a simple verdict from combined results."""
    malicious     = vt.get("malicious", 0)
    suspicious    = vt.get("suspicious", 0)
    otx_hits      = otx.get("pulse_count", 0)

    if malicious >= 5 or otx_hits >= 3:
        return "MALICIOUS"
    elif malicious >= 1 or suspicious >= 2 or otx_hits >= 1:
        return "SUSPICIOUS"
    else:
        return "CLEAN"

# LOGGING

def log_result(ioc: str, ioc_type: str, vt: dict, otx: dict, v: str):
    """Append a structured case entry to the investigation log."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = (
        f"\n{'='*60}\n"
        f"[{ts}] IOC: {ioc} TYPE: {ioc_type.upper()} verdict: {v}\n"
        f"  VT  -> malicious={vt.get('malicious', 'N/A')} "
        f"suspicious={vt.get('suspicious', 'N/A')} "
        f"total_engines={vt.get('total', 'N/A')} "
        f"  OTX -> pulses={otx.get('pulse_count', 'N/A')} "
        f"reputation={otx.get('reputation', 'N/A')}\n"
    )
    if vt.get("error"):
        entry += f" VT error: {vt['error']}\n"
    if otx.get("error"):
        entry += f" OTX error: {otx['error']}\n"

    with open(LOG_FILE, "a") as f:
        f.write(entry)

# OUTPUT

VERDICT_COLOR = {
    "MALICIOUS": "\033[91m", #red
    "SUSPICIOUS": "\033[93m", #yellow
    "CLEAN": "\033[92m", #green
}

RESET = "\033[0m"
BOLD = "\033[1m"

def print_report(ioc: str, ioc_type: str, vt: dict, otx: dict, v: str):
    color = VERDICT_COLOR.get(v, "")
    print(f"\n{BOLD}{'-'*60}{RESET}")
    print(f"  IOC     : {ioc}")
    print(f"  Type    : {ioc_type.upper()}")
    print(f"  Verdict : {color}{BOLD}{v}{RESET}")
    print(f"{'─'*60}{RESET}")

    # VirusTotal block
    if vt.get("error"):
        print(f"  [VT]  Error — {vt['error']}")
    else:
        print(f"  [VT]  Malicious={vt['malicious']}  Suspicious={vt['suspicious']}  "
              f"Harmless={vt['harmless']}  Total engines={vt['total']}")
        if ioc_type == "ip":
            print(f"        Country={vt['country']}  ASN={vt['asn']}  Owner={vt['as_owner']}")
        elif ioc_type == "domain":
            print(f"        Registrar={vt['registrar']}  Created={vt['creation_date']}")
        elif ioc_type == "hash":
            print(f"        Name={vt['file_name']}  Type={vt['file_type']}  "
                  f"Size={vt['file_size']} bytes")
            if vt["tags"]:
                print(f"        Tags={', '.join(vt['tags'])}")

    # OTX block
    if otx.get("error"):
        print(f"  [OTX] Error — {otx['error']}")
    else:
        print(f"  [OTX] Pulses={otx['pulse_count']}  Reputation={otx['reputation']}  "
              f"Country={otx['country']}  ASN={otx['asn']}")
        if otx["pulses"]:
            print(f"        Top pulses:")
            for p in otx["pulses"]:
                print(f"          • {p}")

    print(f"  Logged  : {LOG_FILE}")
    print(f"{'─'*60}\n")

# MAIN 

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel Triage - VT + OTX IOC lookup | Author: Omar Fattouh(0xTT)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "   python threat_intel.py 8.8.8.8\n"
            "   python threat_intel.py malware.example.com\n"
            "   python threat_intel.py 44d88612fea8a8f36de82e1278abb02f"
            "   python threat_intel.py 8.8.8.8 1.1.1.1 suspicious.io\n\n"
            "Env vars required:\n"
            "   export VT_API_KEY='your_key'\n"
            "   export OTX_API_KEY='your_key'"
        )
    )
    parser.add_argument(
        "iocs",
        nargs="+",
        metavar="IOC",
        help="One or more IPs, domains, or file hashes"
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="Skip writing results to investigation_log.txt"
    )
    args = parser.parse_args()

    for ioc in args.iocs:
        ioc_type = classify_ioc(ioc.strip())
        if ioc_type == "unknown":
            print(f"[!] Cannot classify IOC: {ioc} - skipping")
            continue
        vt = vt_lookup(ioc,ioc_type)
        otx = otx_lookup(ioc, ioc_type)
        v = verdict(vt, otx)

        print_report(ioc, ioc_type, vt, otx, v)

        if not args.no_log:
            log_result(ioc, ioc_type, vt, otx, v)

if __name__ == "__main__":
    main()