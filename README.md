# threat-intel-triage
**Author:** Omar Fattouh

A command-line IOC triage tool that queries **VirusTotal v3** and **AlienVault OTX** to assess the threat level of IPs, domains, and file hashes. Built as part of a Security Engineering portfolio to demonstrate Python automation and threat intelligence integration.

---

## Features

- Auto-classifies IOC type (IP, domain, MD5/SHA1/SHA256 hash) — no flags needed
- Queries VirusTotal v3 and AlienVault OTX in parallel per IOC
- Derives a `MALICIOUS / SUSPICIOUS / CLEAN` verdict from combined results
- Type-specific context: ASN + country for IPs, registrar for domains, file name/type/tags for hashes
- Batch mode — pass multiple IOCs in one command
- Appends structured UTC-timestamped entries to `investigation_log.txt` for case tracking
- `--no-log` flag to suppress logging

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/yourhandle/threat-intel-triage.git
cd threat-intel-triage
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Set API keys as environment variables**
```bash
export VT_API_KEY="your_virustotal_api_key"
export OTX_API_KEY="your_alienvault_otx_api_key"
```

> Get a free VirusTotal key at https://www.virustotal.com  
> Get a free OTX key at https://otx.alienvault.com

---

## Usage

```bash
python threat_intel.py <IOC> [IOC ...] [--no-log]
```

**Single IOC**
```bash
python threat_intel.py 185.220.101.45
python threat_intel.py malware.example.com
python threat_intel.py 44d88612fea8a8f36de82e1278abb02f
```

**Batch — multiple IOCs in one call**
```bash
python threat_intel.py 185.220.101.45 suspicious.io 44d88612fea8a8f36de82e1278abb02f
```

**Skip logging**
```bash
python threat_intel.py 8.8.8.8 --no-log
```

---

## Sample Output

```
────────────────────────────────────────────────────────────
  IOC     : 185.220.101.45
  Type    : IP
  Verdict : MALICIOUS
────────────────────────────────────────────────────────────
  [VT]  Malicious=18  Suspicious=2  Harmless=55  Total engines=75
        Country=DE  ASN=60729  Owner=Sebastian Merkel
  [OTX] Pulses=7  Reputation=-2  Country=Germany  ASN=AS60729
        Top pulses:
          • Tor Exit Nodes - 2024
          • C2 Infrastructure Feed
          • Abuse.ch Feodo Tracker
  Logged  : investigation_log.txt
────────────────────────────────────────────────────────────
```

---

## Case Log Format

Results are appended to `investigation_log.txt`:

```
============================================================
[2025-12-01T14:32:10Z] IOC: 185.220.101.45  TYPE: IP  VERDICT: MALICIOUS
  VT  → malicious=18 suspicious=2 total_engines=75
  OTX → pulses=7 reputation=-2
```

---

## Verdict Logic

| Condition | Verdict |
|---|---|
| VT malicious ≥ 5 **or** OTX pulses ≥ 3 | `MALICIOUS` |
| VT malicious ≥ 1 **or** VT suspicious ≥ 2 **or** OTX pulses ≥ 1 | `SUSPICIOUS` |
| None of the above | `CLEAN` |

---

## MITRE ATT&CK Context

This tool supports triage during the **Investigation** phase of incident response, mapping to:

- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) — C2 IP/domain identification
- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) — malicious hash identification

---

## Security Note

**Never hardcode API keys.** This tool reads keys from environment variables only. Add a `.gitignore` to exclude any log files before pushing:

```
investigation_log.txt
.env
```
