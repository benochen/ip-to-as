# IP → ASN & Organization Lookup (with optional RDAP enrichment)

`ip_to_as_enriched.py` resolves IP addresses to their **Autonomous System Number (ASN)** and **organization name**, using:

- **ip-api.com** (default): fast, free (rate-limited), returns ASN, organization, ISP, and country.
- **RDAP** (optional `--rdap`): enriches with **CIDR prefix**, **RIR** (ARIN/RIPE/APNIC/AFRINIC/LACNIC), and **holder/registrant**.

The tool supports **CSV** (default) and **JSON** output, **concurrent** requests, **retries**, **timeouts**, and basic **rate limiting**.

---

## Requirements

- **Python 3.8+**
- `requests` library

Install dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```txt
requests>=2.25.0,<3.0
```

---

## Usage

Run the script with **one or more IPs** or provide a file containing IPs.

### Basic (ASN + organization via ip-api.com)
```bash
python ip_to_as_enriched.py 8.8.8.8 1.1.1.1
```

**Output (CSV to stdout):**
```csv
ip,ok,asn,org_name,holder,cidr,rir,country,country_code,isp,source,error
1.1.1.1,True,13335,"Cloudflare, Inc.",,,APNIC,Australia,AU,Cloudflare,"ip-api",
8.8.8.8,True,15169,"Google LLC",,,ARIN,United States,US,Google,"ip-api",
```

---

### From a file
Create `ips.txt` (one IP per line):

```
8.8.8.8
1.1.1.1
9.9.9.9
```

Run:
```bash
python ip_to_as_enriched.py -i ips.txt -o result.csv
```

---

### JSON output
```bash
python ip_to_as_enriched.py 8.8.8.8 --json -o result.json
```

**Example JSON:**
```json
[
  {
    "ip": "8.8.8.8",
    "ok": true,
    "asn": "15169",
    "org_name": "Google LLC",
    "country": "United States",
    "country_code": "US",
    "isp": "Google",
    "source": ["ip-api"],
    "error": null
  }
]
```

---

### RDAP enrichment (CIDR, RIR, holder)
```bash
python ip_to_as_enriched.py -i ips.txt --rdap -o result.csv
```

Adds fields:
- `cidr` — announced prefix (when available)
- `rir` — inferred registry (ARIN/RIPE/APNIC/AFRINIC/LACNIC)
- `holder` — registrant/holder name (best-effort from RDAP entities)

---

### Advanced options

- Limit concurrency and throttle requests:
```bash
python ip_to_as_enriched.py -i ips.txt -w 8 --qps 6 --rdap -o out.csv
```

- Increase timeout and retries:
```bash
python ip_to_as_enriched.py 1.1.1.1 --timeout 10 --retries 5
```

---

## Command Line Options

| Option | Description | Default |
|---|---|---|
| `ips` | IPs as positional arguments (if no `--input`) | — |
| `-i, --input` | File with one IP per line | — |
| `-o, --output` | Output file (CSV or JSON) | stdout |
| `--json` | Output JSON instead of CSV | false |
| `--rdap` | Enable RDAP enrichment (CIDR, RIR, holder) | false |
| `-w, --workers` | Number of concurrent threads | 12 |
| `--timeout` | HTTP timeout (seconds) | 6.0 |
| `--retries` | Retries per request | 3 |
| `--qps` | Approximate requests/second across workers | 9 |

> ⚠️ Throttling note: effective per-task delay is computed as  
> `qps_delay ≈ (workers / qps) * 0.9`.  
> Keep `--qps` under public limits to avoid HTTP 429 (Too Many Requests).

---

## Output Fields (CSV/JSON)

- `ip` — queried IP  
- `ok` — `True` if an ASN was successfully resolved  
- `asn` — numeric ASN (string)  
- `org_name` — organization parsed from ip-api `as`/`org`  
- `holder` — RDAP holder/registrant (if `--rdap`)  
- `cidr` — RDAP network/prefix (if `--rdap`)  
- `rir` — inferred registry (if `--rdap`)  
- `country`, `country_code`, `isp` — from ip-api  
- `source` — `ip-api` or `ip-api|rdap`  
- `error` — error message if any  

---

## Data Sources & Limits

- **ip-api.com** free endpoint: `http://ip-api.com/json/{ip}`  
  (rate-limited, HTTP only on free plan).  
- **RDAP** via `https://rdap.org/ip/{ip}` → redirects to the appropriate RIR.  
  Responses vary; some fields may be missing.  

For high-volume use, consider a commercial provider (ipinfo, MaxMind, WhoisXML, Team Cymru).

---

## License

This script is provided under the **MIT License**.  
Check the usage terms of ip-api.com and RDAP/RIR services before heavy or commercial use.
