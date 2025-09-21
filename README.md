# IP → ASN & Organization Lookup (with optional RDAP enrichment)

`ip_to_as_enriched.py` resolves IP addresses to their **Autonomous System Number (ASN)** and **organization name**, using:

- **ip-api.com** (default): fast, free (rate-limited 45 ip per minutes), returns ASN, organization, ISP, and country.
- **RDAP** (optional `--rdap`): enriches with **CIDR prefix**, **RIR** (ARIN/RIPE/APNIC/AFRINIC/LACNIC), and **holder/registrant**.

The tool supports **CSV** (default) and **JSON** output, **concurrent** requests, **retries**, **timeouts**, and basic **rate limiting**.

## Features

- Input from CLI (`python ip_to_as_enriched.py 8.8.8.8 …`) or file (`--input ips.txt`)
- CSV or JSON output (`--json`)
- Concurrency control (`--workers`)
- Retries with exponential backoff
- Throttling via `--qps` to stay friendly with public endpoints
- Clean parsing of `ASxxxxx Org Name` into `asn` + `org_name`

## Requirements

- **Python 3.8+**
- `requests` library

Install:

```bash
pip install -r requirements.txt
