# CRT Hosts Enricher

**Giovanni Guarino** - *Creator and Maintainer*  
📧 Email: giovannni.guarino.ita@gmail.com  
🐙 GitHub: [@gioguanuo](https://github.com/gioguanuo)  
💼 LinkedIn: https://www.linkedin.com/checkpoint/challengesV2/AQFRIyZpS82tnQAAAZjDYpMKg0_xL3sqes9EQ-KkPoeewWL4wubCUxC6cSj278tIYpFEuMLaPwEtSBmKQpuCprBthcSQlvd0dQ?ut=0We_pCJWdXuHU1

## 📜 License

This project is licensed under the MIT License - see the [LICENSE]file for details.

**Copyright © 2024 Giovanni Guarino. All rights reserved.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

A powerful command-line tool that extracts hostnames from SSL certificates via [crt.sh](https://crt.sh/) and enriches them with comprehensive network intelligence including IP addresses, ASN information, CIDR blocks, and geolocation data.

## 🚀 Features

- **SSL Certificate Analysis**: Extract all hostnames from SSL certificates for any domain
- **IP Resolution**: Resolve hostnames to IPv4 addresses with filtering options
- **ASN Intelligence**: Get ASN numbers, organization names, and domains via IPinfo
- **Network Mapping**: Retrieve CIDR blocks and routing information via BGPView
- **Geolocation Data**: Country and continent information for IP addresses
- **Detailed Logging**: Comprehensive logging with configurable verbosity levels
- **Export Options**: Multiple CSV output formats (raw and enriched data)
- **Rate Limiting**: Respectful API usage with configurable delays
- **Error Resilience**: Robust retry mechanisms with exponential backoff

## 📋 Prerequisites

- Python 3.6 or higher
- Internet connection for API queries
- IPinfo.io API token (free tier available)

## 🛠 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/gioguanuo/crt_hosts_enricher.git
   cd crt_hosts_enricher
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   
   Or manually install (no external dependencies required for basic functionality):
   ```bash
   # The script uses only Python standard library modules
   # No additional packages required!
   ```

3. **Configure IPinfo token:**
   Edit the script and replace `IPINFO_TOKEN` with your token:
   ```python
   IPINFO_TOKEN = "your_ipinfo_token_here"
   ```
   
   Get a free token at: https://ipinfo.io/signup

## 🏃‍♂️ Quick Start

### Basic Usage

```bash
# Analyze a domain
python crt_hosts_enricher.py --domain example.com -o analysis

# Use a crt.sh URL (paste from browser)
python crt_hosts_enricher.py --crt-url "https://crt.sh/?q=example.com" -o analysis

# Only include resolvable hosts with public IPs
python crt_hosts_enricher.py --domain example.com --only-resolvable --public-only -o analysis
```

### Advanced Options

```bash
# Verbose logging with custom log file
python crt_hosts_enricher.py --domain example.com -o analysis --verbose --log-file custom.log

# Adjust timeouts and rate limiting
python crt_hosts_enricher.py --domain example.com -o analysis --http-timeout 30 --sleep 1.0

# Maximum verbosity for debugging
python crt_hosts_enricher.py --domain example.com -o analysis -v --http-retries 5
```

## 📊 Output Files

The tool generates multiple output files:

### 1. Raw Hostnames (`*-raw.csv`)
Contains all unique hostnames found in SSL certificates before filtering:
```csv
hostname
subdomain1.example.com
subdomain2.example.com
api.example.com
```

### 2. Enriched Data (`*.csv`)
Complete analysis with network intelligence:
```csv
hostname,ip,cidr,asn,as_name,as_domain,country,continent
api.example.com,203.0.113.1,203.0.113.0/24,AS64496,Example Corp,example.net,US,North America
```

### 3. Log File (`logs/crt_enricher-YYYYMMDD.log`)
Detailed execution log with debugging information, API responses, and error details.

## 🔧 Command Line Options

### Required Arguments
- `--domain DOMAIN` or `--crt-url URL`: Source for certificate data

### Filtering Options
- `--only-resolvable`: Include only hosts that resolve to IPv4
- `--public-only`: Include only public IP addresses
- `--only-a`: Compatibility flag (IPv4 only, already default)

### Network Options
- `--http-timeout SECONDS`: HTTP timeout (default: 60)
- `--http-retries COUNT`: HTTP retry attempts (default: 3)
- `--sleep SECONDS`: Pause between API calls (default: 0.5)

### Output Options
- `-o, --output FILENAME`: Output CSV filename (required)
- `--log-file PATH`: Custom log file path
- `--verbose, -