#!/usr/bin/env python3
"""
CRT Hosts Enricher - SSL Certificate Analysis Tool
Extracts hostnames from crt.sh and enriches with IP, ASN, and geolocation data.

Author: Giovanni Guarino
Email: tua.email@example.com
GitHub: https://github.com/gioguanuo/crt_hosts_enricher
License: MIT
Version: 2.1


Extract hostnames from SSL certificates and enrich with network intelligence.


__author__ = "Giovanni Guarino"
__copyright__ = "Copyright 2025, Giovanni Guarino"
__license__ = "MIT"
__version__ = "2.1"
__maintainer__ = "Giovanni Guarino"
__email__ = "giovanni.guarino.ita@gmail.com"
__status__ = "Production"
"""
import argparse
import csv
import json
import logging
import os
import socket
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

# ================== CONFIG ==================
IPINFO_TOKEN = "f97aa0477bc627"   # Your IPinfo token
USER_AGENT = "crt_hosts_enricher/2.1 (+https://crt.sh/)"
DEFAULT_SLEEP = 0.5  # Pause between ipinfo calls to avoid rate-limit
VERSION = "2.1"
# ===========================================

class ColoredFormatter(logging.Formatter):
    """Colored log formatter for terminal output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        if hasattr(record, 'no_color') or not sys.stdout.isatty():
            return super().format(record)
        
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)

def setup_logging(log_file=None, verbose=False):
    """Setup logging configuration with file and console handlers"""
    
    # Create logs directory if it doesn't exist
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(exist_ok=True)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = ColoredFormatter(
        fmt='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            fmt='[%(asctime)s] [%(levelname)s] [%(funcName)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Log startup info
        logging.info(f"Logging initialized - File: {log_file}")
        logging.debug(f"Debug logging enabled")
    
    return logger

def log_stats(stats_dict, title="Statistics"):
    """Log statistics in a formatted way"""
    logging.info(f"=== {title} ===")
    for key, value in stats_dict.items():
        logging.info(f"  {key}: {value}")

# -------- HTTP with retry/backoff --------
def http_get_json(url, timeout=60, retries=3, backoff_base=1.7, label=""):
    """HTTP GET with JSON parsing, retry logic, and detailed logging"""
    attempt = 0
    last_err = None
    
    logging.debug(f"Starting HTTP request to: {url}")
    
    while attempt < retries:
        attempt += 1
        try:
            logging.debug(f"HTTP attempt {attempt}/{retries} for {label or url}")
            
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            start_time = time.time()
            
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response_time = time.time() - start_time
                body = resp.read().decode("utf-8", errors="replace").strip()
                
            logging.debug(f"HTTP response received in {response_time:.2f}s, body length: {len(body)}")
            
            # Try standard JSON first
            try:
                result = json.loads(body)
                logging.debug(f"Successfully parsed JSON response")
                return result
            except json.JSONDecodeError:
                logging.debug("Standard JSON parsing failed, trying JSON lines format")
                # Try JSON lines (one per line)
                objs = []
                for line_num, line in enumerate(body.splitlines(), 1):
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        objs.append(json.loads(s))
                    except Exception as e:
                        logging.debug(f"Failed to parse JSON line {line_num}: {e}")
                
                if objs:
                    logging.debug(f"Successfully parsed {len(objs)} JSON lines")
                    return objs
                raise json.JSONDecodeError("No valid JSON found", body, 0)
                
        except Exception as e:
            last_err = e
            logging.warning(f"HTTP request failed (attempt {attempt}/{retries}): {e.__class__.__name__}: {e}")
            
            if attempt < retries:
                wait_s = backoff_base ** attempt
                logging.info(f"Retrying in {wait_s:.1f}s...")
                time.sleep(wait_s)
            else:
                logging.error(f"All {retries} attempts failed for {label or url}")
                break
    
    raise last_err if last_err else RuntimeError("http_get_json: unknown error")

# -------- IP utilities ----------
def is_public_ip(ip):
    """Check if IP address is public (global)"""
    try:
        ip_obj = ip_address(ip)
        is_global = ip_obj.is_global
        logging.debug(f"IP {ip} is {'public' if is_global else 'private'}")
        return is_global
    except ValueError as e:
        logging.debug(f"Invalid IP address '{ip}': {e}")
        return False

# -------- Host resolution (IPv4 only) --------
def resolve_host_ipv4(host):
    """Resolve hostname to IPv4 address"""
    try:
        logging.debug(f"Resolving {host} to IPv4...")
        ip = socket.gethostbyname(host)
        logging.debug(f"Resolved {host} → {ip}")
        return ip
    except socket.gaierror as e:
        logging.debug(f"Failed to resolve {host}: {e}")
        return None

# -------- IPinfo LITE (free tier) --------
def ipinfo_lite(ip, timeout=60, retries=3):
    """
    Query IPinfo LITE API (free tier)
    Endpoint: https://api.ipinfo.io/lite/<ip>?token=...
    Returns: { "ip", "asn", "as_name", "as_domain", "country", "continent", ... }
    Note: Does NOT provide CIDR/route information.
    """
    url = f"https://api.ipinfo.io/lite/{urllib.parse.quote(ip)}?token={IPINFO_TOKEN}"
    
    logging.debug(f"Querying IPinfo LITE for {ip}")
    
    try:
        data = http_get_json(url, timeout=timeout, retries=retries, 
                           backoff_base=1.7, label=f"ipinfo-lite {ip}")
        
        # Normalize possible formats
        if isinstance(data, list):
            data = data[0] if data and isinstance(data[0], dict) else {}
        if not isinstance(data, dict):
            data = {}
        
        result = {
            "asn": data.get("asn") or "",
            "as_name": data.get("as_name") or "",
            "as_domain": data.get("as_domain") or "",
            "country": data.get("country") or data.get("country_name") or "",
            "continent": data.get("continent") or data.get("continent_name") or ""
        }
        
        logging.debug(f"IPinfo result for {ip}: ASN={result['asn']}, Country={result['country']}")
        return result
        
    except Exception as e:
        logging.error(f"IPinfo query failed for {ip}: {e}")
        raise

# -------- BGPView for CIDR --------
def bgpview_cidr(ip, timeout=60, retries=3):
    """
    Query BGPView API for CIDR information
    Endpoint: https://api.bgpview.io/ip/<ip>
    Returns: (cidr, asn, as_name) if available
    """
    url = f"https://api.bgpview.io/ip/{urllib.parse.quote(ip)}"
    
    logging.debug(f"Querying BGPView for {ip}")
    
    try:
        data = http_get_json(url, timeout=timeout, retries=retries, 
                           backoff_base=1.7, label=f"bgpview {ip}")
        
        if isinstance(data, dict) and data.get("status") == "ok":
            prefixes = data.get("data", {}).get("prefixes") or []
            if prefixes:
                p = prefixes[0]  # Take first prefix
                cidr = p.get("prefix", "")
                asn_obj = p.get("asn") or {}
                asn_num = asn_obj.get("asn")
                as_name = asn_obj.get("name") or asn_obj.get("description") or ""
                asn = f"AS{asn_num}" if asn_num else ""
                
                logging.debug(f"BGPView result for {ip}: CIDR={cidr}, ASN={asn}")
                return cidr, asn, as_name
        
        logging.debug(f"No BGPView data found for {ip}")
        return "", "", ""
        
    except Exception as e:
        logging.error(f"BGPView query failed for {ip}: {e}")
        raise

# -------- crt.sh helpers --------
def build_crt_url_from_domain(domain):
    """Build crt.sh URL from domain name"""
    return f"https://crt.sh/?Identity={urllib.parse.quote(domain.strip())}&output=json"

def normalize_crt_url(url):
    """
    Normalize crt.sh URL to standard format
    Accepts:
      - https://crt.sh/?Identity=domain[&output=json]
      - https://crt.sh/?q=domain
    Returns: ...?Identity=...&output=json
    """
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query)
    
    # Convert ?q= to ?Identity=
    if "q" in q and "Identity" not in q:
        domain = q["q"][0]
        return build_crt_url_from_domain(domain)
    
    # Add output=json if missing
    if "Identity" in q and "output" not in q:
        sep = "&" if parsed.query else ""
        return urllib.parse.urlunparse(parsed._replace(query=parsed.query + f"{sep}output=json"))
    
    return url

def fetch_hosts_from_crt(domain_or_url, http_timeout, http_retries):
    """Fetch and parse hostnames from crt.sh"""
    
    # Build URL
    if domain_or_url.lower().startswith("http"):
        url = normalize_crt_url(domain_or_url)
        domain = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("Identity", ["unknown"])[0]
    else:
        url = build_crt_url_from_domain(domain_or_url)
        domain = domain_or_url
    
    logging.info(f"Querying crt.sh for domain: {domain}")
    logging.debug(f"crt.sh URL: {url}")

    try:
        data = http_get_json(url, timeout=http_timeout, retries=http_retries, 
                           backoff_base=1.9, label="crt.sh")
        
        if not data:
            logging.warning("No data returned from crt.sh")
            return []
        
        logging.info(f"Retrieved {len(data)} certificate entries from crt.sh")
        
    except Exception as e:
        logging.error(f"Failed to fetch data from crt.sh: {e}")
        raise

    # Parse hostnames from certificates
    hosts = set()
    cert_count = 0
    hostname_count = 0
    
    for entry in data or []:
        cert_count += 1
        cn = (entry.get("common_name") or "").strip()
        san = (entry.get("name_value") or "").strip()
        
        candidates = []
        if cn:
            candidates.append(cn)
        if san:
            candidates += san.split("\n")
        
        for h in candidates:
            h = h.strip().lower().strip(".")
            if not h or "*" in h:  # Skip wildcards
                continue
            if "." not in h:  # Skip single labels
                continue
            
            if h not in hosts:
                hostname_count += 1
                logging.debug(f"Found hostname: {h}")
            hosts.add(h)
    
    unique_hosts = sorted(hosts)
    
    logging.info(f"Processed {cert_count} certificates")
    logging.info(f"Found {hostname_count} total hostnames")
    logging.info(f"Unique hostnames: {len(unique_hosts)}")
    
    return unique_hosts

# -------- MAIN --------
def main():
    parser = argparse.ArgumentParser(
        description="Extract hostnames from crt.sh and enrich with IPinfo LITE (ASN, AS name/domain, country/continent) + CIDR via BGPView.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s --domain example.com -o analysis
  %(prog)s --crt-url "https://crt.sh/?q=example.com" -o analysis.csv
  %(prog)s --domain example.com --only-resolvable --public-only -o analysis

Version: {VERSION}
        """
    )
    
    # Input source (mutually exclusive)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--domain", 
                            help="Domain to search on crt.sh (e.g., medirect.com.mt)")
    source_group.add_argument("--crt-url", 
                            help="crt.sh URL (accepts ?q= format pasted from browser)")
    
    # Filtering options
    parser.add_argument("--only-resolvable", action="store_true",
                       help="Include only hosts that resolve to at least one IPv4")
    parser.add_argument("--public-only", action="store_true",
                       help="Include only public IP addresses")
    parser.add_argument("--only-a", action="store_true",
                       help="Compatibility: limit to IPv4 (already default behavior)")
    
    # HTTP options
    parser.add_argument("--http-timeout", type=float, default=60.0,
                       help="HTTP timeout (seconds) for crt.sh/ipinfo/bgpview (default: 60)")
    parser.add_argument("--http-retries", type=int, default=3,
                       help="HTTP retry attempts (default: 3)")
    parser.add_argument("--sleep", type=float, default=DEFAULT_SLEEP,
                       help="Pause between ipinfo calls (seconds, default: 0.5)")
    
    # Output options
    parser.add_argument("-o", "--output", required=True,
                       help="Output CSV filename (e.g., Analysis-MeDirect or Analysis-MeDirect.csv)")
    parser.add_argument("--log-file",
                       help="Log file path (default: logs/crt_enricher-YYYYMMDD.log)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging (debug level)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    
    args = parser.parse_args()

    # Setup output filenames
    output_file = args.output
    if not output_file.lower().endswith(".csv"):
        output_file += ".csv"
    
    raw_output_file = output_file[:-4] + "-raw.csv"  # Raw hostname list before filters
    
    # Setup logging
    if not args.log_file:
        timestamp = datetime.now().strftime("%Y%m%d")
        args.log_file = f"logs/crt_enricher-{timestamp}.log"
    
    logger = setup_logging(args.log_file, args.verbose)
    
    # Log startup information
    logging.info(f"=== CRT Hosts Enricher v{VERSION} ===")
    logging.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info(f"Command: {' '.join(sys.argv)}")
    logging.info(f"Output file: {output_file}")
    logging.info(f"Raw output file: {raw_output_file}")
    logging.info(f"Log file: {args.log_file}")
    
    # Log configuration
    config_info = {
        "HTTP timeout": f"{args.http_timeout}s",
        "HTTP retries": args.http_retries,
        "Sleep between calls": f"{args.sleep}s",
        "Only resolvable": args.only_resolvable,
        "Public IPs only": args.public_only,
        "Verbose logging": args.verbose
    }
    log_stats(config_info, "Configuration")

    try:
        # 1) Fetch hostnames from crt.sh
        source = args.crt_url if args.crt_url else args.domain
        logging.info(f"Starting hostname extraction from: {source}")
        
        hosts = fetch_hosts_from_crt(source, 
                                   http_timeout=args.http_timeout, 
                                   http_retries=args.http_retries)
        
        if not hosts:
            logging.error("No hostnames found. Exiting.")
            return 1

        # 1a) Save raw hostname list
        logging.info(f"Saving raw hostname list to: {raw_output_file}")
        with open(raw_output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["hostname"])
            for hostname in hosts:
                writer.writerow([hostname])

        # 2) Resolve hostnames and apply filters
        logging.info("Starting hostname resolution and filtering...")
        
        resolved_hosts = []
        stats = {
            "total_hosts": len(hosts),
            "excluded_not_resolvable": 0,
            "excluded_private_ip": 0,
            "included_hosts": 0
        }
        
        for i, hostname in enumerate(hosts, 1):
            if i % 50 == 0:  # Progress logging
                logging.info(f"Progress: {i}/{len(hosts)} hosts processed")
            
            ip = resolve_host_ipv4(hostname)
            
            # Apply filters
            if not ip and args.only_resolvable:
                logging.debug(f"{hostname} → not resolvable, excluded")
                stats["excluded_not_resolvable"] += 1
                continue
                
            if ip and args.public_only and not is_public_ip(ip):
                logging.debug(f"{hostname} → {ip} (private), excluded")
                stats["excluded_private_ip"] += 1
                continue
            
            resolved_hosts.append((hostname, ip or ""))
            stats["included_hosts"] += 1

        log_stats(stats, "Hostname Resolution Results")

        # 3) Enrich with IPinfo LITE + BGPView data
        logging.info("Starting IP enrichment with IPinfo and BGPView...")
        
        enriched_data = []
        api_stats = {
            "ipinfo_success": 0,
            "ipinfo_failed": 0,
            "bgpview_success": 0,
            "bgpview_failed": 0
        }
        
        for i, (hostname, ip) in enumerate(resolved_hosts, 1):
            if i % 10 == 0:  # Progress logging
                logging.info(f"Enrichment progress: {i}/{len(resolved_hosts)} hosts processed")
            
            # Initialize enrichment data
            asn = as_name = as_domain = country = continent = cidr = ""
            
            if ip:
                # IPinfo LITE query
                try:
                    lite_data = ipinfo_lite(ip, timeout=args.http_timeout, retries=args.http_retries)
                    asn = lite_data["asn"]
                    as_name = lite_data["as_name"]
                    as_domain = lite_data["as_domain"]
                    country = lite_data["country"]
                    continent = lite_data["continent"]
                    api_stats["ipinfo_success"] += 1
                    
                except Exception as e:
                    logging.warning(f"IPinfo failed for {ip}: {e}")
                    api_stats["ipinfo_failed"] += 1
                
                # BGPView query for CIDR (and backup ASN data)
                try:
                    bgp_cidr, bgp_asn, bgp_name = bgpview_cidr(ip, timeout=args.http_timeout, retries=args.http_retries)
                    if bgp_cidr:
                        cidr = bgp_cidr
                    # Use BGPView data as fallback if IPinfo didn't provide it
                    if not asn and bgp_asn:
                        asn = bgp_asn
                    if not as_name and bgp_name:
                        as_name = bgp_name
                    api_stats["bgpview_success"] += 1
                    
                except Exception as e:
                    logging.warning(f"BGPView failed for {ip}: {e}")
                    api_stats["bgpview_failed"] += 1
                
                # Rate limiting
                time.sleep(args.sleep)

            # Store enriched data
            enriched_data.append({
                "hostname": hostname,
                "ip": ip,
                "cidr": cidr,
                "asn": asn,
                "as_name": as_name,
                "as_domain": as_domain,
                "country": country,
                "continent": continent
            })

        log_stats(api_stats, "API Query Results")

        # 4) Save enriched CSV
        logging.info(f"Saving enriched data to: {output_file}")
        
        fieldnames = ["hostname", "ip", "cidr", "asn", "as_name", "as_domain", "country", "continent"]
        
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(enriched_data)

        # 5) Display summary
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)
        
        # Show sample of results
        print(f"\nSample Results (first 30 entries):\n")
        print(f"{'Hostname':<60} {'IP':<15} {'CIDR':<18} {'ASN':<12} {'AS Name':<35} {'Country':<8} {'Continent'}")
        print("-" * 150)
        
        for row in enriched_data[:30]:
            print(f"{row['hostname']:<60} {row['ip']:<15} {row['cidr']:<18} {row['asn']:<12} "
                  f"{(row['as_name'] or '')[:35]:<35} {row['country']:<8} {row['continent']}")
        
        if len(enriched_data) > 30:
            print(f"\n... and {len(enriched_data) - 30} more entries")
        
        # Final statistics
        final_stats = {
            "Total unique hostnames found": stats["total_hosts"],
            "Hostnames excluded (not resolvable)": stats["excluded_not_resolvable"],
            "Hostnames excluded (private IP)": stats["excluded_private_ip"],
            "Hostnames included in analysis": stats["included_hosts"],
            "IPinfo queries successful": api_stats["ipinfo_success"],
            "BGPView queries successful": api_stats["bgpview_success"]
        }
        
        print(f"\nStatistics:")
        for key, value in final_stats.items():
            print(f"  {key}: {value}")
        
        print(f"\nFiles created:")
        print(f"  Raw hostnames: {raw_output_file}")
        print(f"  Enriched data: {output_file}")
        print(f"  Log file: {args.log_file}")
        
        logging.info("Analysis completed successfully")
        logging.info(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return 0

    except KeyboardInterrupt:
        logging.warning("Analysis interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())