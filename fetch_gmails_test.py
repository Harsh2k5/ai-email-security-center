import os
import requests
import json
import time
import urllib.parse
import csv
import pandas as pd
import base64
import dns.resolver
from io import StringIO
from dotenv import load_dotenv

import argparse

# Add at the beginning of the file

import sys
print(f"Python executable: {sys.executable}")
def parse_args():
    parser = argparse.ArgumentParser(description="Check URL security")
    parser.add_argument("--url", help="URL to scan")
    parser.add_argument("--output", help="Output file path", default="security_results.csv")
    parser.add_argument("--append", action="store_true", help="Append to existing file instead of overwriting")
    return parser.parse_args()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Define the output file path
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "security_results.csv")

# Load API keys from .env
load_dotenv()
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# API Endpoints
SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Cache for checked IPs
checked_ips = {}

def fetch_malicious_urls():
    """Fetches recent malicious URLs from URLHaus."""
    print("\n📥 Fetching recent malicious URLs from URLHaus...")
    response = requests.get("https://urlhaus.abuse.ch/downloads/csv_online/")

    if response.status_code != 200:
        print("❌ Failed to fetch data from URLHaus")
        return []

    csv_data = response.text.split("\n")[8:]
    csv_reader = csv.reader(StringIO("\n".join(csv_data)), quotechar='"')

    urls = []
    next(csv_reader, None)

    for row in csv_reader:
        if len(row) >= 7:
            url = row[2]  # Extract URL (3rd column)
            threat_type = row[5]  # Extract threat type (6th column)
            tags = row[6]  # Extract tags (7th column)
            urls.append({"url": url, "threat": threat_type, "tags": tags})

    print(f"✅ Retrieved {len(urls)} URLs from URLHaus.")
    return urls[:2]  # Limit to 10 URLs for testing

def check_url_google_safe_browsing(url):
    """Check if a URL is malicious using Google Safe Browsing API."""
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {"clientId": "spam-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(f"{SAFE_BROWSING_API_URL}?key={GOOGLE_SAFE_BROWSING_KEY}", headers=headers, data=json.dumps(payload))
    if response.status_code == 200:
        result = response.json()
        return "MALICIOUS" if "matches" in result else "SAFE"
    return "ERROR"

def check_url_urlhaus(url):
    """Check if a URL is in URLhaus database."""
    data = {"url": url}
    
    try:
        response = requests.post(URLHAUS_API, data=data)
        if response.status_code == 200:
            json_data = response.json()
            if json_data["query_status"] == "ok":
                return f"MALICIOUS: {json_data['threat']} ({json_data['tags']})"
            return "SAFE"
    except Exception as e:
        return f"Error checking URLhaus: {e}"

    return "UNKNOWN"

def submit_to_virustotal(url):
    """Submits a URL to VirusTotal for scanning."""
    headers = {"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"url": url}
    
    response = requests.post(VIRUSTOTAL_API_URL, headers=headers, data=data)
    
    if response.status_code == 200:
        scan_id = response.json().get("data", {}).get("id", None)
        if scan_id:
            return scan_id
    print(f"❌ Error submitting to VirusTotal: {response.text}")
    return None

def get_virustotal_results(url):
    """Fetches VirusTotal results or submits if not found."""
    url_identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": VT_API_KEY}
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_identifier}"

    response = requests.get(analysis_url, headers=headers)
    
    if response.status_code == 200:
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 3:
            return "MALICIOUS"
        elif stats.get("suspicious", 0) > 0:
            return "SUSPICIOUS"
        elif stats.get("harmless", 0) > stats.get("undetected", 0):
            return "SAFE"
        return "UNKNOWN"

    elif response.status_code == 404:  # URL not found, submit for scanning
        scan_id = submit_to_virustotal(url)
        if scan_id:
            print(f"🔄 Waiting for VirusTotal scan results for {url}...")
            time.sleep(60)
            return get_virustotal_results(url)
        return "SUBMITTED"

    return "UNKNOWN"

def check_ip_abuseipdb(url):
    """Check if the IP of a URL is in AbuseIPDB database."""
    import socket
    from urllib.parse import urlparse
    
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.split(':')[0]
    
    # Check if hostname is already an IP address
    if is_valid_ip(hostname):
        ip_address = hostname
    else:
        # Try to resolve the hostname to an IP address
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            return "ERROR: Could not resolve hostname to IP"
    
    if ip_address in checked_ips:
        return checked_ips[ip_address]

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 365}
    
    try:
        response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            result = "MALICIOUS" if score > 50 else "SAFE"
            checked_ips[ip_address] = result
            return result
    except Exception as e:
        return f"ERROR: {str(e)}"
        
    return "ERROR"

def is_valid_ip(ip):
    """Check if a string is a valid IPv4 address."""
    import re
    pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return pattern.match(ip) is not None

def extract_domain(url):
    """Extracts the domain from a URL."""
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.netloc

def check_spf(domain):
    """Check SPF record for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_record = rdata.to_text()
            if "v=spf1" in txt_record:
                return f"✅ SPF Found: {txt_record}"
        return "❌ No SPF Record"
    except:
        return "❌ No SPF Record"

def check_dkim(domain, selector="default"):
    """Check DKIM record for a domain using a given selector."""
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, "TXT")
        for rdata in answers:
            return f"✅ DKIM Found: {rdata.to_text()}"
        return "❌ No DKIM Record"
    except:
        return "❌ No DKIM Record"

def check_dmarc(domain):
    """Check DMARC record for a domain."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            return f"✅ DMARC Found: {rdata.to_text()}"
        return "❌ No DMARC Record"
    except:
        return "❌ No DMARC Record"

# Modify the main function
def main():
    args = parse_args()
    
    if args.url:
        # Single URL scan mode
        url = args.url
        domain = extract_domain(url)
        
        print(f"🔍 Checking URL: {url}")
        
        google_result = check_url_google_safe_browsing(url)
        vt_result = get_virustotal_results(url)
        urlhaus_result = check_url_urlhaus(url)
        abuseipdb_result = check_ip_abuseipdb(url)
        spf_result = check_spf(domain)
        dkim_result = check_dkim(domain)
        dmarc_result = check_dmarc(domain)
        
        results = [{
            "URL": url,
            "Domain": domain,
            "Threat Type": "Manual Scan",
            "Tags": "Manual Scan",
            "Google Safe Browsing": google_result,
            "VirusTotal": vt_result,
            "URLhaus": urlhaus_result,
            "AbuseIPDB": abuseipdb_result,
            "SPF": spf_result,
            "DKIM": dkim_result,
            "DMARC": dmarc_result,
            "Scan Time": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        }]

        output_file = args.output


        if args.append and os.path.exists(output_file):
            try:
                # Read existing file
                existing_df = pd.read_csv(output_file)
                
                # Add Scan Time column if it doesn't exist
                if "Scan Time" not in existing_df.columns:
                    existing_df["Scan Time"] = "Not Available"
                
                # Create DataFrame from new results
                new_df = pd.DataFrame(results)
                
                # Concatenate and save
                combined_df = pd.concat([existing_df, new_df], ignore_index=True)
                combined_df.to_csv(output_file, index=False)
            except Exception as e:
                print(f"Error appending to file: {e}")
                # Fall back to creating a new DataFrame
                pd.DataFrame(results).to_csv(output_file, index=False)
        else:
            # Create new file
            pd.DataFrame(results).to_csv(output_file, index=False)
        
        # Handle the case for OUTPUT_FILE separately
        if output_file != OUTPUT_FILE:
            pd.DataFrame(results).to_csv(OUTPUT_FILE, index=False)
            
        print(f"\n📁 Results saved to {output_file}")
    else:
        # Original batch scan mode
        urls_data = fetch_malicious_urls()
        results = []

        for i, entry in enumerate(urls_data):
            url, threat_type, tags = entry["url"], entry["threat"], entry["tags"]
            domain = extract_domain(url)

            print("\n" + "=" * 50)
            print(f"🔍 Checking URL {i+1}/{len(urls_data)}: {url}")
            print(f"   - Threat Type: {threat_type} | Tags: {tags}")

            google_result = check_url_google_safe_browsing(url)
            vt_result = get_virustotal_results(url)
            urlhaus_result = check_url_urlhaus(url)
            abuseipdb_result = check_ip_abuseipdb(url)
            spf_result = check_spf(domain)
            dkim_result = check_dkim(domain)
            dmarc_result = check_dmarc(domain)

            print(f"📊 FINAL RESULTS for {url}:")
            print(f"   - Google Safe Browsing: {google_result}")
            print(f"   - VirusTotal: {vt_result}")
            print(f"   - URLhaus: {urlhaus_result}")
            print(f"   - AbuseIPDB: {abuseipdb_result}")
            print(f"   - SPF: {spf_result}")
            print(f"   - DKIM: {dkim_result}")
            print(f"   - DMARC: {dmarc_result}")

            results.append({
                "URL": url,
                "Domain": domain,
                "Threat Type": threat_type,
                "Tags": tags,
                "Google Safe Browsing": google_result,
                "VirusTotal": vt_result,
                "URLhaus": urlhaus_result,
                "AbuseIPDB": abuseipdb_result,
                "SPF": spf_result,
                "DKIM": dkim_result,
                "DMARC": dmarc_result
            })
            
            time.sleep(2)  # Avoid rate limits

        pd.DataFrame(results).to_csv("security_results.csv", index=False)
        print("\n📁 Results saved to security_results.csv")
    return len(results) - 1

if __name__ == "__main__":
    main()