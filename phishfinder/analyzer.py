# phishfinder/analyzer.py

import email
import re
from ipwhois import IPWhois
import logging

# Configure ipwhois logging to prevent verbose output
logging.getLogger('ipwhois').setLevel(logging.WARNING)


class PhishFinder:
    """
    Analyzes raw email content to extract and enrich key threat indicators
    from a potential phishing email.
    """

    def __init__(self, email_raw_content: str):
        # 1. Parse the raw email text into an EmailMessage object
        self.msg = email.message_from_string(email_raw_content)
        self.indicators = {}  # Dictionary to store all findings

    # --------------------------------------------------------------------------
    # HELPER 1: Extracting Key Email Headers (Sender/Path Analysis)
    # --------------------------------------------------------------------------
    def _extract_headers(self):
        self.indicators['Subject'] = self.msg.get('Subject', 'N/A')
        self.indicators['From'] = self.msg.get('From', 'N/A')
        self.indicators['Return-Path'] = self.msg.get('Return-Path', 'N/A')
        self.indicators['Message-ID'] = self.msg.get('Message-ID', 'N/A')

        # Extracting the 'Received' header chain (email path)
        received_headers = self.msg.get_all('Received')
        if received_headers:
            # Look at the last 'Received' header for the connecting IP
            first_hop = received_headers[-1]
            # Regex to find an IPv4 address bracketed by []
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', first_hop)

            # Simple check to filter out common private IPs (e.g., 127.0.0.1)
            connecting_ip = ip_match.group(1) if ip_match else 'N/A'

            # Note: This is a basic filter. A full solution checks against RFC 1918 ranges.
            if connecting_ip.startswith('192.168.') or connecting_ip.startswith('10.') or connecting_ip == '127.0.0.1':
                self.indicators['Connecting_IP'] = 'Internal/Private'
            else:
                self.indicators['Connecting_IP'] = connecting_ip
        else:
            self.indicators['Connecting_IP'] = 'N/A'

    # --------------------------------------------------------------------------
    # HELPER 2: Extracting Malicious URLs from the Body
    # --------------------------------------------------------------------------
    def _extract_urls(self):
        body = ""
        # Handle multipart emails (HTML/plain text parts)
        if self.msg.is_multipart():
            for part in self.msg.walk():
                ctype = part.get_content_type()
                cdisp = part.get('Content-Disposition')

                # Get payload from plain text or HTML parts without attachments
                if (ctype == 'text/plain' or ctype == 'text/html') and cdisp is None:
                    try:
                        body += part.get_payload(decode=True).decode()
                    except:
                        # Skip if decoding fails
                        continue
        else:
            # Handle single-part emails
            body = self.msg.get_payload(decode=True).decode()

        # Regex to find URLs starting with http://, https://, or www.
        url_regex = r'(?:https?:\/\/|www\.)[a-zA-Z0-9\.\/\-_=?&%]+'
        found_urls = re.findall(url_regex, body)

        # Store unique URLs found
        self.indicators['URLs_Found'] = list(set(found_urls))

    # --------------------------------------------------------------------------
    # HELPER 3: IP Enrichment/Reputation Check (More Robust)
    # --------------------------------------------------------------------------
    def _enrich_data(self):
        connecting_ip = self.indicators.get('Connecting_IP')

        # Only run lookup if it's a public IP
        if connecting_ip != 'N/A' and connecting_ip != 'Internal/Private':
            try:
                # Use ipwhois to get ASN (Autonomous System Number) and country info
                obj = IPWhois(connecting_ip)

                # Use lookup_rdap which is the modern standard
                results = obj.lookup_rdap(depth=1, inc_none=False)

                # Attempt to extract organization and country code
                org_name = results.get('asn_description', 'Unknown Organization')
                country_code = results.get('asn_country_code', 'Unknown')

                # Fallback check (sometimes network names are in the 'nets' list)
                if org_name == 'Unknown Organization' and results.get('nets'):
                    org_name = results['nets'][0].get('name', 'Unknown Organization')

                self.indicators['IP_ASN_Org'] = org_name
                self.indicators['IP_Country'] = country_code

            except Exception:
                # Catching any exception (like rate-limiting or parsing failure)
                self.indicators['IP_ASN_Org'] = 'Lookup Failed (Check Rate Limits)'
                self.indicators['IP_Country'] = 'Lookup Failed (Check Rate Limits)'
        else:
            self.indicators['IP_ASN_Org'] = 'N/A (Internal/Private IP)'
            self.indicators['IP_Country'] = 'N/A (Internal/Private IP)'

    # --------------------------------------------------------------------------
    # MAIN METHOD: Analysis and Reporting (THIS IS WHERE THE CALLS HAPPEN)
    # --------------------------------------------------------------------------
    def analyze_and_report(self):
        # 1. Run all analysis steps - This is why the error occurred before!
        self._extract_headers()
        self._extract_urls()
        self._enrich_data()

        print("\n" + "=" * 50)
        print("         🚨 PhishFinder Analysis Report 🚨")
        print("=" * 50)

        # 2. Generate a structured report output
        print("\n## 1. Email Headers and Source")
        print(f"  Subject: {self.indicators.get('Subject')}")
        print(f"  From: {self.indicators.get('From')}")
        print(f"  Return-Path: {self.indicators.get('Return-Path')}")
        print(f"  Connecting IP: {self.indicators.get('Connecting_IP')}")
        print(f"  Originating Network: {self.indicators.get('IP_ASN_Org')}")
        print(f"  IP Country: {self.indicators.get('IP_Country')}")

        print("\n## 2. Malicious Indicators")
        if self.indicators.get('URLs_Found'):
            print(f"  ⚠️ Potential Phishing URLs Found ({len(self.indicators['URLs_Found'])}):")
            for url in self.indicators['URLs_Found']:
                print(f"    - {url}")
        else:
            print("  ✅ No external URLs found.")

        print(f"\n## 3. Recommended Action")
        print(f"  - **Check 'From' vs 'Return-Path'**: Look for domain mismatch.")
        print(
            f"  - **Check Country/Network**: Investigate if the IP origin ({self.indicators.get('IP_Country')}) is unusual.")
        if self.indicators.get('URLs_Found'):
            print(
                f"  - **Sandbox URLs**: Submitting all found URLs to a secure sandbox (e.g., VirusTotal) is MANDATORY.")

        print("\n" + "=" * 50)

        # Return the collected indicators dictionary for programmatic use
        return self.indicators