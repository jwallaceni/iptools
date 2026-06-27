#!/usr/bin/env python3
"""
IPTools - Advanced IP Scanner with Cloud Detection and Microsoft Online Enumeration
"""

import ipaddress
import subprocess
import platform
import sys
import re
import json
import requests
from colorama import init, Fore, Style, Back
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Initialize colorama for cross-platform color support
init(autoreset=True)

# ASCII Art Banner
BANNER = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════════════════════╗
{Fore.BLUE}║                                                                  ║
{Fore.BLUE}║  {Fore.CYAN}██████╗ ████████╗██████╗  ██████╗  ██████╗ ██╗  ██╗{Fore.BLUE}  ║
{Fore.BLUE}║  {Fore.CYAN}██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗██╔═══██╗██║ ██╔╝{Fore.BLUE}  ║
{Fore.BLUE}║  {Fore.CYAN}██████╔╝   ██║   ██████╔╝██║   ██║██║   ██║█████╔╝ {Fore.BLUE}  ║
{Fore.BLUE}║  {Fore.CYAN}██╔═══╝    ██║   ██╔═══╝ ██║   ██║██║   ██║██╔═██╗ {Fore.BLUE}  ║
{Fore.BLUE}║  {Fore.CYAN}██║        ██║   ██║     ╚██████╔╝╚██████╔╝██║  ██╗{Fore.BLUE}  ║
{Fore.BLUE}║  {Fore.CYAN}╚═╝        ╚═╝   ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝{Fore.BLUE}  ║
{Fore.BLUE}║                                                                  ║
{Fore.BLUE}║  {Fore.WHITE}Advanced IP Scanner & Cloud Enumeration Tool{Fore.BLUE}              ║
{Fore.BLUE}║  {Fore.YELLOW}Version 2.0 | Created by Security Enthusiasts{Fore.BLUE}          ║
{Fore.BLUE}╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Cloud provider detection patterns
CLOUD_PROVIDERS = {
    'AWS': {
        'patterns': [
            r'^ec2-.*\.compute\.amazonaws\.com$',
            r'^ip-.*\.ec2\.internal$',
            r'^.*\.amazonaws\.com$'
        ],
        'api': 'https://ip-ranges.amazonaws.com/ip-ranges.json'
    },
    'Azure': {
        'patterns': [
            r'^.*\.cloudapp\.azure\.com$',
            r'^.*\.azurewebsites\.net$',
            r'^.*\.azure\.com$'
        ],
        'api': 'https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20250303.json'
    },
    'GCP': {
        'patterns': [
            r'^.*\.compute\.googleapis\.com$',
            r'^.*\.googleapis\.com$'
        ],
        'api': 'https://www.gstatic.com/ipranges/cloud.json'
    },
    'DigitalOcean': {
        'patterns': [
            r'^.*\.digitalocean\.com$'
        ]
    },
    'Oracle Cloud': {
        'patterns': [
            r'^.*\.oraclecloud\.com$'
        ]
    }
}

def print_banner():
    """Display the ASCII art banner"""
    print(BANNER)
    print()

def ping_host(ip):
    """Ping a host and return True if reachable"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '2000' if platform.system().lower() == 'windows' else '2'
    
    command = ['ping', param, '1', timeout, timeout_val, str(ip)]
    
    try:
        if platform.system().lower() == 'windows':
            subprocess.check_output(command, stderr=subprocess.DEVNULL, shell=True)
        else:
            subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def get_ptr_record(ip):
    """Perform reverse DNS lookup"""
    try:
        rev_name = dns.reversename.from_address(str(ip))
        answers = dns.resolver.resolve(rev_name, "PTR")
        return str(answers[0].target)
    except:
        return None

def get_cloud_provider(ip, ptr_record):
    """Detect cloud provider based on PTR record and IP ranges"""
    if ptr_record:
        ptr_lower = ptr_record.lower()
        for provider, info in CLOUD_PROVIDERS.items():
            for pattern in info.get('patterns', []):
                if re.search(pattern, ptr_lower):
                    return provider
    
    # Check against cloud IP ranges using APIs
    # This is a simplified version - in production you'd cache these
    return "Unknown"

def check_ip_with_cloud_apis(ip):
    """Check IP against cloud provider APIs"""
    provider = "Unknown"
    details = {}
    
    try:
        # Check AWS IP ranges
        response = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            for prefix in data.get('prefixes', []):
                if ipaddress.ip_address(ip) in ipaddress.ip_network(prefix['ip_prefix']):
                    provider = "AWS"
                    details['region'] = prefix.get('region')
                    details['service'] = prefix.get('service')
                    break
    except:
        pass
    
    if provider == "Unknown":
        try:
            # Check Azure IP ranges
            response = requests.get('https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20250303.json', timeout=5)
            if response.status_code == 200:
                data = response.json()
                for value in data.get('values', []):
                    for prefix in value.get('properties', {}).get('addressPrefixes', []):
                        if '/' in prefix:
                            if ipaddress.ip_address(ip) in ipaddress.ip_network(prefix):
                                provider = "Azure"
                                details['region'] = value.get('properties', {}).get('region')
                                details['service'] = value.get('properties', {}).get('systemService')
                                break
                        else:
                            if ip == prefix:
                                provider = "Azure"
                                details['region'] = value.get('properties', {}).get('region')
                                details['service'] = value.get('properties', {}).get('systemService')
                                break
                if provider != "Unknown":
                    break
        except:
            pass
    
    if provider == "Unknown":
        try:
            # Check GCP IP ranges
            response = requests.get('https://www.gstatic.com/ipranges/cloud.json', timeout=5)
            if response.status_code == 200:
                data = response.json()
                for prefix in data.get('prefixes', []):
                    ip_range = prefix.get('ipv4Prefix') or prefix.get('ipv6Prefix')
                    if ip_range and ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                        provider = "GCP"
                        details['region'] = prefix.get('scope')
                        break
        except:
            pass
    
    return provider, details

def nslookup_ip(ip):
    """Perform various DNS lookups on an IP"""
    results = {
        'ip': str(ip),
        'ptr': None,
        'a_records': [],
        'mx_records': [],
        'txt_records': []
    }
    
    # Get PTR record
    ptr = get_ptr_record(ip)
    if ptr:
        results['ptr'] = ptr
    
    # Try to get A records for the PTR
    if ptr:
        try:
            answers = dns.resolver.resolve(ptr, 'A')
            results['a_records'] = [str(r) for r in answers]
        except:
            pass
        
        # Try MX records
        try:
            domain = '.'.join(ptr.split('.')[-3:])  # Extract domain from FQDN
            answers = dns.resolver.resolve(domain, 'MX')
            results['mx_records'] = [f"{r.exchange} (priority: {r.preference})" for r in answers]
        except:
            pass
        
        # Try TXT records
        try:
            domain = '.'.join(ptr.split('.')[-3:])
            answers = dns.resolver.resolve(domain, 'TXT')
            results['txt_records'] = [str(r) for r in answers[:3]]  # Limit to 3 TXT records
        except:
            pass
    
    return results

def mfasweep_scan(email):
    """Perform MFASweep-like scan against Microsoft Online"""
    print(f"\n{Fore.YELLOW}[*] Starting MFASweep scan for: {email}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Checking Microsoft Online services...{Style.RESET_ALL}")
    
    # This is a simplified implementation of MFASweep concepts
    # In practice, you would use the actual MFASweep tool or implement the API calls
    
    results = {
        'email': email,
        'office365': False,
        'mfa_enabled': False,
        'auth_methods': [],
        'legacy_auth_enabled': False,
        'conditional_access': False
    }
    
    try:
        # Check Office 365 tenant existence
        response = requests.get(f'https://login.microsoftonline.com/{email}', timeout=10, allow_redirects=False)
        if response.status_code in [200, 302]:
            results['office365'] = True
            
            # Basic MFA detection (simplified)
            # In reality, you'd need to check different endpoints
            
            # Check for MFA claim in authentication
            response = requests.get(
                f'https://login.microsoftonline.com/common/GetCredentialType',
                json={'username': email},
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('EstsAuthEnabled'):
                    results['mfa_enabled'] = True
                
                # Check for legacy authentication
                if data.get('EstsLegacyAuthEnabled'):
                    results['legacy_auth_enabled'] = True
                    results['auth_methods'].append('Legacy Authentication (Insecure)')
                
                # Check authentication methods
                if data.get('EstsMFA'):
                    results['mfa_enabled'] = True
                    results['auth_methods'].append('Multi-Factor Authentication')
                    results['auth_methods'].append('Microsoft Authenticator')
                
                # Conditional Access Policies
                if data.get('EstsConditionalAccessPolicies'):
                    results['conditional_access'] = True
                    results['auth_methods'].append('Conditional Access Policies')
    
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}[-] Error connecting to Microsoft services{Style.RESET_ALL}")
    
    # Display MFASweep results
    print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════{Style.RESET_ALL}")
    print(f"{Fore.CYAN}MFASweep Results for: {email}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}═══════════════════════════════════════════════════════{Style.RESET_ALL}")
    
    for key, value in results.items():
        if key == 'email':
            continue
        color = Fore.GREEN if value else Fore.RED
        status = "✓" if value else "✗"
        if isinstance(value, list) and value:
            print(f"{Fore.GREEN}✓ {key.replace('_', ' ').title()}: {', '.join(value)}{Style.RESET_ALL}")
        elif isinstance(value, bool):
            print(f"{color}{status} {key.replace('_', ' ').title()}: {value}{Style.RESET_ALL}")
        elif value:
            print(f"{Fore.GREEN}✓ {key.replace('_', ' ').title()}: {value}{Style.RESET_ALL}")
    
    return results

def scan_cidr(cidr_network):
    """Scan all IP addresses in a CIDR network"""
    try:
        network = ipaddress.ip_network(cidr_network, strict=False)
        total_ips = network.num_addresses - 2
        
        print(f"\n{Fore.CYAN}[*] Scanning network: {cidr_network}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total hosts to scan: {total_ips}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] This may take a while...{Style.RESET_ALL}")
        print("-" * 60)
        
        alive_hosts = {}
        dead_hosts = []
        host_details = {}
        
        # Scan all IPs
        for idx, ip in enumerate(network.hosts(), 1):
            print(f"[{idx}/{total_ips}] Pinging {ip}...", end=' ', flush=True)
            
            if ping_host(ip):
                print(f"{Fore.GREEN}✓ Host is up{Style.RESET_ALL}")
                alive_hosts[str(ip)] = {
                    'reachable': True,
                    'ptr': None,
                    'cloud_provider': 'Unknown',
                    'details': {}
                }
            else:
                print(f"{Fore.RED}✗ No response{Style.RESET_ALL}")
                dead_hosts.append(str(ip))
        
        # Show alive hosts
        if alive_hosts:
            print(f"\n{Fore.GREEN}═══════════════════════════════════════════════════════{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Alive Hosts Found: {len(alive_hosts)}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}═══════════════════════════════════════════════════════{Style.RESET_ALL}")
            
            # Process alive hosts with cloud detection
            print(f"\n{Fore.YELLOW}[*] Performing cloud detection and DNS lookups on alive hosts...{Style.RESET_ALL}")
            
            for ip in list(alive_hosts.keys()):
                print(f"\n{Fore.CYAN}[+] Processing: {ip}{Style.RESET_ALL}")
                
                # Get PTR record
                ptr = get_ptr_record(ip)
                if ptr:
                    alive_hosts[ip]['ptr'] = ptr
                    print(f"    {Fore.WHITE}PTR: {ptr}{Style.RESET_ALL}")
                
                # Detect cloud provider using API
                provider, details = check_ip_with_cloud_apis(ip)
                alive_hosts[ip]['cloud_provider'] = provider
                alive_hosts[ip]['details'] = details
                
                if provider != "Unknown":
                    print(f"    {Fore.GREEN}☁️  Cloud Provider: [{provider}]{Style.RESET_ALL}")
                    if details.get('region'):
                        print(f"    {Fore.WHITE}   Region: {details['region']}{Style.RESET_ALL}")
                    if details.get('service'):
                        print(f"    {Fore.WHITE}   Service: {details['service']}{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.YELLOW}🌐 Cloud Provider: Not detected{Style.RESET_ALL}")
            
            # Perform detailed nslookup on all alive hosts
            print(f"\n{Fore.YELLOW}[*] Performing comprehensive nslookup on all alive hosts...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}═══════════════════════════════════════════════════════{Style.RESET_ALL}")
            
            for ip in alive_hosts.keys():
                print(f"\n{Fore.GREEN}📡 NSLookup Results for: {ip}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{'─' * 50}{Style.RESET_ALL}")
                
                dns_results = nslookup_ip(ip)
                
                if dns_results['ptr']:
                    print(f"  {Fore.CYAN}PTR Record: {Fore.WHITE}{dns_results['ptr']}{Style.RESET_ALL}")
                
                if dns_results['a_records']:
                    print(f"  {Fore.CYAN}A Records: {Fore.WHITE}{', '.join(dns_results['a_records'])}{Style.RESET_ALL}")
                
                if dns_results['mx_records']:
                    print(f"  {Fore.CYAN}MX Records:{Style.RESET_ALL}")
                    for mx in dns_results['mx_records']:
                        print(f"    {Fore.WHITE}  • {mx}{Style.RESET_ALL}")
                
                if dns_results['txt_records']:
                    print(f"  {Fore.CYAN}TXT Records:{Style.RESET_ALL}")
                    for txt in dns_results['txt_records']:
                        print(f"    {Fore.WHITE}  • {txt[:100]}{'...' if len(txt) > 100 else ''}{Style.RESET_ALL}")
    
    except ValueError as e:
        print(f"{Fore.RED}Error: Invalid CIDR notation.{Style.RESET_ALL}")
        print(f"Details: {e}")
        sys.exit(1)

def main():
    """Main function"""
    print_banner()
    
    # Get CIDR input
    if len(sys.argv) > 1:
        cidr = sys.argv[1]
    else:
        cidr = input(f"{Fore.CYAN}Enter network in CIDR notation (e.g., 192.168.1.0/24): {Style.RESET_ALL}").strip()
    
    if not cidr:
        print(f"{Fore.RED}Error: No CIDR provided.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Run scan
    scan_cidr(cidr)
    
    # Ask about Microsoft Online account
    print(f"\n{Fore.YELLOW}═══════════════════════════════════════════════════════{Style.RESET_ALL}")
    response = input(f"{Fore.CYAN}Do you have a valid Microsoft Online account? (y/n): {Style.RESET_ALL}").strip().lower()
    
    if response in ['y', 'yes']:
        email = input(f"{Fore.CYAN}Enter the email address to scan: {Style.RESET_ALL}").strip()
        if email:
            mfasweep_scan(email)
        else:
            print(f"{Fore.RED}No email provided. Skipping MFASweep.{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}MFASweep skipped.{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[✓] Scan complete!{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}\n[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)
