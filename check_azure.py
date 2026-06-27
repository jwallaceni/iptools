#!/usr/bin/env python3
"""
Script to check if an IP address belongs to Azure using checkip.cloud API
"""

import requests
import sys
import json
import argparse

def check_ip_azure(ip_address, debug=False):
    """
    Check if an IP address belongs to Azure using checkip.cloud API
    
    Args:
        ip_address (str): IPv4 address to check
        debug (bool): Enable debug output
    
    Returns:
        dict: API response or None if error
    """
    url = f"https://checkip.cloud/api/ip/{ip_address}"
    
    try:
        if debug:
            print(f"[DEBUG] Making request to: {url}", file=sys.stderr)
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # Parse JSON response
        data = response.json()
        
        if debug:
            print(f"[DEBUG] Response status: {response.status_code}", file=sys.stderr)
            print(f"[DEBUG] Response keys: {list(data.keys())}", file=sys.stderr)
        
        # Check multiple possible locations for Azure provider info
        is_azure = False
        azure_details = {}
        
        # Try different possible paths in the response
        if 'cloud' in data:
            cloud_data = data['cloud']
            if debug:
                print(f"[DEBUG] Cloud data keys: {list(cloud_data.keys()) if isinstance(cloud_data, dict) else 'not a dict'}", file=sys.stderr)
            
            # Check provider field
            if isinstance(cloud_data, dict):
                provider = cloud_data.get('provider', '')
                if provider and provider.lower() == 'azure':
                    is_azure = True
                    azure_details = cloud_data
                elif debug:
                    print(f"[DEBUG] Provider found: '{provider}'", file=sys.stderr)
        
        # If not found in 'cloud', check other possible paths
        if not is_azure and 'provider' in data:
            if data['provider'].lower() == 'azure':
                is_azure = True
                azure_details = data
        
        # Some APIs use 'organisation' or 'org' field
        if not is_azure and 'organisation' in data:
            if 'azure' in data['organisation'].lower():
                is_azure = True
                azure_details = data
        
        return {
            'ip': ip_address,
            'data': data,
            'is_azure': is_azure,
            'azure_details': azure_details
        }
    
    except requests.exceptions.RequestException as e:
        print(f"Error making API request: {e}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Check if an IP address belongs to Azure using checkip.cloud API'
    )
    parser.add_argument(
        'ip_address',
        type=str,
        help='IPv4 address to check (e.g., 4.149.254.68)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print detailed JSON output'
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug output'
    )
    
    args = parser.parse_args()
    
    # Basic IP validation
    ip_parts = args.ip_address.split('.')
    if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
        print(f"Error: '{args.ip_address}' is not a valid IPv4 address", file=sys.stderr)
        sys.exit(1)
    
    # Check the IP
    result = check_ip_azure(args.ip_address, debug=args.debug)
    
    if result is None:
        sys.exit(1)
    
    # Output results
    if args.verbose:
        print("Full API Response:")
        print(json.dumps(result['data'], indent=2))
    
    # Check if Azure using multiple methods
    is_azure = result['is_azure']
    
    # Also try to grep for Azure-like strings in the response
    response_str = json.dumps(result['data']).lower()
    has_azure_string = 'azure' in response_str
    
    if args.debug:
        print(f"[DEBUG] is_azure flag: {is_azure}", file=sys.stderr)
        print(f"[DEBUG] Contains 'azure' string: {has_azure_string}", file=sys.stderr)
    
    # Display results
    if is_azure or has_azure_string:
        print(f"✅ IP {args.ip_address} is an Azure asset IP")
        
        # Try to extract Azure details
        if result['azure_details']:
            if 'region' in result['azure_details']:
                print(f"   Region: {result['azure_details']['region']}")
            if 'service' in result['azure_details']:
                print(f"   Service: {result['azure_details']['service']}")
        elif 'cloud' in result['data'] and isinstance(result['data']['cloud'], dict):
            cloud = result['data']['cloud']
            if cloud.get('region'):
                print(f"   Region: {cloud['region']}")
            if cloud.get('service'):
                print(f"   Service: {cloud['service']}")
        
        sys.exit(0)
    else:
        provider = result['data'].get('cloud', {}).get('provider', 'Unknown')
        print(f"❌ IP {args.ip_address} is NOT in Azure")
        if provider != 'Unknown':
            print(f"   Provider: {provider}")
        sys.exit(1)

if __name__ == "__main__":
    main()
