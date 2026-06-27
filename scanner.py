import ipaddress
import subprocess
import platform
import sys
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init(autoreset=True)

def ping_host(ip):
    """
    Ping a host and return True if it's reachable, False otherwise.
    Works on Windows, Linux, and macOS.
    """
    # Determine ping command based on OS
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    
    # Build the ping command
    command = ['ping', param, '1', timeout, timeout_val, str(ip)]
    
    try:
        # Suppress output by redirecting to null
        if platform.system().lower() == 'windows':
            subprocess.check_output(command, stderr=subprocess.DEVNULL, shell=True)
        else:
            subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def scan_cidr(cidr_network):
    """
    Scan all IP addresses in a CIDR network and print results.
    """
    try:
        # Parse the CIDR notation
        network = ipaddress.ip_network(cidr_network, strict=False)
        
        print(f"\n{Fore.CYAN}Scanning network: {cidr_network}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total hosts to scan: {network.num_addresses - 2} (excluding network and broadcast){Style.RESET_ALL}")
        print("-" * 50)
        
        alive_hosts = []
        dead_hosts = []
        
        # Iterate through all IPs in the network
        for ip in network.hosts():  # .hosts() excludes network and broadcast addresses
            print(f"Pinging {ip}...", end=' ', flush=True)
            
            if ping_host(ip):
                print(f"{Fore.GREEN}✓ Host is up{Style.RESET_ALL}")
                alive_hosts.append(str(ip))
            else:
                print(f"{Fore.RED}✗ No response from host{Style.RESET_ALL}")
                dead_hosts.append(str(ip))
        
        # Print summary
        print("\n" + "=" * 50)
        print(f"{Fore.CYAN}Scan Complete!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Alive hosts ({len(alive_hosts)}):{Style.RESET_ALL}")
        for ip in alive_hosts:
            print(f"  {Fore.GREEN}{ip}{Style.RESET_ALL}")
        
        print(f"{Fore.RED}Dead hosts ({len(dead_hosts)}):{Style.RESET_ALL}")
        for ip in dead_hosts[:10]:  # Show only first 10 dead hosts to avoid clutter
            print(f"  {Fore.RED}{ip}{Style.RESET_ALL}")
        if len(dead_hosts) > 10:
            print(f"  {Fore.YELLOW}... and {len(dead_hosts) - 10} more{Style.RESET_ALL}")
            
    except ValueError as e:
        print(f"{Fore.RED}Error: Invalid CIDR notation. Please use format like '192.168.1.0/24'{Style.RESET_ALL}")
        print(f"Details: {e}")
        sys.exit(1)

def main():
    """
    Main function to handle user input and start the scan.
    """
    print(f"{Fore.CYAN}IP CIDR Scanner{Style.RESET_ALL}")
    print("=" * 50)
    
    # Get CIDR input from user
    if len(sys.argv) > 1:
        cidr = sys.argv[1]
    else:
        cidr = input("Enter network in CIDR notation (e.g., 192.168.1.0/24): ").strip()
    
    if not cidr:
        print(f"{Fore.RED}Error: No CIDR provided.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Start scanning
    scan_cidr(cidr)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}\nScan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)