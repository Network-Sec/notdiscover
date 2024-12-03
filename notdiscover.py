from scapy.all import *
import ipaddress
import argparse
import sys

# List available interfaces using Scapy's `conf.ifaces`
def list_interfaces():
    print("Available Interfaces:")
    interfaces = scapy.interfaces
    interfaces.show_interfaces()

# Map human-readable interface names or index numbers to Scapy-compatible names
def resolve_interface(interface_input):
    resolved_interface = None

    # If the input is numeric, treat it as an index
    if interface_input.isdigit():
        index = int(interface_input)
        # Search for the interface by index
        for iface in conf.ifaces.values():
            if iface.index == index:
                resolved_interface = iface.name
                break
    else:
        # Otherwise, treat it as a human-readable name and search by name
        for iface in conf.ifaces.values():
            if interface_input in iface.name:
                resolved_interface = iface.name
                break

    if resolved_interface is None:
        print(f"Error: Could not resolve interface '{interface_input}' to a valid Scapy-compatible name.")
        sys.exit(1)

    return resolved_interface

# Get the IP range for the interface
def get_ip_range(interface_name):
    try:
        ip = scapy.get_if_addr(interface_name)
        if not ip:
            print(f"Error: Unable to retrieve IP address for interface '{interface_name}'.")
            sys.exit(1)
        return f"{ip}/24"
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

# Perform an ARP scan
from scapy.all import ARP, Ether, srp, conf
import ipaddress
import sys

def scan(ip_range, interface_name, passive=False, timeout=0.5, chunk_size=256, verbose=False, no_colors=False):
    if passive:
        print("Passive mode is not implemented yet.")
        sys.exit(1)

    # Set the interface for Scapy to use
    conf.iface = interface_name

    try:
        # Generate all IP addresses in the range
        all_ips = [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
    except ValueError as e:
        print(f"Error parsing IP range: {e}")
        return []

    # Split IP range into manageable chunks
    ip_chunks = [all_ips[i:i + chunk_size] for i in range(0, len(all_ips), chunk_size)]

    devices_list = []

    # Print header
    if no_colors:
        print("IP Address\t\tMAC Address")
        print("-----------------------------------------")
    else:
        print("\033[1;32mIP Address\033[0m\t\t\033[1;34mMAC Address\033[0m")
        print("-----------------------------------------")

    # Process each chunk
    for chunk in ip_chunks:
        if verbose:
            print(f"Scanning chunk: {chunk[0]} - {chunk[-1]}")

        # Create ARP request for this chunk
        arp_request = ARP(pdst=chunk)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Send ARP request and capture responses
        answered, unanswered = srp(arp_request_broadcast, timeout=timeout, verbose=verbose)

        for sent, received in answered:
            if no_colors:
                print(f"{received.psrc}\t\t{received.hwsrc}")
            else:
                print(f"\033[1;32m{received.psrc}\033[0m\t\t\033[1;34m{received.hwsrc}\033[0m")
            devices_list.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices_list

# Display results in a formatted table
def display_result(devices_list, no_colors, verbose):
    if verbose:
        print(f"Found {len(devices_list)} devices:")
    
    if no_colors:
        print("IP Address\t\tMAC Address")
        print("-----------------------------------------")
    else:
        print("\033[1;32mIP Address\033[0m\t\t\033[1;34mMAC Address\033[0m")
        print("-----------------------------------------")
    
    for device in devices_list:
        if no_colors:
            print(f"{device['ip']}\t\t{device['mac']}")
        else:
            print(f"\033[1;32m{device['ip']}\033[0m\t\t\033[1;34m{device['mac']}\033[0m")

# Main function
def main():
    parser = argparse.ArgumentParser(description="A Python tool for ARP scanning, similar to Netdiscover.")
    parser.add_argument('-i', '--interface', type=str, help="Network interface to use (e.g., Ethernet, wlan0)")
    parser.add_argument('-r', '--range', type=str, help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument('-p', '--passive', action='store_true', help="Run in passive mode (only listen for responses)")
    parser.add_argument('-t', '--timeout', type=int, default=0.5, help="Timeout for each ARP request (default: 1s)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Show verbose output")
    parser.add_argument('-c', '--count', type=int, default=5, help="Number of IPs to probe before declaring it alive (default: 5)")
    parser.add_argument('-n', '--no-colors', action='store_true', help="Disable colored output")
    parser.add_argument('--list-interfaces', '-l', action='store_true', help="List all available network interfaces")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    if not args.interface:
        print("Error: Interface not specified. Use --list-interfaces to view available interfaces.")
        sys.exit(1)

    # Resolve interface using either index or name
    interface = resolve_interface(args.interface)
    ip_range = args.range or get_ip_range(interface)

    print(f"Scanning network: {ip_range}")
    devices_list = scan(ip_range, interface, args.passive, args.timeout, verbose=args.verbose)
    #display_result(devices_list, args.no_colors, args.verbose)

if __name__ == "__main__":
    main()
