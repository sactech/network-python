import pandas as pd
import yaml
import getpass
import logging
from netmiko import ConnectHandler
from openpyxl import Workbook
import socket

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load devices from YAML
def load_devices(filename):
    with open(filename, 'r') as file:
        devices = yaml.safe_load(file)
    return devices

# Parse VRFs
def parse_vrfs(vrf_output):
    vrf_list = []
    for line in vrf_output.splitlines():
        if 'ipv4' in line:
            vrf_name = line.split()[0]
            vrf_list.append(vrf_name)
    return vrf_list

# Parse ARP
def parse_arp(arp_output):
    arp_entries = []
    for line in arp_output.splitlines():
        if 'ARPA' in line:
            parts = line.split()
            ip_address = parts[1]
            mac_address = parts[3]
            interface = parts[5]
            arp_entries.append({'IP Address': ip_address, 'MAC Address': mac_address, 'Interface': interface})
    return pd.DataFrame(arp_entries)

# Parse Nexus ARP
def parse_nexus_arp(arp_output):
    arp_entries = []
    start_parsing = False
    for line in arp_output.splitlines():
        if 'Address' in line and 'MAC Address' in line:
            start_parsing = True
            continue
        if start_parsing and line.strip():
            parts = line.split()
            ip_address = parts[0]
            mac_address = parts[2]
            interface = parts[3]
            arp_entries.append({'IP Address': ip_address, 'MAC Address': mac_address, 'Interface': interface})
    return pd.DataFrame(arp_entries)

# DNS resolution
def resolve_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Resolution Failed"

# Fetch ARP data
def fetch_arp_data(device, username, password, device_type):
    device_config = {
        'device_type': 'cisco_ios' if device_type == 'router' else 'cisco_nxos',
        'host': device,
        'username': username,
        'password': password
    }
    try:
        with ConnectHandler(**device_config) as conn:
            if device_type == 'switch':
                output = conn.send_command('show ip arp vrf all')
                return parse_nexus_arp(output)
            elif device_type == 'router':
                vrfs_output = conn.send_command('show vrf')
                vrfs = parse_vrfs(vrfs_output)
                all_vrfs_arp_data = pd.DataFrame()
                for vrf in vrfs:
                    arp_output = conn.send_command(f'show ip arp vrf {vrf}')
                    vrf_arp_data = parse_arp(arp_output)
                    vrf_arp_data['VRF'] = vrf
                    all_vrfs_arp_data = pd.concat([all_vrfs_arp_data, vrf_arp_data])
                return all_vrfs_arp_data
    except Exception as e:
        logging.error(f"Failed to connect or retrieve data from {device}: {e}")
        return pd.DataFrame()

# Main function
def main():
    devices = load_devices('devices.yaml')
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    results = pd.DataFrame()
    
    for device in devices.get('switches', []):
        logging.info(f"Fetching ARP data from switch: {device}")
        arp_data = fetch_arp_data(device, username, password, 'switch')
        results = pd.concat([results, arp_data])
        
    for device in devices.get('routers', []):
        logging.info(f"Fetching ARP data from router: {device}")
        arp_data = fetch_arp_data(device, username, password, 'router')
        results = pd.concat([results, arp_data])
    
    # Apply DNS resolution
    results['DNS Name'] = results['IP Address'].apply(resolve_dns)

    # Save results to Excel
    results.to_excel('arp_results.xlsx', index=False)
    logging.info("ARP data and DNS resolution have been written to arp_results.xlsx")

if __name__ == '__main__':
    main()
