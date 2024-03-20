import paramiko
import pandas as pd
import getpass
import yaml
import logging
import re
from paramiko import SSHClient, AutoAddPolicy

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_device_info(file_path='devices.yaml'):
    with open(file_path) as file:
        devices = yaml.safe_load(file)
    return devices.get('switches', [])

def execute_command(host, username, password, command):
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode('utf-8').strip()

def parse_show_interface_description(output):
    desc_entries = {}
    lines = output.splitlines()
    for line in lines:
        if line.startswith('Eth') or line.startswith('mgmt'):
            parts = line.split()
            desc_entries[parts[0]] = ' '.join(parts[1:])
    return desc_entries

def parse_show_interface_brief(output):
    brief_entries = {}
    lines = output.splitlines()
    for line in lines:
        if line.startswith('Eth'):
            parts = line.split()
            interface, status, vlan = parts[0], parts[-1], parts[-3]
            brief_entries[interface] = {'status': status, 'vlan': vlan}
    return brief_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^\*\s+\d+\s+([0-9a-f\.]{14})', line):
            parts = line.split()
            vlan, mac, interface = parts[1], parts[2], parts[-1]
            if interface not in mac_entries:
                mac_entries[interface] = []
            mac_entries[interface].append(mac)
    return mac_entries

def combine_data(device, desc_data, brief_data, mac_data):
    combined_data = []
    for interface, desc in desc_data.items():
        data = {
            'Device': device,
            'Interface': interface,
            'Description': desc,
            'Status': brief_data.get(interface, {}).get('status', 'N/A'),
            'VLAN': brief_data.get(interface, {}).get('vlan', 'N/A'),
            'MAC Address': ', '.join(mac_data.get(interface, 'N/A'))
        }
        combined_data.append(data)
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")
    all_data = []

    for device in devices:
        logging.info(f"Processing device: {device}")
        desc_output = execute_command(device, username, password, "show interface description")
        brief_output = execute_command(device, username, password, "show interface brief")
        mac_output = execute_command(device, username, password, "show mac address-table")
        
        desc_data = parse_show_interface_description(desc_output)
        brief_data = parse_show_interface_brief(brief_output)
        mac_data = parse_show_mac_address_table(mac_output)
        
        device_data = combine_data(device, desc_data, brief_data, mac_data)
        all_data.extend(device_data)

    if all_data:
        df = pd.DataFrame(all_data)
        df.to_csv('network_data_combined.csv', index=False)
        logging.info(f"Data successfully saved to network_data_combined.csv.")

if __name__ == "__main__":
    main()
