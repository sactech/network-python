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
    try:
        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(hostname=host, username=username, password=password, timeout=10)
            stdin, stdout, stderr = client.exec_command(command)
            return stdout.read().decode('utf-8').strip()
    except Exception as e:
        logging.error(f"Failed to execute command on {host}: {e}")
        return ""

def parse_show_interface_status(output):
    status_entries = []
    lines = output.splitlines()
    for line in lines[2:]:  # Skip header lines
        match = re.match(r'(\S+)\s+([\w\s\-\.\/]+)\s+(connected|notconnect|disabled|sfpAbsent|down)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
        if match:
            port, name, status, vlan, duplex, speed, type = match.groups()
            status_entries.append({
                'Port': port,
                'Name': name.strip(),
                'Status': status,
                'Vlan': vlan,
                'Duplex': duplex,
                'Speed': speed,
                'Type': type
            })
    return status_entries

def parse_show_interface_description(output):
    desc_entries = {}
    lines = output.splitlines()
    for line in lines:
        match = re.match(r'^(mgmt0|Eth[\d/]+|Po\d+|Lo\d+)\s+(\S+.*\S)\s*$', line)
        if match:
            interface, description = match.groups()
            desc_entries[interface.strip()] = description.strip()
    return desc_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    lines = output.splitlines()
    for line in lines:
        match = re.match(r'^\*?\s+(\d+|-)\s+([0-9a-fA-F\.]+)\s+\w+\s+\d+\s+\w+\s+(\S+)', line)
        if match:
            vlan, mac_address, port = match.groups()
            if vlan.isdigit():  # Check if VLAN is a valid number
                mac_entries.setdefault(port, []).append(mac_address)
    return mac_entries

def combine_data(status_data, desc_data, mac_data):
    combined_data = []
    for entry in status_data:
        port = entry['Port']
        combined_entry = entry.copy()
        combined_entry.update(desc_data.get(port, {'Description': 'N/A'}))
        mac_entries = mac_data.get(port, ['N/A'])
        for mac in mac_entries:
            combined_data.append({**combined_entry, 'MAC Address': mac})
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device in devices:
        logging.info(f"Processing device: {device}")

        status_output = execute_command(device, username, password, "show interface status")
        status_data = parse_show_interface_status(status_output)

        desc_output = execute_command(device, username, password, "show interface description")
        desc_data = parse_show_interface_description(desc_output)

        mac_output = execute_command(device, username, password, "show mac address-table")
        mac_data = parse_show_mac_address_table(mac_output)

        device_data = combine_data(status_data, desc_data, mac_data)
        all_data.extend(device_data)

    df = pd.DataFrame(all_data)
    df.to_csv('network_data_combined.csv', index=False)
    logging.info("Data successfully saved to network_data_combined.csv.")

if __name__ == "__main__":
    main()
