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

def parse_show_interface_description(output):
    desc_entries = {}
    for line in output.splitlines():
        match = re.match(r'^(Eth[0-9/]+)\s+(.*)', line)
        if match:
            interface, description = match.groups()
            desc_entries[interface] = {'Description': description.strip()}
    return desc_entries

def parse_show_interface_brief(output):
    brief_entries = {}
    for line in output.splitlines():
        match = re.match(r'^(Eth[0-9/]+)\s+\w+\s+\w+\s+(\w+)\s+(\d+|trunk|--)', line)
        if match:
            interface, status, vlan = match.groups()
            brief_entries[interface] = {
                'Status': 'up' if status == 'connected' else 'down',
                'VLAN': vlan if vlan.isdigit() or vlan == 'trunk' else 'N/A'
            }
    return brief_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    for line in output.splitlines()[2:]: # Adjust index to skip headers
        match = re.match(r'^\*\s+(\d+|All)\s+([0-9a-f\.]+)\s+\w+\s+\S+\s+(Eth[0-9/]+)', line)
        if match:
            vlan, mac_address, interface = match.groups()
            mac_entries.setdefault(interface, []).append(mac_address)
    return mac_entries

def combine_data(device, desc_data, brief_data, mac_data):
    combined_data = []
    for interface, b_data in brief_data.items():
        desc = desc_data.get(interface, {}).get('Description', 'N/A')
        macs = mac_data.get(interface, [])
        for mac in macs:
            combined_data.append({
                'Device': device,
                'Interface': interface,
                'Description': desc,
                'Status': b_data['Status'],
                'VLAN': b_data['VLAN'],
                'MAC Address': mac
            })
        if not macs:
            combined_data.append({
                'Device': device,
                'Interface': interface,
                'Description': desc,
                'Status': b_data['Status'],
                'VLAN': b_data['VLAN'],
                'MAC Address': 'N/A'
            })
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

    df = pd.DataFrame(all_data)
    if not df.empty:
        df.to_csv('network_data_combined.csv', index=False)
        logging.info("Data successfully saved to 'network_data_combined.csv'.")
    else:
        logging.warning("No data collected to write to CSV.")

if __name__ == "__main__":
    main()
