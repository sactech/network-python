import pandas as pd
import getpass
import yaml
import logging
import re
from netmiko import ConnectHandler

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_device_info(file_path='devices.yaml'):
    with open(file_path) as file:
        devices = yaml.safe_load(file)
    return devices

def execute_command(device_info, command):
    try:
        logging.info(f"Connecting to device: {device_info['host']}")
        with ConnectHandler(**device_info) as ssh:
            output = ssh.send_command(command)
            logging.debug(f"Command: {command}\nOutput:\n{output}")
            return output
    except Exception as e:
        logging.error(f"Failed to execute command on {device_info['host']}: {e}")
        return ""

def parse_show_interface_description(output):
    desc_entries = {}
    lines = output.splitlines()
    for line in lines:
        match = re.match(r'^(mgmt0|Eth[\d/]+|Po\d+|Lo\d+)\s+(.*)', line)
        if match:
            interface, description = match.groups()
            desc_entries[interface.strip()] = description.strip()
    logging.debug(f"Parsed description data: {desc_entries}")
    return desc_entries

def parse_show_interface_brief(output):
    brief_entries = []
    lines = output.splitlines()
    start_parsing = False
    for line in lines:
        if '-----' in line:
            start_parsing = True
            continue
        if start_parsing:
            match = re.match(r'^(mgmt0|Eth[\d/]+|Po\d+|Lo\d+)\s+(\d+|--)\s+(\S*)\s+(\S*)\s+(\S+).*', line)
            if match:
                interface, vlan, _, _, status = match.groups()
                vlan = 'N/A' if vlan == '--' else vlan
                brief_entries.append({
                    'Port': interface,
                    'VLAN': vlan,
                    'Status': status,
                })
    logging.debug(f"Parsed brief data: {brief_entries}")
    return brief_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    lines = output.splitlines()
    start_index = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("VLAN"):
            start_index = i + 1
            break

    regex = re.compile(r'^\S+\s+(\d+|\-)\s+([0-9a-fA-F\.]{14})\s+(\S+)\s+\S+\s+\S+\s+(\S+)')
    for line in lines[start_index:]:
        match = regex.search(line)
        if match:
            vlan, mac_address, _, port = match.groups()
            if vlan == '-':
                continue
            mac_entries.setdefault(port, []).append(mac_address)
    logging.debug(f"Parsed MAC address data: {mac_entries}")
    return mac_entries

def combine_data(device, brief_data, desc_data, mac_data):
    combined_data = []
    for entry in brief_data:
        port = entry['Port']
        name = desc_data.get(port, 'N/A')
        status = entry['Status']
        vlan = entry['VLAN']
        mac_addresses = mac_data.get(port, ['N/A'])
        for mac_address in mac_addresses:
            combined_entry = {
                'Device': device,
                'Port': port,
                'Name': name,
                'Status': status,
                'VLAN': vlan,
                'MAC Address': mac_address
            }
            combined_data.append(combined_entry)
    logging.debug(f"Combined data: {combined_data}")
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device_hostname in devices['switches']:
        device_info = {
            'device_type': 'cisco_nxos',  # Specific to Cisco NX-OS devices
            'host': device_hostname,
            'username': username,
            'password': password
        }
        logging.info(f"Processing device: {device_hostname}")
        desc_output = execute_command(device_info, "show interface description")
        brief_output = execute_command(device_info, "show interface brief")
        mac_output = execute_command(device_info, "show mac address-table")

        desc_data = parse_show_interface_description(desc_output)
                brief_data = parse_show_interface_brief(brief_output)
        mac_data = parse_show_mac_address_table(mac_output)

        combined_data = combine_data(device_hostname, brief_data, desc_data, mac_data)

        all_data.extend(combined_data)

    if all_data:
        df = pd.DataFrame.from_records(all_data)
        df.to_csv('network_data_combined.csv', index=False)
        logging.info("Data successfully saved to network_data_combined.csv.")
    else:
        logging.warning("No data collected.")

if __name__ == "__main__":
    main()
