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
    return devices.get('switches', [])

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
    regex = re.compile(r'^(\*|G)?\s*(\d+|\-)\s+([0-9a-fA-F\.]+)\s+(\S+)\s+[\-\d]+\s+\S+\s+\S+\s+(\S+)')
    lines = output.splitlines()
    for line in lines:
        match = regex.match(line)
        if match:
            vlan, mac_address, _, port = match.groups()[1:]
            if vlan == '-' or not vlan.isdigit():
                continue
            mac_entries.setdefault(port, []).append(mac_address)
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
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device_hostname in devices:
        device_info = {
            'device_type': 'cisco_nxos',
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
