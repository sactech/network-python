import pandas as pd
import getpass
import yaml
import logging
import re
from netmiko import ConnectHandler

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
    for line in output.splitlines():
        match = re.match(r'^(mgmt0|Eth[\d/]+|Po\d+|Lo\d+)\s+(.*)', line)
        if match:
            interface, description = match.groups()
            desc_entries[interface.strip().lower()] = description.strip()
    return desc_entries

def parse_show_interface_brief(output):
    brief_entries = {}
    for line in output.splitlines():
        match = re.match(r'^(mgmt0|Eth[\d/]+|Po\d+|Lo\d+|Tunnel\d+)\s+\S+\s+(\S+)\s+\S+\s+(\S+)', line)
        if match:
            interface, status = match.groups()
            brief_entries[interface.lower()] = {'Status': status}
    return brief_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    for line in output.splitlines():
        match = re.match(r'^\*\s+\S+\s+([0-9a-fA-F.:]+)\s+\S+\s+(\S+)', line)
        if match:
            mac_address, port = match.groups()
            port_key = port.lower().replace('ethernet', 'eth')  # Normalizing port names
            mac_entries.setdefault(port_key, []).append(mac_address)
    return mac_entries

def combine_data(device, brief_data, desc_data, mac_data):
    combined_data = []
    for port, details in brief_data.items():
        mac_addresses = mac_data.get(port, ['N/A'])
        description = desc_data.get(port, 'No description')
        combined_entry = {
            'Device': device,
            'Interface': port.upper(),
            'Description': description,
            'Status': details['Status'],
            'MAC Addresses': ', '.join(mac_addresses)
        }
        combined_data.append(combined_entry)
        logging.debug(f"Combined entry: {combined_entry}")
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device_category, device_list in devices.items():
        for device_hostname in device_list:
            device_info = {
                'device_type': 'cisco_nxos',
                'host': device_hostname,
                'username': username,
                'password': password,
            }

            logging.info(f"Processing {device_category}: {device_hostname}")
            desc_output = execute_command(device_info, "show interface description")
            brief_output = execute_command(device_info, "show interface brief")
            mac_output = execute_command(device_info, "show mac address-table")

            desc_data = parse_show_interface_description(desc_output)
            brief_data = parse_show_interface_brief(brief_output)
            mac_data = parse_show_mac_address_table(mac_output)

            combined_data = combine_data(device_hostname, brief_data, desc_data, mac_data)
            all_data.extend(combined_data)

    if all_data:
        df = pd.DataFrame(all_data)
        df.to_excel('network_data_combined.xlsx', index=False)
        logging.info("Data successfully saved to network_data_combined.xlsx.")
    else:
        logging.warning("No data collected.")

if __name__ == "__main__":
    main()
