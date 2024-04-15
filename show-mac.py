import pandas as pd
import getpass
import yaml
import logging
import re
from netmiko import ConnectHandler
from openpyxl import Workbook

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_device_info(file_path='devices.yaml'):
    with open(file_path) as file:
        devices = yaml.safe_load(file)
    return devices['switches']

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
        match = re.match(r'^(mgmt0|Eth\d+/\d+(/\d+)?|Po\d+)\s+(.*)', line, re.IGNORECASE)
        if match:
            interface, description = match.groups()[0], match.groups()[-1]
            desc_entries[interface.strip()] = description.strip()
    return desc_entries

def parse_show_interface_brief(output):
    brief_entries = {}
    for line in output.splitlines():
        match = re.match(r'^(mgmt0|Eth\d+/\d+(/\d+)?|Po\d+)\s+\S+\s+\S+\s+\S+\s+(\w+)', line, re.IGNORECASE)
        if match:
            interface, status = match.groups()[0], match.groups()[-1]
            brief_entries[interface] = {'Status': status}
    return brief_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    for line in output.splitlines():
        match = re.match(r'^\*\s+\d+\s+([0-9a-f:.]+)\s+dynamic\s+.*\s+(\S+)', line, re.IGNORECASE)
        if match:
            mac_address, port = match.groups()
            mac_entries.setdefault(port, []).append(mac_address)
    return mac_entries

def combine_data(device, brief_data, desc_data, mac_data):
    combined_data = []
    for interface, details in brief_data.items():
        mac_addresses = mac_data.get(interface, ['N/A'])
        description = desc_data.get(interface, 'No description')
        status = details['Status']
        for mac in mac_addresses:
            combined_data.append({
                'Device': device,
                'Interface': interface,
                'Status': status,
                'Description': description,
                'MAC Address': mac
            })
    return combined_data

def main():
    devices = read_device_info()
    if not devices:  # Ensure there are devices to process
        logging.error("No devices found. Check your YAML file.")
        return

    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device_hostname in devices:
        device_info = {
            'device_type': 'cisco_nxos',
            'host': device_hostname,
            'username': username,
            'password': password,
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
        df = pd.DataFrame(all_data)
        df.to_excel('network_data.xlsx', index=False)
        logging.info("Data successfully saved to network_data.xlsx.")
    else:
        logging.warning("No data collected.")

if __name__ == "__main__":
    main()
