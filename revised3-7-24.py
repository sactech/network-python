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
            command_output = stdout.read().decode('utf-8').strip()
            if not command_output:
                logging.warning(f"No output for {command} on {host}.")
                return None
            return command_output
    except Exception as e:
        logging.error(f"Failed to execute command on {host}: {e}")
        return None

def parse_show_interface_description(output):
    desc_entries = {}
    for line in output.splitlines():
        match = re.match(r'^(mgmt0|Eth[\d/]+|Po\d+|Lo\d+)\s+(.*)', line)
        if match:
            interface, description = match.groups()
            desc_entries[interface.strip()] = description.strip()
    return desc_entries

def parse_show_interface_brief(output):
    brief_entries = []
    for line in output.splitlines():
        match = re.match(r'^(mgmt0|Eth[\d/]+|Po\d+|Lo\d+)\s+(\d+|--)\s+(\S*)\s+(\S*)\s+(\S+).*', line)
        if match:
            interface, vlan, _, _, status = match.groups()
            vlan = 'N/A' if vlan == '--' else vlan
            brief_entries.append({
                'Port': interface,
                'VLAN': vlan,
                'Status': status,
            })
    return brief_entries

def parse_show_mac_address_table(output):
    mac_entries = []
    for line in output.splitlines():
        match = re.match(r'\s*\S*\s+(\d+)\s+([0-9a-fA-F.:]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+([\w\-/]+)', line)
        if match:
            vlan, mac_address, port = match.groups()
            mac_entries.append({"vlan": vlan, "mac_address": mac_address.lower(), "port": port})
    return mac_entries

def combine_data(device, brief_data, desc_data, mac_data):
    combined_data = []
    for entry in mac_data:
        port = entry["port"]
        vlan = entry["vlan"]
        mac_address = entry["mac_address"]
        description = desc_data.get(port, "No description")
        status = next((item['Status'] for item in brief_data if item['Port'] == port), 'Unknown')
        
        combined_entry = {
            'Device': device,
            'VLAN': vlan,
            'Port': port,
            'MAC Address': mac_address,
            'Description': description,
            'Status': status
        }
        combined_data.append(combined_entry)
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device_hostname in devices:
        logging.info(f"Processing device: {device_hostname}")
        desc_output = execute_command(device_hostname, username, password, "show interface description")
        brief_output = execute_command(device_hostname, username, password, "show interface brief")
        mac_output = execute_command(device_hostname, username, password, "show mac address-table")

        desc_data = parse_show_interface_description(desc_output or "")
        brief_data = parse_show_interface_brief(brief_output or "")
        mac_data = parse_show_mac_address_table(mac_output or "")

        combined_data = combine_data(device_hostname, brief_data, desc_data, mac_data)
        all_data.extend(combined_data)

    if all_data:
        df = pd.DataFrame.from_records(all_data, columns=['Device', 'VLAN', 'Port', 'MAC Address', 'Description', 'Status'])
        df.to_csv('network_data_combined.csv', index=False)
        logging.info("Data successfully saved to network_data_combined.csv.")
    else:
        logging.warning("No data collected.")

if __name__ == "__main__":
    main()
