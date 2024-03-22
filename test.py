from netmiko import ConnectHandler
import pandas as pd
import getpass
import yaml
import logging
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_device_info(file_path='devices.yaml'):
    with open(file_path) as file:
        devices = yaml.safe_load(file)
    return devices.get('switches', [])

def execute_command(device_details, command):
    try:
        with ConnectHandler(**device_details) as conn:
            output = conn.send_command(command)
        return output
    except Exception as e:
        logging.error(f"Failed to execute command: {e}")
        return ""

def parse_show_interface_status(output):
    status_entries = []
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^Eth', line):
            fields = line.split()
            status_entries.append({
                'Port': fields[0],
                'Name': fields[1],
                'Status': fields[2],
                'Vlan': fields[3],
                'Duplex': fields[4],
                'Speed': fields[5],
                'Type': ' '.join(fields[6:])  # Handle Type field possibly containing spaces
            })
    return status_entries

def parse_show_interface_description(output):
    desc_entries = {}
    lines = output.splitlines()
    for line in lines[2:]:  # Assuming the first two lines are headers
        fields = line.split()
        desc_entries[fields[0]] = ' '.join(fields[1:])
    return desc_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^\*', line):  # Assuming entries start with '*'
            fields = line.split()
            mac_entries.setdefault(fields[-1], []).append(fields[1])  # Assuming MAC address is the second field
    return mac_entries

def combine_data(device, status_data, desc_data, mac_data):
    combined_data = []
    for entry in status_data:
        port = entry['Port']
        combined_entry = entry.copy()
        combined_entry['Description'] = desc_data.get(port, 'N/A')
        combined_entry['MAC Addresses'] = ', '.join(mac_data.get(port, ['N/A']))
        combined_data.append(combined_entry)
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device in devices:
        device_details = {
            'device_type': 'cisco_nxos',  # or 'cisco_nxos' for Nexus devices
            'host': device,
            'username': username,
            'password': password,
            'secret': password,  # assuming enable password is the same
        }

        logging.info(f"Processing device: {device}")

        status_output = execute_command(device_details, "show interface status")
        desc_output = execute_command(device_details, "show interface description")
        mac_output = execute_command(device_details, "show mac address-table")

        status_data = parse_show_interface_status(status_output)
        desc_data = parse_show_interface_description(desc_output)
        mac_data = parse_show_mac_address_table(mac_output)

        device_data = combine_data(device, status_data, desc_data, mac_data)
        all_data.extend(device_data)

    df = pd.DataFrame(all_data)
    df.to_csv('network_data_combined.csv', index=False)
    logging.info("Data successfully saved to 'network_data_combined.csv'.")

if __name__ == "__main__":
    main()
