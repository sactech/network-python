from netmiko import ConnectHandler
import pandas as pd
import getpass
import yaml
import logging
from concurrent.futures import ThreadPoolExecutor
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_device_info(file_path='devices.yaml'):
    try:
        with open(file_path) as file:
            devices = yaml.safe_load(file)
        return devices.get('switches', [])
    except (FileNotFoundError, yaml.YAMLError) as e:
        logging.error(f"Failed to read device info: {e}")
        return []

def execute_commands(device_details, commands):
    try:
        with ConnectHandler(**device_details) as conn:
            outputs = [conn.send_command(command) for command in commands]
        return outputs
    except Exception as e:
        logging.error(f"Failed to execute commands: {e}")
        return [""] * len(commands)

def parse_show_interface_brief(output):
    interface_data = []
    lines = output.splitlines()
    headers = lines[1].split()  # Assuming headers are in the second line
    for line in lines[2:]:  # Skip headers and separator lines
        fields = line.split()
        if len(fields) == len(headers):  # Ensure matching number of fields
            interface_data.append(dict(zip(headers, fields)))
    return interface_data

def parse_show_interface_descriptions(output):
    desc_data = {}
    lines = output.splitlines()[3:]  # Skip headers and separators
    for line in lines:
        if len(line.strip()) == 0:
            continue
        port, description = line.split(maxsplit=1)  # Split by first space
        desc_data[port.strip()] = description.strip()
    return desc_data

def parse_show_mac_address_table(output):
    mac_entries = {}
    lines = output.splitlines()
    for line in lines:
        match = re.match(r'^\*?(\d+)\s+([0-9a-fA-F\.]+)\s+\w+\s+\d+\s+\w+\s+(\S+)', line)
        if match:
            vlan, mac_address, port = match.groups()
            mac_entries.setdefault(port, []).append(mac_address)
    return mac_entries

def combine_data(device, interface_data, desc_data, mac_data):
    combined_data = []
    for entry in interface_data:
        port = entry['Port']
        combined_entry = {
            'Device': device,
            'Port': port,
            'Status': entry.get('Status', 'N/A'),
            'Description': desc_data.get(port, 'N/A'),
            'MAC Addresses': ', '.join(mac_data.get(port, ['N/A']))
        }
        combined_data.append(combined_entry)
    return combined_data

def process_device(device):
    try:
        device_details = {
            'device_type': 'cisco_nxos',
            'host': device,
            'username': username,
            'password': password,
            'secret': password,  # Assuming enable password is the same
        }
        commands = ["show interface brief", "show interface description", "show mac address-table"]
        outputs = execute_commands(device_details, commands)
        interface_data = parse_show_interface_brief(outputs[0])
        desc_data = parse_show_interface_descriptions(outputs[1])
        mac_data = parse_show_mac_address_table(outputs[2])
        return combine_data(device, interface_data, desc_data, mac_data)
    except Exception as e:
        logging.error(f"Error processing device {device}: {e}")
        return []

def main():
    devices = read_device_info()
    if len(devices) == 0:
        logging.error("No devices found in the configuration file.")
        return

    global username
    username = input("Enter SSH username: ")
    global password
    password = getpass.getpass("Enter SSH password: ")

    all_data = []
    concurrency_limit = 2

    with ThreadPoolExecutor(max_workers=concurrency_limit) as executor:
        futures = [executor.submit(process_device, device) for device in devices]
        for future in futures:
            all_data.extend(future.result())

    df = pd.DataFrame(all_data)
    df.to_csv('network_data_combined.csv', index=False)
    logging.info("Data successfully saved to network_data_combined.csv.")

if __name__ == "__main__":
    main()
