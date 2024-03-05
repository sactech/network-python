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
    for line in output.splitlines():
        if line.strip() and not line.startswith('Port') and not line.startswith('-----'):
            parts = line.split()
            if len(parts) > 6:  # Handle lines where 'Name' field might have spaces
                port = parts[0]
                status = parts[-5]
                vlan = parts[-4]
                duplex = parts[-3]
                speed = parts[-2]
                type = parts[-1]
                name = " ".join(parts[1:-5])
                status_entries.append({'Port': port, 'Name': name, 'Status': status, 'Vlan': vlan, 'Duplex': duplex, 'Speed': speed, 'Type': type})
            else:
                logging.warning(f"Skipping unexpected line format: {line}")
    return status_entries

def parse_show_interface_description(output):
    desc_entries = {}
    for line in output.splitlines()[2:]:  # Adjust based on your actual command output header
        if line.strip() and not line.startswith('Interface') and not line.startswith('-----'):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                interface, description = parts[0], parts[1]
                desc_entries[interface] = description
    return desc_entries

def parse_show_ip_interface_brief(output):
    ip_entries = {}
    for line in output.splitlines():
        if line.strip() and not line.startswith('Interface') and not line.startswith('IP Address') and not line.startswith('-----'):
            parts = line.split()
            if len(parts) >= 6:
                interface, ip_address = parts[0], parts[1]
                ip_entries[interface] = ip_address
    return ip_entries

def parse_show_mac_address_table(output):
    mac_entries = []
    for line in output.splitlines():
        if re.match(r'^\*?\s+\d+\s+([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}', line):
            parts = line.split()
            vlan, mac_address, port = parts[0], parts[1], parts[-1]
            mac_entries.append({'Port': port, 'MAC Address': mac_address, 'VLAN': vlan})
    return mac_entries

def combine_data(status_data, desc_data, ip_data, mac_data):
    combined_data = []
    for status in status_data:
        port = status['Port']
        combined = status.copy()
        combined['Description'] = desc_data.get(port, '')
        combined['IP Address'] = ip_data.get(port, 'N/A')
        mac_info = next((item for item in mac_data if item['Port'] == port), None)
        combined['MAC Address'] = mac_info['MAC Address'] if mac_info else 'N/A'
        combined['MAC VLAN'] = mac_info['VLAN'] if mac_info else 'N/A'
        combined_data.append(combined)
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device in devices:
        logging.info(f"Processing device: {device}")

        status_output = execute_command(device, username, password, "show interface status")
        desc_output = execute_command(device, username, password, "show interface description")
        ip_output = execute_command(device, username, password, "show ip interface brief")
        mac_output = execute_command(device, username, password, "show mac address-table")

        status_data = parse_show_interface_status(status_output)
        desc_data = parse_show_interface_description(desc_output)
        ip_data = parse_show_ip_interface_brief(ip_output)
        mac_data = parse_show_mac_address_table(mac_output)

        combined_data = combine_data(status_data, desc_data, ip_data, mac_data)

        for data in combined_data:
            data['Device'] = device

        all_data.extend(combined_data)

    df = pd.DataFrame(all_data)
    if not df.empty:
        df = df[['Device'] + [col for col in df.columns if col != 'Device']]
        df.to_csv('network_data_combined.csv', index=False)
        logging.info("Data successfully saved to network_data_combined.csv.")
    else:
        logging.warning("No data collected.")

if __name__ == "__main__":
    main()
