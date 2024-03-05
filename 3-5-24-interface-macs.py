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
        if re.match(r'^Eth', line) and not re.match(r'^---', line):
            parts = re.split(r'\s{2,}', line)
            if len(parts) >= 6:
                status_entries.append({
                    'Port': parts[0], 'Name': parts[1], 'Status': parts[2],
                    'Vlan': parts[3], 'Duplex': parts[4], 'Speed': parts[5], 'Type': parts[6] if len(parts) > 6 else ''
                })
    return status_entries

def parse_show_interface_description(output):
    desc_entries = {}
    for line in output.splitlines():
        match = re.match(r'^(Eth[0-9/]+)\s+(.*)', line)
        if match:
            interface, description = match.groups()
            desc_entries[interface] = {'Description': description}
    return desc_entries

def parse_show_ip_interface_brief(output):
    ip_entries = {}
    for line in output.splitlines():
        if re.match(r'^(Vlan|Eth|Lo|mgmt0)', line):
            parts = line.split()
            if len(parts) >= 3:
                ip_entries[parts[0]] = {'IP Address': parts[1], 'Interface Status': parts[2]}
    return ip_entries

def parse_show_mac_address_table(output):
    mac_entries = {}
    for line in output.splitlines():
        if re.match(r'^\*?\s+\d+\s+([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}', line):
            parts = line.split()
            if len(parts) >= 4:
                port = parts[-1]
                mac_entries.setdefault(port, []).append({'MAC Address': parts[1], 'VLAN': parts[0]})
    return mac_entries

def combine_data(status_data, desc_data, ip_data, mac_data):
    combined_data = []
    for entry in status_data:
        port = entry['Port']
        combined_entry = entry.copy()
        combined_entry.update(desc_data.get(port, {}))
        combined_entry.update(ip_data.get(port, {'IP Address': 'N/A', 'Interface Status': 'N/A'}))
        mac_entries = mac_data.get(port, [{'MAC Address': 'N/A', 'VLAN': 'N/A'}])
        for mac_entry in mac_entries:
            combined_data.append({**combined_entry, **mac_entry})
    return combined_data

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device in devices:
        logging.info(f"Processing device: {device}")
        commands = {
            "show interface status": parse_show_interface_status,
            "show interface description": parse_show_interface_description,
            "show ip interface brief": parse_show_ip_interface_brief,
            "show mac address-table": parse_show_mac_address_table,
        }

        data_collect = {cmd: func(execute_command(device, username, password, cmd)) for cmd, func in commands.items()}

        combined_data = combine_data(data_collect["show interface status"], data_collect["show interface description"], 
                                     data_collect["show ip interface brief"], data_collect["show mac address-table"])

        for data in combined_data:
            data['Device'] = device  # Adding device name to each row

        all_data.extend(combined_data)

    df = pd.DataFrame(all_data)
    if not df.empty:
        df = df[['Device'] + [col for col in df.columns if col != 'Device']]  # Ensure 'Device' column is at the front
        df.to_csv('network_data_combined.csv', index=False)
        logging.info("Data successfully saved to network_data_combined.csv.")
    else:
        logging.warning("No data collected.")

if __name__ == "__main__":
    main()
