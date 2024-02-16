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
    return devices['devices']

def execute_command(host, username, password, command):
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode('utf-8').strip()

def parse_show_interface_status(output):
    data = []
    lines = output.splitlines()[2:]  # Adjust based on your actual command output
    for line in lines:
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 6:
            data.append({
                'Port': parts[0],
                'Name': parts[1],
                'Status': parts[2],
                'Vlan': parts[3],
                'Duplex': parts[4],
                'Speed': parts[5],
                'Type': ' '.join(parts[6:])  # Combine remaining parts for Type
            })
    return data

def parse_show_interface_description(output):
    descriptions = {}
    lines = output.splitlines()[2:]  # Adjust based on actual command output header
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            descriptions[parts[0]] = parts[1]
    return descriptions

def parse_show_ip_interface_brief(output):
    ip_details = {}
    lines = output.splitlines()[1:]  # Skip header line
    for line in lines:
        parts = line.split()
        if len(parts) >= 5:
            ip_details[parts[0]] = {'IP Address': parts[1], 'Interface Status': ' '.join(parts[2:])}
    return ip_details

def combine_data(status_data, desc_data, ip_data):
    combined = []
    for entry in status_data:
        port = entry['Port']
        combined_entry = entry.copy()
        combined_entry.update({'Description': desc_data.get(port, 'N/A')})
        combined_entry.update(ip_data.get(port, {'IP Address': 'N/A', 'Interface Status': 'N/A'}))
        combined.append(combined_entry)
    return combined

def main():
    devices = read_device_info()
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    final_data = []

    for device in devices:
        logging.info(f"Processing device: {device['host']}")
        status_output = execute_command(device['host'], username, password, "show interface status")
        desc_output = execute_command(device['host'], username, password, "show interface description")
        ip_output = execute_command(device['host'], username, password, "show ip interface brief")

        status_data = parse_show_interface_status(status_output)
        desc_data = parse_show_interface_description(desc_output)
        ip_data = parse_show_ip_interface_brief(ip_output)

        device_data = combine_data(status_data, desc_data, ip_data)
        for entry in device_data:
            entry['Device'] = device['host']
        final_data.extend(device_data)

    df = pd.DataFrame(final_data)

    # Ensure 'Device' column is at the front
    cols = ['Device'] + [col for col in df.columns if col != 'Device']
    df = df[cols]

    df.to_csv('nexus_interface_data.csv', index=False)
    logging.info("Data saved to nexus_interface_data.csv.")

if __name__ == "__main__":
    main()
