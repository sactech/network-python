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
        devices = yaml.load(file, Loader=yaml.FullLoader)
    return devices['devices']

def execute_command(host, username, password, command):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(hostname=host, username=username, password=password)
    logging.info(f"Executing command: {command} on {host}")
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode('utf-8')
    client.close()
    if not output.strip():
        logging.warning(f"Command '{command}' on {host} returned empty output.")
        return None
    logging.info(f"Command executed successfully: {command} on {host}")
    return output

def standardize_interface_name(interface):
    mapping = {
        'Gi': 'GigabitEthernet',
        'Fa': 'FastEthernet',
        'Te': 'TenGigabitEthernet',
        'Vl': 'Vlan',
        'Lo': 'Loopback',
    }
    for short, full in mapping.items():
        if interface.startswith(short):
            return interface.replace(short, full, 1)
    return interface

def parse_show_ip_int_brief(output, host):
    data = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        data.append({
            'Host': host,
            'Interface': parts[0],
            'IP-Address': parts[1],
            'OK?': parts[2],
            'Method': parts[3],
            'Status': parts[4],
            'Protocol': parts[5],
        })
    return data

def parse_show_int_desc(output):
    data = []
    for line in output.splitlines()[1:]:
        parts = re.split(r'\s{2,}', line.strip())  # Split by two or more spaces
        if len(parts) >= 4:  # Check to ensure there are enough parts
            data.append({
                'Interface': standardize_interface_name(parts[0]),
                'Description': parts[3],
            })
    return data

def parse_show_int_status(output):
    data = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6:  # Ensure there are enough parts for the expected columns
            data.append({
                'Port': standardize_interface_name(parts[0]),
                'Vlan': parts[3],
                'Duplex': parts[4],
                'Speed': parts[5],
                'Type': parts[6] if len(parts) > 6 else '',
            })
    return data

def main():
    devices = read_device_info('devices.yaml')
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []

    for device in devices:
        host = device['host']

        ip_int_brief_output = execute_command(host, username, password, "show ip interface brief")
        int_desc_output = execute_command(host, username, password, "show interfaces description")
        int_status_output = execute_command(host, username, password, "show interfaces status")

        ip_int_brief_data = parse_show_ip_int_brief(ip_int_brief_output, host)
        int_desc_data = parse_show_int_desc(int_desc_output)
        int_status_data = parse_show_int_status(int_status_output)

        # Convert to DataFrames
        df_ip_int_brief = pd.DataFrame(ip_int_brief_data)
        df_int_desc = pd.DataFrame(int_desc_data)
        df_int_status = pd.DataFrame(int_status_data).rename(columns={'Port': 'Interface'})

        # Merge DataFrames
        df_merged = pd.merge(df_ip_int_brief, df_int_desc, on='Interface', how='left')
        df_merged = pd.merge(df_merged, df_int_status, on='Interface', how='left')
        df_merged.drop(columns=['Host_x', 'Host_y'], errors='ignore', inplace=True)

        all_data.append(df_merged)

    if all_data:
        final_df = pd.concat(all_data, ignore_index=True)
        final_df.to_csv('network_data.csv', index=False)
        logging.info("Data successfully saved to network_data.csv.")

if __name__ == "__main__":
    main()
