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
        return devices.get('switches', [])  # Return only the switches list

def execute_commands(device_info):
    commands = {
        'desc': "show interface description",
        'mac': "show mac address-table",
        'status': "show interface brief"
    }
    results = {}
    try:
        logging.info(f"Connecting to device: {device_info['host']}")
        with ConnectHandler(**device_info) as ssh:
            for key, command in commands.items():
                output = ssh.send_command(command)
                results[key] = output
                logging.debug(f"Command: {command}\nOutput:\n{output}")
    except Exception as e:
        logging.error(f"Failed to execute commands on {device_info['host']}: {e}")
    return results

def parse_data(device_name, results):
    parsed_data = []
    if results:
        # Parse interface status
        status_data = {}
        lines = results['status'].splitlines()
        for line in lines:
            match = re.match(r'^(mgmt0|Eth\d+/\d+(/\d+)?|Po\d+)\s+\S+\s+\S+\s+\S+\s+(\w+)\s+', line, re.IGNORECASE)
            if match:
                interface, _, status = match.groups()
                status_data[interface.lower()] = status

        # Combine all data
        lines = results['desc'].splitlines()
        for line in lines:
            match = re.match(r'^(mgmt0|Eth\d+/\d+(/\d+)?|Po\d+)\s+(.*)', line, re.IGNORECASE)
            if match:
                interface, _, description = match.groups()
                interface = interface.lower()
                if interface in status_data:  # Ensure only interfaces with status are included
                    mac_addresses = []
                    mac_lines = results['mac'].splitlines()
                    for mac_line in mac_lines:
                        mac_match = re.match(r'^\*\s+\d+\s+([0-9a-f:.]+)\s+dynamic\s+.*\s+' + re.escape(interface) + r'$', mac_line, re.IGNORECASE)
                        if mac_match:
                            mac_addresses.append(mac_match.group(1))
                    for mac_address in mac_addresses:
                        parsed_data.append({
                            'Device': device_name,
                            'Interface': interface,
                            'Status': status_data[interface],
                            'Description': description.strip(),
                            'MAC Address': mac_address
                        })
                    if not mac_addresses:
                        parsed_data.append({
                            'Device': device_name,
                            'Interface': interface,
                            'Status': status_data[interface],
                            'Description': description.strip(),
                            'MAC Address': 'No MAC Address Found'
                        })

    return parsed_data

def main():
    switches = read_device_info()
    if not switches:
        logging.error("No switch data found. Check your YAML file.")
        return

    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    all_data = []
    for switch in switches:
        device_info = {
            'device_type': 'cisco_nxos',
            'host': switch,
            'username': username,
            'password': password,
        }
        results = execute_commands(device_info)
        switch_data = parse_data(switch, results)
        all_data.extend(switch_data)

    if all_data:
        df = pd.DataFrame(all_data)
        df.to_excel('network_data.xlsx', index=False)
        logging.info("Data successfully saved to network_data.xlsx.")
    else:
        logging.warning("No data collected.")

if __name__ == "__main__":
    main()
