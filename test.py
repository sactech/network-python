from netmiko import ConnectHandler
import pandas as pd
import getpass
import yaml
import logging
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

def execute_command(device_details, command):
  try:
    with ConnectHandler(**device_details) as conn:  # Close connection automatically
      output = conn.send_command(command)
    return output
  except Exception as e:
    logging.error(f"Failed to execute command: {e}")
    return ""

def parse_show_interface_brief(output):
  # Improved parsing for 'show interface brief'
  interface_data = []
  lines = output.splitlines()
  headers = lines[0].split()  # Assuming headers on the first line
  for line in lines[1:]:  # Skip headers
    fields = line.split()
    if len(fields) == len(headers):  # Ensure matching number of fields
      interface_data.append(dict(zip(headers, fields)))
  return interface_data

def parse_show_interface_descriptions(output):
  # Simplified parsing assuming consistent format
  desc_data = {}
  lines = output.splitlines()[2:]  # Assuming headers in the first two lines
  for line in lines:
    port, description = line.split(':', 1)  # Split by ':' assuming consistent format
    desc_data[port.strip()] = description.strip()
  return desc_data

def parse_show_mac_address_table(output):
  # Existing parsing logic seems appropriate for 'show mac address-table'
  mac_entries = {}
  lines = output.splitlines()
  for line in lines:
    if re.match(r'^\*', line):  # Assuming entries start with '*'
      fields = line.split()
      mac_entries.setdefault(fields[-1], []).append(fields[1])  # Assuming MAC address is the second field
  return mac_entries

def combine_data(device, interface_data, desc_data, mac_data):
  combined_data = []
  for entry in interface_data:
    port = entry['intf']  # Assuming interface name is in 'intf' key
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
      'device_type': 'cisco_nxos',
      'host': device,
      'username': username,
      'password': password,
      'secret': password,  # assuming enable password is the same
    }

    logging.info(f"Processing device: {device}")

    brief_output = execute_command(device_details, "show interface brief")
    desc_output = execute_command(device_details, "show interface descriptions")
    mac_output = execute_command(device_details, "show mac address-table")

    interface_data = parse_show_interface_brief(brief_output)
    desc_data = parse_show_interface_descriptions(desc_output)
    mac_data = parse_show_mac_address_table(mac_output)

    device_data = combine_data(device, interface_data, desc_data, mac_data)
    all_data.extend(device_data)

  df = pd.DataFrame(all_data)
  df.to_csv('network_data_combined.csv', index=False)
  logging.info("Data successfully saved to network_data_combined.csv.")

if __name__ == "__main__":
  main()
