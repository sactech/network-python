#!/usr/bin/env python

import csv
import getpass
import ipaddress
import re
from netmiko import ConnectHandler
from socket import gethostbyaddr
import yaml

# CSV header
csv_header = ["Device", "Port", "Interface Description", "Status", "VLAN", "MAC Address"]

# Global regex patterns
description_regex = re.compile(r'Description: (.*)', re.MULTILINE)
status_regex = re.compile(r'line protocol is (\S+)')

def parse_interface_data(interface_output):
    """Parse interface data from show interface command."""
    interface_data = {}
    # Parse interface description
    description_match = re.search(description_regex, interface_output)
    if description_match:
        interface_data['description'] = description_match.group(1)
    else:
        interface_data['description'] = 'N/A'
    # Parse interface status
    status_match = re.search(status_regex, interface_output)
    if status_match:
        interface_data['status'] = status_match.group(1)
    else:
        interface_data['status'] = 'N/A'
    return interface_data

def trace_mac(mac, switch_ip, username, password, secret):
    """Trace MAC address through switches."""
    results = []
    device = {
        'device_type': 'cisco_ios',
        'host': switch_ip,
        'username': username,
        'password': password,
        'secret': secret
    }
    try:
        with ConnectHandler(**device) as net_connect:
            # Execute commands to gather interface information
            command = f"show mac address-table address {mac}"
            output = net_connect.send_command(command)
            # Parse interface data from output
            interface_data = parse_interface_data(output)
            # Append device name, MAC address, and parsed interface data to results
            results.append([net_connect.find_prompt().strip('#'), 'N/A', interface_data['description'], 
                            interface_data['status'], 'N/A', mac])
    except Exception as e:
        print(f"Error connecting to switch {switch_ip}: {str(e)}")
    return results

def main():
    # Load switch IPs from YAML config file
    with open('devices.yaml', 'r') as file:
        switch_ips = yaml.safe_load(file)
    
    # Prompt for username, password, and secret
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    secret = getpass.getpass("Enter enable secret (if any): ")

    # Open CSV file for writing
    with open('mac_addresses.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(csv_header)

        # Iterate over each switch IP
        for switch_ip in switch_ips['switches']:
            print(f"Scanning switch {switch_ip}...")
            # Iterate over each IP in the network and trace MAC address
            for ip in ipaddress.IPv4Network(switch_ips['network']):
                print(f"Tracing MAC for IP {ip}...")
                # Trace MAC address through switches
                results = trace_mac(str(ip), switch_ip, username, password, secret)
                # Write results to CSV
                for result in results:
                    csv_writer.writerow(result)

    print("Scan complete.")

if __name__ == "__main__":
    main()
