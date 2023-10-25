import paramiko
import csv
import socket
import ipaddress
import yaml
from getpass import getpass

def is_valid_ipv4(address):
    try:
        ipaddress.ip_address(address)
        return True
    except:
        return False

def dns_resolution(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):  # Handle resolution errors
        return 'Unresolvable'

def fetch_data_from_device(ip, username, password, command):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(ip, username=username, password=password)
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
    except Exception as e:
        print(f"Error connecting to device {ip}: {e}")
        return ''
    finally:
        ssh_client.close()
    return output

def read_yaml_file(filename):
    with open(filename, 'r') as file:
        data = yaml.safe_load(file)
    return data

def main():
    devices = read_yaml_file("devices.yaml")
    username = input("Enter SSH username: ")
    password = getpass("Enter SSH password: ")

    # Fetch ARP data from routers
    print("Fetching ARP data from routers...")
    arp_data = {}
    for ip in devices['routers']:
        try:
            print(f"Connecting to router: {ip}")
            output = fetch_data_from_device(ip, username, password, "show ip arp").strip().split("\n")[1:]
            for line in output:
                parts = line.split()
                if len(parts) >= 4 and is_valid_ipv4(parts[0]):
                    arp_data[parts[2]] = parts[0]
        except Exception as e:
            print(f"Error processing data from router {ip}: {e}")

    results = []

    # Fetch MAC addresses and interface descriptions from switches
    print("\nFetching MAC addresses and interface descriptions from switches...")
    for ip in devices['switches']:
        try:
            print(f"\nConnecting to switch: {ip}")

            # Fetch interface descriptions
            print("Fetching interface descriptions...")
            interface_descs = {}
            output_desc = fetch_data_from_device(ip, username, password, "show interface description").strip().split("\n")[1:]
            for line in output_desc:
                parts = line.split()
                if len(parts) >= 2:
                    interface_name = parts[0]
                    description = ' '.join(parts[1:])
                    interface_descs[interface_name] = description

            # Fetch MAC addresses
            print("Fetching MAC addresses...")
            output_mac = fetch_data_from_device(ip, username, password, "show mac address-table").strip().split("\n")[4:]
            for line in output_mac:
                if line.startswith('*'):
                    parts = line.split()
                    vlan = parts[1]
                    mac_addr = parts[2]
                    port = parts[-1]
                    ip_addr = arp_data.get(mac_addr, "N/A")
                    description = interface_descs.get(port, "N/A")
                    dns_name = dns_resolution(ip_addr)  # Fetch DNS name for IP
                    results.append([ip, port, description, mac_addr, ip_addr, dns_name])
        except Exception as e:
            print(f"Error processing data from switch {ip}: {e}")

    # Write to CSV
    print("\nWriting data to output.csv...")
    with open('output.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Switch', 'Port', 'Description', 'MAC', 'IP', 'DNS Name'])
        for entry in results:
            switch, port, description, mac_addr, ip_addr, dns_name = entry
            writer.writerow([switch, port, description, mac_addr, ip_addr, dns_name])

    print("\nOutput written to output.csv.")

if __name__ == "__main__":
    main()