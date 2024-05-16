import yaml
import csv
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
import getpass
import re

def read_devices(file_path):
    with open(file_path, 'r') as file:
        devices = yaml.safe_load(file)
    return devices

def get_nxos_version(host, username, password):
    device = {
        'device_type': 'cisco_nxos',
        'host': host,
        'username': username,
        'password': password,
    }
    try:
        connection = ConnectHandler(**device)
        output = connection.send_command("show version")
        connection.disconnect()
        return parse_version_info(output)
    except NetMikoTimeoutException:
        return {'host': host, 'error': 'Connection timed out'}
    except NetMikoAuthenticationException:
        return {'host': host, 'error': 'Authentication failed'}
    except Exception as e:
        return {'host': host, 'error': str(e)}

def parse_version_info(output):
    # Define regex patterns to extract the required information
    kickstart_pattern = re.compile(r'kickstart: version (\S+)')
    system_pattern = re.compile(r'system: version (\S+)')
    os_pattern = re.compile(r'Nexus Operating System \(NX-OS\) Software\s*Version\s*(\S+)')

    kickstart_version = kickstart_pattern.search(output)
    system_version = system_pattern.search(output)
    os_version = os_pattern.search(output)

    return {
        'kickstart': kickstart_version.group(1) if kickstart_version else 'N/A',
        'system': system_version.group(1) if system_version else 'N/A',
        'os': os_version.group(1) if os_version else 'N/A',
    }

def main():
    devices = read_devices('devices.yaml')
    username = input("Enter your SSH username: ")
    password = getpass.getpass("Enter your SSH password: ")

    results = []
    for switch in devices.get('switches', []):
        print(f"Connecting to {switch}...")
        version_info = get_nxos_version(switch, username, password)
        if 'error' in version_info:
            results.append({'host': switch, 'error': version_info['error']})
        else:
            version_info['host'] = switch
            results.append(version_info)

    # Write results to a CSV file
    with open('switch_versions.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['host', 'os', 'kickstart', 'system', 'error'])
        writer.writeheader()
        for result in results:
            writer.writerow(result)

if __name__ == "__main__":
    main()
