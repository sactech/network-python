import yaml
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
import getpass

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
        return output
    except NetMikoTimeoutException:
        return f"Error: Connection to {host} timed out."
    except NetMikoAuthenticationException:
        return f"Error: Authentication to {host} failed."
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    devices = read_devices('devices.yaml')
    username = input("Enter your SSH username: ")
    password = getpass.getpass("Enter your SSH password: ")

    for switch in devices.get('switches', []):
        print(f"Connecting to {switch}...")
        version_info = get_nxos_version(switch, username, password)
        print(f"Software version for {switch}:\n{version_info}")

if __name__ == "__main__":
    main()
