import yaml
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# Function to update SNMP location on a device
def update_snmp_location(device_info):
    try:
        # Establishing a connection to the device
        with ConnectHandler(**device_info) as conn:
            command = f"snmp-server location {device_info['new_snmp_location']}"
            output = conn.send_config_set(command)
            print(f"Successfully updated {device_info['host']}:\n{output}")
    except NetmikoTimeoutException:
        print(f"Connection timed out for {device_info['host']}")
    except NetmikoAuthenticationException:
        print(f"Authentication failed for {device_info['host']}")
    except Exception as e:
        print(f"Failed to update {device_info['host']}: {e}")

# Load device info from YAML file
try:
    with open('devices.yaml', 'r') as file:
        devices_list = yaml.safe_load(file)['devices']
except FileNotFoundError:
    print("The YAML file was not found.")
    exit()
except yaml.YAMLError as exc:
    print(f"Error in YAML file formatting: {exc}")
    exit()

# Iterate over each device and change SNMP location
for device in devices_list:
    device_params = {
        'device_type': 'cisco_ios',  # or appropriate type for your devices
        'host': device['ip'],
        'username': 'testuser',  # Test username
        'password': 'testpass',  # Test password
        'new_snmp_location': device['new_snmp_location']
    }

    update_snmp_location(device_params)
