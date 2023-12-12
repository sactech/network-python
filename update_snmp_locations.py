import yaml
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# Function to update SNMP location on a device
def update_snmp_location(device_info):
    try:
        # Establishing a connection to the device
        with ConnectHandler(**device_info) as conn:
            print(f"Connecting to {device_info['host']}...")

            # Update SNMP location
            snmp_command = f"snmp-server location {device_info['new_snmp_location']}"
            conn.send_config_set(snmp_command)
            print(f"SNMP location updated for {device_info['host']}.")

            # Save the configuration
            save_command = 'copy running-config startup-config'
            output = conn.send_command_timing(save_command)
            if 'Destination filename [startup-config]?' in output:
                output += conn.send_command_timing('\n')  # Confirm the save if prompted
            if 'Copy in progress' in output:
                print(f"Configuration save initiated for {device_info['host']}. Waiting for completion...")
            else:
                print(f"Unexpected response during save: {output}")

            # Check for completion (optional, based on your device's response)
            # You may need to adjust this part according to the specific response of your devices
            if 'bytes copied in' in output:
                print(f"Configuration successfully saved for {device_info['host']}.")
            else:
                print(f"Could not confirm if configuration was saved for {device_info['host']}. Please verify manually.")
            
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
        'username': 'your_username',  # replace with your username
        'password': 'your_password',  # replace with your password
        'new_snmp_location': device['new_snmp_location']
    }

    update_snmp_location(device_params)
