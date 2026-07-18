#!/usr/bin/env python

import argparse
import netauto

# Parse the commands file and target device(s) from the command line
parser = argparse.ArgumentParser(description='Push a set of config commands to one or more devices from inventory.yaml')
parser.add_argument('commands_file', help='Path to a file with one config command per line')
parser.add_argument('devices', nargs='+', help='Device name(s) as they appear in inventory.yaml (e.g. R1 R2)')
args = parser.parse_args()

with open(args.commands_file) as f:
    commands = [line.strip() for line in f if line.strip()]

if not commands:
    print(f'No commands found in {args.commands_file}')
    raise SystemExit(1)

# Prompt for credentials used against every device
username, password = netauto.get_credentials()

# Load target devices from the YAML inventory (name -> {host, device_type})
all_devices = netauto.load_inventory()
devices_list = netauto.require_devices(all_devices, args.devices)

for device_name, device_info in devices_list.items():
    # Connect, skipping to the next device if it fails
    net_connect = netauto.connect(device_name, device_info, username, password)
    if net_connect is None:
        continue

    # Push the config commands and close the session
    output = net_connect.send_config_set(commands)
    net_connect.disconnect()

    print(f'--- {device_name} ---')
    print(output)
    print()
