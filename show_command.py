#!/usr/bin/env python

import argparse
from getpass import getpass
import netauto

# Parse the show command and target device(s) from the command line
parser = argparse.ArgumentParser(description='Run a show command against one or more devices from inventory.yaml')
parser.add_argument('command', help='Show command to run (e.g. "show ip interface brief")')
parser.add_argument('devices', nargs='+', help='Device name(s) as they appear in inventory.yaml (e.g. R1 R2)')
args = parser.parse_args()

# Prompt for credentials used against every device
username = input('Enter your SSH username: ')
password = getpass()

# Load target devices from the YAML inventory (name -> {host, device_type})
all_devices = netauto.load_inventory()
unknown = [name for name in args.devices if name not in all_devices]
if unknown:
    print(f'Device(s) not found in inventory.yaml: {", ".join(unknown)}')
    raise SystemExit(1)
devices_list = {name: all_devices[name] for name in args.devices}

for device_name, device_info in devices_list.items():
    # Connect, skipping to the next device if it fails
    net_connect = netauto.connect(device_name, device_info, username, password)
    if net_connect is None:
        continue

    # Run the show command and close the session
    output = net_connect.send_command(args.command)
    net_connect.disconnect()

    print(f'--- {device_name} ---')
    print(output)
    print()
