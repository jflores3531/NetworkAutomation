#!/usr/bin/env python
"""Create or update a loopback interface on a device from inventory.yaml."""

import argparse
import netauto

# Parse the target device and loopback config from the command line
parser = argparse.ArgumentParser(description='Create/update a loopback interface on a device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1)')
parser.add_argument('ip_address', help='Loopback IP address (e.g. 1.1.1.1)')
parser.add_argument('subnet_mask', help='Subnet mask (e.g. 255.255.255.255)')
parser.add_argument('--interface', default='0', help='Loopback interface number (default: 0)')
args = parser.parse_args()

device_name = args.device
commands = [
    f'interface Loopback{args.interface}',
    f'ip address {args.ip_address} {args.subnet_mask}'
]

# Prompt for credentials
username, password = netauto.get_credentials()

# Load the target device from the YAML inventory
devices = netauto.load_inventory()
device_info = netauto.require_devices(devices, [device_name])[device_name]

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Push the loopback config and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('config_loopback.py', device_name, username, commands)

print(output)