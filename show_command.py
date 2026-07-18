#!/usr/bin/env python

import argparse
from getpass import getpass
import netauto

# Parse the target device and show command from the command line
parser = argparse.ArgumentParser(description='Run a single show command against a device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1)')
parser.add_argument('command', help='Show command to run (e.g. "show ip interface brief")')
args = parser.parse_args()

device_name = args.device

# Prompt for credentials
username = input('Enter your SSH username: ')
password = getpass()

# Load the target device from the YAML inventory
devices = netauto.load_inventory()
device_info = devices[device_name]

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Run the show command and close the session
output = net_connect.send_command(args.command)
net_connect.disconnect()

print(output)
