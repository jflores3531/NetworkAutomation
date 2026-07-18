#!/usr/bin/env python
"""Compare a device's current running-config and VLANs against its last backup_config.py backup."""

import argparse
import difflib
import os
import netauto

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Diff a device\'s current running-config and VLANs against its last backup_config.py backup')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]
ip_address_of_device = device_info['host']


def load_backup(label):
    """Read a backup file written by backup_config.py, stripping its 3-line header
    (hostname/IP/timestamp) so it doesn't show up as noise in every diff."""
    backup_path = os.path.join('backups', f'{device_name}_{ip_address_of_device}{label}.cfg')
    if not os.path.exists(backup_path):
        print(f'No existing backup found at {backup_path} - run backup_config.py first.')
        raise SystemExit(1)
    with open(backup_path) as f:
        return backup_path, f.readlines()[3:]


running_backup_path, running_backup_lines = load_backup('')
vlan_backup_path, vlan_backup_lines = load_backup('_vlans')

# Prompt for credentials
username, password = netauto.get_credentials()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Pull the current running config and VLANs, then close the session
current_running = str(net_connect.send_command('show running-config'))
current_vlans = str(net_connect.send_command('show vlan brief'))
net_connect.disconnect()


def print_diff(label, backup_path, backup_lines, current_output):
    current_lines = [line + '\n' for line in current_output.splitlines()]
    diff = list(difflib.unified_diff(
        backup_lines,
        current_lines,
        fromfile=backup_path,
        tofile=f'{device_name} current {label}',
        lineterm=''
    ))

    print(f'=== {label} ===')
    if diff:
        print('\n'.join(diff))
    else:
        print(f'No differences - {device_name} matches its last backup ({backup_path}).')
    print()


print_diff('running-config', running_backup_path, running_backup_lines, current_running)
print_diff('vlan brief', vlan_backup_path, vlan_backup_lines, current_vlans)
