#!/usr/bin/env python

import argparse
import glob
import os
from datetime import datetime
from getpass import getpass
import netauto

# Optional device name to back up just one device; omit to back up all of them
parser = argparse.ArgumentParser(description='Back up running-config from devices in inventory.yaml')
parser.add_argument('device', nargs='?', default=None, help='Device name as it appears in inventory.yaml (e.g. R1). Omit to back up all devices.')
args = parser.parse_args()

# Prompt for credentials used against every device being backed up
username = input('Enter your SSH username: ')
password = getpass()

# Load target devices from the YAML inventory (name -> {host, device_type})
all_devices = netauto.load_inventory()
if args.device:
    if args.device not in all_devices:
        print(f'Device "{args.device}" not found in inventory.yaml')
        raise SystemExit(1)
    devices_list = {args.device: all_devices[args.device]}
else:
    devices_list = all_devices

# Prep the output folders and a shared run time for this run's backups
backup_dir = 'backups'
archive_dir = os.path.join(backup_dir, 'archive')
os.makedirs(archive_dir, exist_ok=True)
run_time = datetime.now()
timestamp = run_time.strftime('%Y%m%d_%H%M%S')
max_archives_per_device = 5

for device_name, device_info in devices_list.items():
    ip_address_of_device = device_info['host']

    # Connect, skipping to the next device if it fails
    net_connect = netauto.connect(device_name, device_info, username, password)
    if net_connect is None:
        continue

    # Pull the running config and close the session
    hostname = net_connect.base_prompt
    output = str(net_connect.send_command('show running-config'))
    net_connect.disconnect()

    # Header noting hostname, IP, and when the backup was taken
    header = (
        f'! Hostname: {hostname}\n'
        f'! IP Address: {ip_address_of_device}\n'
        f'! Backup Date/Time: {run_time.strftime("%Y-%m-%d %H:%M:%S")}\n'
    )

    # Write the "latest" backup to disk, named by inventory name/IP so reruns overwrite in place
    filename = os.path.join(backup_dir, f'{device_name}_{ip_address_of_device}.cfg')
    with open(filename, 'w') as backup_file:
        backup_file.write(header + output)
    print('Saved backup to ' + filename)

    # Also keep a dated archive copy, pruned to the N most recent per device
    archive_glob = os.path.join(archive_dir, f'{device_name}_{ip_address_of_device}_*.cfg')
    archive_filename = os.path.join(archive_dir, f'{device_name}_{ip_address_of_device}_{timestamp}.cfg')
    with open(archive_filename, 'w') as archive_file:
        archive_file.write(header + output)

    device_archives = sorted(glob.glob(archive_glob))
    for old_archive in device_archives[:-max_archives_per_device]:
        os.remove(old_archive)