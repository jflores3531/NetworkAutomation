#!/usr/bin/env python
"""Run a show command against one or more devices from inventory.yaml.

Output is passed through netauto.redact_output() before printing, the same way
the *_stig_harden*.py scripts treat their push transcripts. This script reads
config as readily as they write it - `show running-config` returns the RADIUS
key, the SNMPv3 passwords and the NTP authentication key just as surely as
pushing them does - so printing raw output discloses exactly what those scripts
take care not to.

That was not theoretical: an unredacted run of this script through
`show running-config | include radius` put the real RADIUS shared secret into a
session transcript on 2026-08-12. Redacting here was only half the fix - the
pattern list in netauto.py did not recognise NX-OS's single-line
`radius-server host <ip> key <n> <secret>` form at all, because it only looked
for the key at the start or end of a line. See _SECRET_PATTERNS."""

import argparse
import netauto

# Parse the show command and target device(s) from the command line
parser = argparse.ArgumentParser(description='Run a show command against one or more devices from inventory.yaml')
parser.add_argument('command', help='Show command to run (e.g. "show ip interface brief")')
parser.add_argument('devices', nargs='+', help='Device name(s) as they appear in inventory.yaml (e.g. R1 R2)')
args = parser.parse_args()

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

    # Run the show command and close the session
    output = net_connect.send_command(args.command)
    net_connect.disconnect()

    print(f'--- {device_name} ---')
    print(netauto.redact_output(output))
    print()
