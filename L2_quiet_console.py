#!/usr/bin/env python
"""Disable live logging output to the console/terminal on a device - not a
STIG requirement, pure quality-of-life for anyone actively configuring the
device interactively (console or SSH). Log messages still go to the buffer
(`logging buffered`, pushed by L2_stig_harden.py) and syslog servers as
normal - this only stops them from interrupting an active session. Use
`show logging` on the device to see buffered messages on demand instead.

Kept as its own script rather than folded into L2_stig_harden.py since it's
unrelated to STIG compliance and purely a terminal-comfort preference."""

import argparse
import netauto

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Disable live console/terminal logging output on a device (not a STIG requirement)')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

commands = ['no logging console', 'no logging monitor']

# Push the commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('L2_quiet_console.py', device_name, username, commands)

print(f'Console/terminal logging disabled on {device_name}:')
for command in commands:
    print('  ' + command)
print()
print(output)
print('\nLog messages are still buffered and sent to syslog as normal - use `show logging` on the device to view them on demand.')
print('To turn live logging back on: `logging console` / `logging monitor` in config mode.')
