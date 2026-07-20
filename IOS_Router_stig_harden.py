#!/usr/bin/env python
"""Push the global (non-interface-specific) hardening fixes from the DISA Cisco
IOS Router RTR STIG to a device. Interface-scoped rules (directed broadcast,
ICMP redirects/unreachables/mask-reply, proxy ARP, LLDP transmit) need to be
applied per-interface and are intentionally left out of this pass."""

import argparse
import netauto

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    'V-216563 (Gratuitous ARPs)': 'no ip gratuitous-arps',
    'V-216585 (CDP)': 'no cdp run',
    'V-229030 (CEF)': 'ip cef',
}

# V-216571 (AUX port disabled) needs two lines under "line aux 0", so it's
# handled separately from the single-command BASE_FIXES
AUX_PORT_FIX = ['line aux 0', 'no exec']

# Rules that need per-interface targeting and are intentionally not pushed by
# this global-only pass
SKIPPED_RULES = [
    'V-216564 (directed broadcast)',
    'V-216565 (ICMP unreachables)',
    'V-216566 (ICMP mask reply)',
    'V-216567 (ICMP redirects)',
    'V-216584 (LLDP transmit)',
    'V-216586 (proxy ARP)',
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push global RTR STIG hardening fixes to a device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1)')
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

applied_fixes = dict(BASE_FIXES)
applied_fixes['V-216571 (AUX port disabled)'] = '; '.join(AUX_PORT_FIX)

commands = list(BASE_FIXES.values()) + AUX_PORT_FIX

# Push the hardening commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('IOS_Router_stig_harden.py', device_name, username, commands)

print(f'Hardening commands pushed to {device_name}:')
for command in commands:
    print('  ' + command)
print()
print(output)

print(f'\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

print('\nRules requiring interface targeting (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)
