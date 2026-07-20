#!/usr/bin/env python
"""Push the global (non-interface-specific) hardening fixes from the DISA Cisco
IOS Switch L2S STIG to a device. Interface-scoped rules (IP Source Guard, DAI,
access VLAN, native VLAN, etc.) need to know which ports are host-facing vs.
trunk/uplink and are intentionally left out of this pass."""

import argparse
import netauto
import stig_common

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    'V-220630 (BPDU Guard)': 'spanning-tree portfast bpduguard default',
    'V-220631 (Loop Guard)': 'spanning-tree loopguard default',
    'V-220638 (Rapid-PVST)': 'spanning-tree mode rapid-pvst',
    'V-220639 (UDLD)': 'udld enable',
    'V-220637 (IGMP snooping)': 'ip igmp snooping',
}

# Rules that need per-interface targeting (host-facing vs. trunk/uplink) and are
# intentionally not pushed by this global-only pass
SKIPPED_RULES = [
    'V-220632 (Unknown Unicast Flood Blocking)',
    'V-220634 (IP Source Guard)',
    'V-220635 (Dynamic ARP Inspection)',
    'V-220636 (storm control)',
    'V-220640 (static trunk links)',
    'V-220642 (default VLAN on host ports)',
    'V-220643 (default VLAN pruned from trunks)',
    'V-220645 (user-facing ports as access)',
    'V-220646 (native VLAN)',
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push global L2S STIG hardening fixes to a device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# Prompt for VTP password (V-220624) — leave blank to skip
vtp_password = input('Enter VTP domain password (V-220624) — leave blank to skip: ').strip()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Discover the switch's user VLANs (V-220633: DHCP snooping)
vlan_ids = stig_common.discover_user_vlans(net_connect)

applied_fixes = dict(BASE_FIXES)
if vlan_ids:
    applied_fixes['V-220633 (DHCP snooping)'] = f'ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}'
if vtp_password:
    applied_fixes['V-220624 (VTP authentication)'] = f'vtp password {vtp_password}'

commands = list(BASE_FIXES.values())
if vlan_ids:
    commands += ['ip dhcp snooping', f'ip dhcp snooping vlan {",".join(vlan_ids)}']
if vtp_password:
    commands.append(f'vtp password {vtp_password}')

# Push the hardening commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('L2_stig_harden.py', device_name, username, commands)

print(f'Hardening commands pushed to {device_name}:')
for command in commands:
    print('  ' + command)
print()
print(output)

print(f'\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not vtp_password:
    print('\nSkipped V-220624 (VTP authentication) — enter a VTP password at the prompt to include it.')

print('\nRules requiring interface targeting (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)
