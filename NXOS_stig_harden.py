#!/usr/bin/env python
"""Push the global (non-interface-specific) hardening fixes from the DISA Cisco
NX-OS Switch L2S STIG to a device. Interface-scoped rules (Unknown Unicast
Flood Blocking, IP Source Guard, Dynamic ARP Inspection, storm control,
access/native VLAN) need to know which ports are host-facing vs. trunk/uplink
and are intentionally left out of this pass."""

import argparse
import netauto
import stig_common

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    'V-220681 (BPDU Guard)': 'spanning-tree port type edge bpduguard default',
    'V-220682 (Loop Guard)': 'spanning-tree loopguard default',
    'V-220688 (IGMP snooping)': 'ip igmp snooping',
}

# V-220689 (UDLD) needs the udld feature enabled before it can be turned on
UDLD_FIX = ['feature udld', 'udld enable']

# Rules that need per-interface targeting (host-facing vs. trunk/uplink) and are
# intentionally not pushed by this global-only pass
SKIPPED_RULES = [
    'V-220683 (Unknown Unicast Flood Blocking)',
    'V-220685 (IP Source Guard)',
    'V-220686 (Dynamic ARP Inspection)',
    'V-220687 (storm control)',
    'V-220691 (default VLAN on host ports)',
    'V-220692 (default VLAN pruned from trunks)',
    'V-220694 (user-facing ports as access)',
    'V-220695 (native VLAN)',
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push global L2S STIG hardening fixes to an NX-OS device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. NXCore1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# Prompt for VTP password (V-220676) — leave blank to skip
vtp_password = input('Enter VTP domain password (V-220676) — leave blank to skip: ').strip()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Discover the switch's user VLANs (V-220684: DHCP snooping), excluding
# management/servers/unused VLANs from inventory.yaml's non_user_vlans
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=netauto.load_non_user_vlans())

# NTP server IPs (V-220498) come from inventory.yaml's services section instead of
# a prompt. Still prompt for the authentication key — that's credential-like, not
# an address, and doesn't belong in inventory.yaml.
ntp_servers = netauto.load_services().get('ntp_servers', [])
ntp_auth = input('Enter NTP authentication key ID and MD5 value for V-220502, '
                  'space-separated (e.g. "1 MyStrongKey123") — leave blank to skip: ').strip()
ntp_key_id, _, ntp_key_value = ntp_auth.partition(' ')
ntp_key_value = ntp_key_value.strip()
if not ntp_key_value:
    ntp_key_id = None

ntp_commands = []
if ntp_servers or ntp_key_id:
    ntp_commands.append('feature ntp')
if ntp_key_id:
    ntp_commands += [
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}',
        'ntp authenticate',
        f'ntp trusted-key {ntp_key_id}',
    ]
if ntp_servers:
    key_suffix = f' key {ntp_key_id}' if ntp_key_id else ''
    ntp_commands += [f'ntp server {ip}{key_suffix}' for ip in ntp_servers]

applied_fixes = dict(BASE_FIXES)
applied_fixes['V-220689 (UDLD)'] = '; '.join(UDLD_FIX)
if vlan_ids:
    applied_fixes['V-220684 (DHCP snooping)'] = f'feature dhcp; ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}'
if vtp_password:
    applied_fixes['V-220676 (VTP authentication)'] = f'feature vtp; vtp password {vtp_password}'
if ntp_servers:
    applied_fixes['V-220498 (NTP time sync)'] = '; '.join(
        f'ntp server {ip}' + (f' key {ntp_key_id}' if ntp_key_id else '') for ip in ntp_servers)
if ntp_key_id:
    applied_fixes['V-220502 (NTP authentication)'] = '; '.join([
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}', 'ntp authenticate', f'ntp trusted-key {ntp_key_id}'])

commands = list(BASE_FIXES.values()) + UDLD_FIX
if vlan_ids:
    commands += ['feature dhcp', 'ip dhcp snooping', f'ip dhcp snooping vlan {",".join(vlan_ids)}']
if vtp_password:
    commands += ['feature vtp', f'vtp password {vtp_password}']
commands += ntp_commands

# Push the hardening commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('NXOS_stig_harden.py', device_name, username, commands)

print(f'Hardening commands pushed to {device_name}:')
for command in commands:
    print('  ' + command)
print()
print(output)

print(f'\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not vtp_password:
    print('\nSkipped V-220676 (VTP authentication) — enter a VTP password at the prompt to include it.')
if not ntp_servers:
    print('\nSkipped V-220498 (NTP time sync) — add ntp_servers to inventory.yaml\'s services section to include it.')
if not ntp_key_id:
    print('\nSkipped V-220502 (NTP authentication) — enter an NTP key ID/MD5 value at the prompt to include it.')

print('\nRules requiring interface targeting (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)
