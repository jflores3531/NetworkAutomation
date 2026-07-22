#!/usr/bin/env python
"""Push a SISF-based 'device-tracking policy' to a switch's access ports,
restricted to IPv4 (ARP/DHCPv4 only - IPv6 mechanisms disabled), for host IP
visibility via 'show device-tracking database'. Not a STIG requirement - kept
separate from L2_stig_harden.py on purpose. Requires IOS-XE (SISF
device-tracking); the classic-IOS lab switches (S1/S2/S3, vios_l2) don't
support 'device-tracking policy' - confirmed missing from 'device-tracking ?'
on S3, so this won't do anything useful there."""

import argparse
import re
import netauto

# Interface types that take switchport commands — VLAN SVIs, loopbacks, etc. are
# excluded since "switchport mode trunk" can never appear in their blocks and they'd
# otherwise be misclassified as host-facing/access.
SWITCHPORT_PREFIXES = ('GigabitEthernet', 'FastEthernet', 'TenGigabitEthernet', 'Ethernet', 'Port-channel')

POLICY_NAME = 'IPV4_VISIBILITY'


def parse_switchports(cfg):
    """Classify every switchport-capable interface as trunk or host-facing/access:
    an interface counts as trunk only if its block has 'switchport mode trunk';
    anything else (access mode, unset mode, dynamic negotiation) is host-facing.
    Returns (access_names, trunk_names)."""
    access, trunk = [], []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M):
            trunk.append(name)
        else:
            access.append(name)
    return access, trunk


# Parse the target device from the command line
parser = argparse.ArgumentParser(
    description="Push an IPv4-only SISF device-tracking policy to a device's access ports (IOS-XE only, not a STIG requirement)"
)
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

# Classify switchports so the policy is only attached to host-facing/access ports
running_config = str(net_connect.send_command('show running-config'))
access_ports, _ = parse_switchports(running_config)

# tracking enable: actively probe/track hosts on attached ports.
# no protocol ndp / no protocol dhcp6: disable the IPv6-tracking mechanisms,
# leaving ARP + DHCPv4 as the only sources - i.e. IPv4 only.
policy_commands = [
    f'device-tracking policy {POLICY_NAME}',
    'tracking enable',
    'no protocol ndp',
    'no protocol dhcp6',
]

interface_commands = []
for name in access_ports:
    interface_commands.append(f'interface {name}')
    interface_commands.append(f'device-tracking attach-policy {POLICY_NAME}')

commands = policy_commands + interface_commands

# Push the commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('L2_device_tracking.py', device_name, username, commands)

print(f'Device tracking policy pushed to {device_name}:')
for command in commands:
    print('  ' + command)
print()
print(output)

if not access_ports:
    print('\nNo access/host-facing switchports found — policy defined but not attached anywhere.')

print('\nView results with: show device-tracking database')
