#!/usr/bin/env python
"""Push SISF-based 'device-tracking policy' blocks to a switch, for host IP
visibility via 'show device-tracking database'. Not a STIG requirement - kept
separate from l2_stig_harden_global.py on purpose. Requires IOS-XE (SISF
device-tracking); the classic-IOS lab switches (S1/S2/S3, vios_l2) don't
support 'device-tracking policy' - confirmed missing from 'device-tracking ?'
on S3, so this won't do anything useful there.

Three policies, all independent (none replaces another):
- IPV4_VISIBILITY: tracking enabled, IPv6 (ndp/dhcp6) disabled - attached to
  every access port directly (interface-level attach-policy).
- DT-NOIPV6: IPv6 and UDP disabled, ARP/DHCPv4 left alone - its own separate
  policy, not a replacement for IPV4_VISIBILITY.
- NOTRACK: every protocol disabled plus 'tracking disable' outright.

DT-NOIPV6 and NOTRACK are both attached at VLAN scope ('vlan configuration
<id>' / 'device-tracking attach-policy <name>'), to every VLAN except the
default (1) and native/unused (inventory.yaml's native_vlan/unused_vlan).
IOS-XE allows multiple attach-policy lines under the same VLAN target and
resolves conflicts by system-determined priority (see the Cisco FHS/SISF
Configuration Guide) - not verifiable live in this lab, since none of it does
anything on the classic-IOS switches available here."""

import argparse
import re
import netauto

# Interface types that take switchport commands — VLAN SVIs, loopbacks, etc. are
# excluded since "switchport mode trunk" can never appear in their blocks and they'd
# otherwise be misclassified as host-facing/access. The multigigabit and 25G-and-up
# names are IOS-XE (Catalyst 9000) forms with no equivalent on the lab's vios_l2
# image; leaving them out doesn't error, it silently skips those ports, which reads
# exactly like a clean run. AppGigabitEthernet is deliberately excluded: it's the
# internal port to the switch's app-hosting container, not an external attack
# surface, and access-port hardening there would disrupt app hosting rather than
# protect anything.
SWITCHPORT_PREFIXES = (
    'GigabitEthernet', 'FastEthernet', 'TenGigabitEthernet', 'TwoGigabitEthernet',
    'FiveGigabitEthernet', 'TwentyFiveGigE', 'FortyGigabitEthernet', 'HundredGigE',
    'TwoHundredGigE', 'FourHundredGigE', 'Ethernet', 'Port-channel',
)

IPV4_VISIBILITY_POLICY = 'IPV4_VISIBILITY'
NOIPV6_POLICY = 'DT-NOIPV6'
NOTRACK_POLICY = 'NOTRACK'


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


def discover_vlans(net_connect, exclude=()):
    """Return every VLAN ID from 'show vlan brief', excluding the reserved
    fddi/token-ring range (1002-1005) and any VLAN IDs in `exclude`. Distinct
    from stig_common.discover_user_vlans() - this deliberately does NOT
    exclude inventory.yaml's non_user_vlans (management/servers VLANs like
    10/100 still get DT-NOIPV6/NOTRACK attached), only VLAN 1 and the
    native/unused VLAN."""
    exclude_ids = {int(v) for v in exclude}
    vlan_brief = str(net_connect.send_command('show vlan brief'))
    return [
        vid for vid in re.findall(r'^(\d+)\s+\S+', vlan_brief, re.M)
        if not (1002 <= int(vid) <= 1005) and int(vid) not in exclude_ids
    ]


# Parse the target device from the command line
parser = argparse.ArgumentParser(
    description="Push SISF device-tracking policies to a device (IOS-XE only, not a STIG requirement)"
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

# Classify switchports so IPV4_VISIBILITY is only attached to host-facing/access ports
running_config = str(net_connect.send_command('show running-config'))
access_ports, _ = parse_switchports(running_config)

# VLANs to attach DT-NOIPV6/NOTRACK to: everything except VLAN 1 (hardcoded,
# universal default) and native_vlan/unused_vlan from inventory.yaml (both
# currently 999 - deduped automatically via the exclude set).
native_vlan_id = netauto.load_native_vlan()
unused_vlan_id = netauto.load_unused_vlan()
vlan_exclude = [1] + [v for v in (native_vlan_id, unused_vlan_id) if v]
target_vlans = discover_vlans(net_connect, exclude=vlan_exclude)

# tracking enable: actively probe/track hosts on attached ports.
# no protocol ndp / no protocol dhcp6: disable the IPv6-tracking mechanisms,
# leaving ARP + DHCPv4 as the only sources - i.e. IPv4 only.
policy_commands = [
    f'device-tracking policy {IPV4_VISIBILITY_POLICY}',
    'tracking enable',
    'no protocol ndp',
    'no protocol dhcp6',
]

# DT-NOIPV6: its own separate policy, not a replacement for IPV4_VISIBILITY -
# IPv6 and UDP disabled, ARP/DHCPv4 left alone.
policy_commands += [
    f'device-tracking policy {NOIPV6_POLICY}',
    'no protocol ndp',
    'no protocol dhcp6',
    'no protocol udp',
]

# NOTRACK: every protocol disabled plus tracking disabled outright.
policy_commands += [
    f'device-tracking policy {NOTRACK_POLICY}',
    'no protocol ndp',
    'no protocol dhcp6',
    'no protocol arp',
    'no protocol dhcp4',
    'no protocol udp',
    'tracking disable',
]

interface_commands = []
for name in access_ports:
    interface_commands.append(f'interface {name}')
    interface_commands.append(f'device-tracking attach-policy {IPV4_VISIBILITY_POLICY}')

vlan_commands = []
for vlan_id in target_vlans:
    vlan_commands.append(f'vlan configuration {vlan_id}')
    vlan_commands.append(f'device-tracking attach-policy {NOIPV6_POLICY}')
    vlan_commands.append(f'device-tracking attach-policy {NOTRACK_POLICY}')

commands = policy_commands + interface_commands + vlan_commands

# Push the commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('l2_device_tracking.py', device_name, username, commands)

print(f'Device tracking policies pushed to {device_name}:')
for command in commands:
    print('  ' + netauto.redact_secrets(command))
print()
print(netauto.redact_output(output))

if not access_ports:
    print(f'\nNo access/host-facing switchports found — {IPV4_VISIBILITY_POLICY} defined but not attached anywhere.')
if not target_vlans:
    print(f'\nNo VLANs found besides VLAN 1/native/unused — {NOIPV6_POLICY}/{NOTRACK_POLICY} defined but not attached anywhere.')

print('\nView results with: show device-tracking database')
print('View policy/VLAN attachments with: show device-tracking policy <name>')
