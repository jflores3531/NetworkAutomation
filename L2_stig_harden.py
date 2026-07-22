#!/usr/bin/env python
"""Push the global and interface-scoped hardening fixes from the DISA Cisco IOS
Switch L2S STIG to a device. Interface-scoped rules classify each switchport as
host-facing/access or trunk/uplink based on whether "switchport mode trunk" is
present, then push the matching fixes to each. V-220642 (default VLAN on
host-facing ports) and V-220645 (user-facing ports must be access) are left out —
see the comment above L2_stig_audit.py's CHECKS dict for why."""

import argparse
import re
import netauto
import stig_common

# Interface types that take switchport commands — VLAN SVIs, loopbacks, etc. are
# excluded since "switchport mode trunk" can never appear in their blocks and they'd
# otherwise be misclassified as host-facing/access.
SWITCHPORT_PREFIXES = ('GigabitEthernet', 'FastEthernet', 'TenGigabitEthernet', 'Ethernet', 'Port-channel')


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


def shutdown_access_ports(cfg, access_names):
    """Return the subset of access_names whose interface block has 'shutdown' —
    used by V-220641 to reassign only ports that are already disabled."""
    shutdown = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if m and m.group(1) in access_names and re.search(r'^\s*shutdown\s*$', chunk, re.M):
            shutdown.append(m.group(1))
    return shutdown


# Pushed to every host-facing/access-classified interface
ACCESS_PORT_FIXES = [
    'switchport block unicast',       # V-220632 (UUFB)
    'ip verify source',               # V-220634 (IP Source Guard) - needs DHCP snooping active
    'storm-control broadcast level bps 20000000',  # V-220636 (storm control)
]

# Pushed to every trunk/uplink-classified interface (allowed-vlan list, native VLAN
# line, added separately below once the device's actual VLAN database is known)
TRUNK_PORT_FIXES = [
    'switchport nonegotiate',  # V-220640 (static trunk, no DTP negotiation)
]

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    'V-220630 (BPDU Guard)': 'spanning-tree portfast bpduguard default',
    'V-220631 (Loop Guard)': 'spanning-tree loopguard default',
    'V-220638 (Rapid-PVST)': 'spanning-tree mode rapid-pvst',
    'V-220639 (UDLD)': 'udld enable',
    'V-220637 (IGMP snooping)': 'ip igmp snooping',
    'V-220580 (log timestamps)': 'service timestamps log datetime localtime',
    'V-220599 (logging buffer size)': 'logging buffered 64000 informational',
    'V-220612a (log on-failure)': 'login on-failure log',
    'V-220612b (log on-success)': 'login on-success log',
    'V-220576 (lockout after 3 failed attempts)': 'login block-for 900 attempts 3 within 120',
    'V-220578 (admin activity logging)': 'logging userinfo',
    'V-220570a (HTTP session limit)': 'ip http max-connections 2',
    'V-220625 (QoS enabled)': 'mls qos',
}

# Not a STIG requirement - pushed for host visibility only. ARP-probes every
# L2 port and populates 'show ip device tracking all' with each host's
# IP/MAC/VLAN/interface, static or DHCP-assigned alike (unlike IP Source Guard,
# it doesn't rely on the DHCP snooping binding table).
OPTIONAL_FIXES = {
    'IP Device Tracking (host visibility, not a STIG requirement)': 'ip device tracking',
}

# V-220570: session-limit needs its own "line vty 0 4" context
VTY_SESSION_LIMIT_FIX = ['line vty 0 4', 'session-limit 2']

# V-220608: SSH encryption algorithm — includes "ip ssh version 2" too, since
# V-220608's own audit check requires both and this makes V-220607 pass as a
# side effect
SSH_ENCRYPTION_FIX = [
    'ip ssh version 2',
    'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr',
]

# V-220586: disable unnecessary/nonsecure services — idempotent, safe to push
# unconditionally even when a service is already disabled
UNNECESSARY_SERVICES_FIX = [
    'no boot network',
    'no ip boot server',
    'no ip bootp server',
    'no ip dns server',
    'no ip identd',
    'no ip finger',
    'no ip http server',
    'no ip rcmd rcp-enable',
    'no ip rcmd rsh-enable',
    'no service config',
    'no service finger',
    'no service tcp-small-servers',
    'no service udp-small-servers',
    'no service pad',
    'no service call-home',
]

# V-220571/572/573/574/582/597/611/613: config-change archive logging satisfies
# all 8 rules at once (DISA reuses the exact same evidence for each)
ARCHIVE_LOGGING_FIX = [
    'archive',
    'log config',
    'logging enable',
    'logging size 1000',
    'notify syslog contenttype plaintext',
    'hidekeys',
]

# Rules intentionally not pushed by this script (see module docstring)
SKIPPED_RULES = [
    'V-220642 (default VLAN on host ports)',
    'V-220645 (user-facing ports as access)',
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

# VTP password (V-220624) comes from secrets.yaml instead of a prompt (gitignored,
# never committed - see secrets.yaml.example)
secrets = netauto.load_secrets()
vtp_password = str(secrets.get('vtp_password') or '').strip()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Discover the switch's user VLANs (V-220633: DHCP snooping, V-220635: DAI),
# excluding management/servers/unused VLANs from inventory.yaml's non_user_vlans
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=netauto.load_non_user_vlans())

# V-220629: STP root port(s), live - Root Guard must never be pushed there (see
# stig_common.discover_root_port_interfaces for why: it forces the port into
# root-inconsistent/blocking state, a real outage risk).
root_ports = stig_common.discover_root_port_interfaces(net_connect)

# Classify switchports (host-facing/access vs. trunk/uplink) for the interface-scoped fixes
running_config = str(net_connect.send_command('show running-config'))
access_ports, trunk_ports = parse_switchports(running_config)
root_guard_ports = [name for name in trunk_ports if name not in root_ports]

# V-220641: already-shutdown access ports get reassigned to the designated
# unused VLAN (safe - they're not passing traffic)
unused_vlan = netauto.load_unused_vlan()
disabled_ports = shutdown_access_ports(running_config, access_ports) if unused_vlan else []

# V-220643/641: trunks should carry only VLANs that actually exist in the switch's
# VLAN database, minus the default VLAN (1) and the designated unused VLAN - not
# just "everything except 1/999", which would still leave every undefined VLAN ID
# allowed too. An explicit list also sidesteps the except/remove semantics
# entirely (no risk of clobbering a pre-existing restriction on first run).
trunk_vlan_exclude = [1] + ([unused_vlan] if unused_vlan else [])
allowed_trunk_vlans = stig_common.discover_user_vlans(net_connect, exclude=trunk_vlan_exclude)

# Native VLAN for trunk ports (V-220646) comes from inventory.yaml instead of a prompt
native_vlan_id = netauto.load_native_vlan()

# NTP/syslog server IPs (V-220601, V-220620) come from inventory.yaml's services
# section. NTP authentication key (V-220606) comes from secrets.yaml.
services = netauto.load_services()
ntp_servers = services.get('ntp_servers', [])
syslog_servers = services.get('syslog_servers', [])
ntp_auth_key = secrets.get('ntp_auth_key') or {}
ntp_key_id = ntp_auth_key.get('id')
ntp_key_value = ntp_auth_key.get('value')
if not ntp_key_value:
    ntp_key_id = None

ntp_commands = []
if ntp_key_id:
    ntp_commands += [
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}',
        'ntp authenticate',
        f'ntp trusted-key {ntp_key_id}',
    ]
if ntp_servers:
    key_suffix = f' key {ntp_key_id}' if ntp_key_id else ''
    ntp_commands += [f'ntp server {ip}{key_suffix}' for ip in ntp_servers]

# AAA/RADIUS (V-220587/617) is pushed by the separate L2_stig_harden_aaa.py
# script, not here - bundling aaa new-model in with this script's ~60-command
# batch caused a live session to drop on S2 right after aaa new-model took
# effect, before the rest of the block could send, leaving the device
# half-configured and SSH-inaccessible (recovered via console + 'no aaa
# new-model'). Keeping it isolated makes it safer to push and easier to
# diagnose if it ever fails again.

# Build the per-interface command blocks now that ports are classified
trunk_fixes = list(TRUNK_PORT_FIXES)
if allowed_trunk_vlans:
    trunk_fixes.append(f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)}')
if native_vlan_id:
    trunk_fixes.append(f'switchport trunk native vlan {native_vlan_id}')

interface_commands = []
for name in access_ports:
    interface_commands.append(f'interface {name}')
    interface_commands += ACCESS_PORT_FIXES
for name in trunk_ports:
    interface_commands.append(f'interface {name}')
    interface_commands += trunk_fixes
    if name in root_guard_ports:
        interface_commands.append('spanning-tree guard root')
for name in disabled_ports:
    interface_commands.append(f'interface {name}')
    interface_commands.append(f'switchport access vlan {unused_vlan}')

applied_fixes = dict(BASE_FIXES)
applied_fixes.update(OPTIONAL_FIXES)
applied_fixes['V-220586 (unnecessary services)'] = '; '.join(UNNECESSARY_SERVICES_FIX)
applied_fixes['V-220608 (SSH encryption)'] = '; '.join(SSH_ENCRYPTION_FIX)
applied_fixes['V-220571/572/573/574/582/597/611/613 (archive logging)'] = '; '.join(ARCHIVE_LOGGING_FIX)
applied_fixes['V-220570b (VTY session limit)'] = '; '.join(VTY_SESSION_LIMIT_FIX)
if vlan_ids:
    applied_fixes['V-220633 (DHCP snooping)'] = f'ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}'
    applied_fixes['V-220635 (DAI)'] = f'ip arp inspection vlan {",".join(vlan_ids)}'
if vtp_password:
    applied_fixes['V-220624 (VTP authentication)'] = f'vtp password {vtp_password}'
if access_ports:
    applied_fixes['V-220632 (UUFB)'] = '; '.join(ACCESS_PORT_FIXES[:1]) + f' (on {len(access_ports)} access port(s))'
    applied_fixes['V-220634 (IP Source Guard)'] = '; '.join(ACCESS_PORT_FIXES[1:2]) + f' (on {len(access_ports)} access port(s))'
    applied_fixes['V-220636 (storm control)'] = '; '.join(ACCESS_PORT_FIXES[2:3]) + f' (on {len(access_ports)} access port(s))'
if trunk_ports:
    applied_fixes['V-220640 (static trunk)'] = f'switchport nonegotiate (on {len(trunk_ports)} trunk port(s))'
    if root_guard_ports:
        applied_fixes['V-220629 (Root Guard)'] = (
            f'spanning-tree guard root (on {len(root_guard_ports)} trunk port(s) not leading '
            f'to the STP root: {", ".join(root_guard_ports)})'
        )
    if allowed_trunk_vlans:
        applied_fixes['V-220643/641b (trunks scoped to real VLANs only)'] = (
            f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)} '
            f'(on {len(trunk_ports)} trunk port(s))'
        )
    if native_vlan_id:
        applied_fixes['V-220646 (native VLAN)'] = f'switchport trunk native vlan {native_vlan_id} (on {len(trunk_ports)} trunk port(s))'
if disabled_ports:
    applied_fixes['V-220641a (disabled ports to unused VLAN)'] = f'switchport access vlan {unused_vlan} (on {len(disabled_ports)} disabled port(s): {", ".join(disabled_ports)})'
if ntp_servers:
    applied_fixes['V-220601 (NTP time sync)'] = '; '.join(
        f'ntp server {ip}' + (f' key {ntp_key_id}' if ntp_key_id else '') for ip in ntp_servers)
if ntp_key_id:
    applied_fixes['V-220606 (NTP authentication)'] = '; '.join([
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}', 'ntp authenticate', f'ntp trusted-key {ntp_key_id}'])
if syslog_servers:
    applied_fixes['V-220620 (dual syslog servers)'] = '; '.join(f'logging host {ip}' for ip in syslog_servers)

commands = list(BASE_FIXES.values()) + list(OPTIONAL_FIXES.values()) + UNNECESSARY_SERVICES_FIX + SSH_ENCRYPTION_FIX + ARCHIVE_LOGGING_FIX + VTY_SESSION_LIMIT_FIX
if vlan_ids:
    commands += ['ip dhcp snooping', f'ip dhcp snooping vlan {",".join(vlan_ids)}', f'ip arp inspection vlan {",".join(vlan_ids)}']
if vtp_password:
    commands.append(f'vtp password {vtp_password}')
commands += interface_commands
commands += ntp_commands
commands += [f'logging host {ip}' for ip in syslog_servers]

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
print('\nIP Device Tracking pushed - view results with `show ip device tracking all` on the device.')

if not access_ports:
    print('\nNo access/host-facing switchports found — nothing to push for V-220632/634/636.')
if not trunk_ports:
    print('\nNo trunk switchports found — nothing to push for V-220629/640/643/646.')
elif not root_guard_ports:
    print('\nSkipped V-220629 (Root Guard) — every trunk port is this switch\'s STP root port toward the root bridge; Root Guard must not be applied there.')
if trunk_ports and not allowed_trunk_vlans:
    print('\nSkipped V-220643/641b (trunk VLAN scoping) — no VLANs discovered in the VLAN database besides VLAN 1/unused_vlan.')
if trunk_ports and not native_vlan_id:
    print('\nSkipped V-220646 (native VLAN) — add native_vlan to inventory.yaml to include it.')
if not unused_vlan:
    print('\nSkipped V-220641 (unused VLAN) — add unused_vlan to inventory.yaml to include it.')
elif not disabled_ports:
    print('\nNo disabled (shutdown) access ports found — nothing to reassign for V-220641.')
if not vtp_password:
    print('\nSkipped V-220624 (VTP authentication) — add vtp_password to secrets.yaml to include it.')
if not ntp_servers:
    print('\nSkipped V-220601 (NTP time sync) — add ntp_servers to inventory.yaml\'s services section to include it.')
if not syslog_servers:
    print('\nSkipped V-220620 (dual syslog servers) — add syslog_servers to inventory.yaml\'s services section to include it.')
if not ntp_key_id:
    print('\nSkipped V-220606 (NTP authentication) — add ntp_auth_key to secrets.yaml to include it.')

print('\nV-220587/617 (AAA new-model + RADIUS auth) is pushed separately by L2_stig_harden_aaa.py.')

print('\nRules requiring interface targeting (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)
