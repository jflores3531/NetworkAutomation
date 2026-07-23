#!/usr/bin/env python
"""Push the global (non-interface-specific) hardening fixes from the DISA Cisco
NX-OS Switch L2S STIG to a device. Interface-scoped rules (Unknown Unicast
Flood Blocking, IP Source Guard, Dynamic ARP Inspection, storm control,
access/native VLAN) need to know which ports are host-facing vs. trunk/uplink
and are intentionally left out of this pass.
V-220681 (BPDU Guard) also pushes 'spanning-tree port type edge default' -
without it, the global bpduguard-default command has no edge ports to
activate on and is a functional no-op (same false-pass shape as L2S's
V-220630/PortFast). V-220493 (exec-timeout) uses NX-OS's single-argument
syntax ('exec-timeout <minutes>'), not IOS's two-argument form. V-220676
(VTP) requires a 'vtp domain' be set before 'vtp password' takes effect at
all on NX-OS - confirmed live on NXCore1 ("Domain not set" otherwise).
V-220689 (UDLD) only pushes 'feature udld' - 'udld enable' isn't valid
NX-OS syntax (confirmed live: "% Invalid command"), an IOS-ism that doesn't
carry over; UDLD is on by default for fiber interfaces once the feature
itself is enabled.
Also pushes V-220695 (native VLAN): unless a switchport already has an
explicit 'switchport access vlan <n>' line, it's pushed to trunk mode with
the shared native_vlan - the inverse default from L2_stig_harden.py's
access-layer switches. Appropriate here since NXCore1/NXCore2 are core
switches where most ports interconnect other switches, not end hosts."""

import argparse
import re
import netauto
import stig_common

# Interface types that take switchport commands on NX-OS - mgmt0
# (management), Vlan<n> (SVIs), and loopback<n> aren't physical/logical
# switchports and can't take 'switchport mode' commands at all.
NXOS_SWITCHPORT_PREFIXES = ('Ethernet', 'port-channel')


def classify_non_access_ports(cfg):
    """Return switchport-capable interface names lacking an explicit
    'switchport access vlan <n>' line. Checks for the VLAN assignment, not
    'switchport mode access' - confirmed live that 'switchport mode access'
    alone doesn't reliably show up in NX-OS running-config (default mode,
    same omission pattern IOS uses for VLAN 1), so it isn't a trustworthy
    signal on its own. An explicit access VLAN assignment is. Per Jorge's
    policy for these core switches: unless a port is already configured as
    access, it should be trunk - these are the switch's interconnect/uplink
    ports, or ports left in NX-OS's default negotiated mode."""
    non_access = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        if not re.search(r'^\s*switchport access vlan \d+\s*$', chunk, re.M):
            non_access.append(m.group(1))
    return non_access


# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    # 'spanning-tree port type edge bpduguard default' only activates BPDU
    # Guard on ports typed as "edge" (NX-OS's PortFast equivalent) - without
    # 'spanning-tree port type edge default' (the global equivalent of IOS's
    # 'spanning-tree portfast default'), the bpduguard-default command was
    # present in the config but functionally inert everywhere, since no port
    # was ever typed as edge (same false-pass shape as L2S's V-220630).
    'V-220681a (edge port type, required for BPDU Guard to activate)': 'spanning-tree port type edge default',
    'V-220681b (BPDU Guard)': 'spanning-tree port type edge bpduguard default',
    'V-220682 (Loop Guard)': 'spanning-tree loopguard default',
    'V-220688 (IGMP snooping)': 'ip igmp snooping',
}

# V-220493: exec-timeout on both console and vty (DISA's Check Text configures
# both). NX-OS's exec-timeout takes a single argument (minutes only), unlike
# IOS's two-argument 'exec-timeout <min> <sec>' form - stig_common.exec_timeout_ok()
# assumes the IOS syntax and would never match real NX-OS config.
EXEC_TIMEOUT_FIX = ['line console', 'exec-timeout 5', 'line vty', 'exec-timeout 5']

# V-220689 (UDLD): 'udld enable' is not a valid NX-OS global command at all -
# confirmed live on NXCore1 ("% Invalid command"), an IOS-ism that doesn't
# carry over. Per the STIG's own Fix Text, 'feature udld' alone is sufficient -
# UDLD is enabled by default on every fiber interface once the feature itself
# is turned on, no separate enable command needed.
UDLD_FIX = ['feature udld']

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

# VTP password (V-220676) comes from secrets.yaml instead of a prompt (gitignored,
# never committed - see secrets.yaml.example). VTP domain comes from
# inventory.yaml - required on NX-OS before a password takes effect at all
# (confirmed live on NXCore1: 'vtp password ...' silently fails with "Domain
# not set" otherwise, and Netmiko doesn't treat that as fatal). Not needed on
# IOS L2S switches, which accept the password with no domain set.
secrets = netauto.load_secrets()
vtp_password = str(secrets.get('vtp_password') or '').strip()
vtp_domain = netauto.load_vtp_domain()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Discover the switch's user VLANs (V-220684: DHCP snooping), excluding
# management/servers/unused VLANs from inventory.yaml's non_user_vlans
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=netauto.load_non_user_vlans())

# V-220695: classify switchports so every port lacking explicit access mode
# gets pushed to trunk with the shared native VLAN. Native VLAN comes from
# inventory.yaml (same native_vlan value L2_stig_harden.py uses, currently
# 999) - created in the VLAN database here too.
running_config = str(net_connect.send_command('show running-config'))
trunk_target_ports = classify_non_access_ports(running_config)
native_vlan_id = netauto.load_native_vlan()

native_vlan_commands = [f'vlan {native_vlan_id}', 'name NATIVE', 'exit'] if native_vlan_id else []

interface_commands = []
for name in trunk_target_ports:
    interface_commands.append(f'interface {name}')
    interface_commands.append('switchport mode trunk')
    if native_vlan_id:
        interface_commands.append(f'switchport trunk native vlan {native_vlan_id}')

# NTP server IPs (V-220498) come from inventory.yaml's services section. NTP
# authentication key (V-220502) comes from secrets.yaml.
ntp_servers = netauto.load_services().get('ntp_servers', [])
ntp_auth_key = secrets.get('ntp_auth_key') or {}
ntp_key_id = ntp_auth_key.get('id')
ntp_key_value = ntp_auth_key.get('value')
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
applied_fixes['V-220493 (exec-timeout)'] = '; '.join(EXEC_TIMEOUT_FIX)
applied_fixes['V-220689 (UDLD)'] = '; '.join(UDLD_FIX)
if trunk_target_ports and native_vlan_id:
    applied_fixes['V-220695 (native VLAN)'] = (
        f'switchport mode trunk; switchport trunk native vlan {native_vlan_id} '
        f'(on {len(trunk_target_ports)} non-access port(s): {", ".join(trunk_target_ports)})'
    )
if vlan_ids:
    applied_fixes['V-220684 (DHCP snooping)'] = f'feature dhcp; ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}'
if vtp_password and vtp_domain:
    applied_fixes['V-220676 (VTP authentication)'] = (
        f'feature vtp; vtp domain {vtp_domain}; vtp mode transparent; vtp password {vtp_password}'
    )
if ntp_servers:
    applied_fixes['V-220498 (NTP time sync)'] = '; '.join(
        f'ntp server {ip}' + (f' key {ntp_key_id}' if ntp_key_id else '') for ip in ntp_servers)
if ntp_key_id:
    applied_fixes['V-220502 (NTP authentication)'] = '; '.join([
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}', 'ntp authenticate', f'ntp trusted-key {ntp_key_id}'])

commands = list(BASE_FIXES.values()) + EXEC_TIMEOUT_FIX + UDLD_FIX
if vlan_ids:
    commands += ['feature dhcp', 'ip dhcp snooping', f'ip dhcp snooping vlan {",".join(vlan_ids)}']
commands += native_vlan_commands + interface_commands
if vtp_password and vtp_domain:
    # Domain must be set before the password takes effect - confirmed live
    # on NXCore1 ('vtp password ...' fails with "Domain not set" otherwise.
    # Transparent mode also means this switch won't originate/relay VLAN
    # database changes to peers (same reasoning L2_stig_harden.py uses).
    commands += ['feature vtp', f'vtp domain {vtp_domain}', 'vtp mode transparent', f'vtp password {vtp_password}']
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

if not native_vlan_id:
    print('\nSkipped V-220695 (native VLAN) — add native_vlan to inventory.yaml to include it.')
elif not trunk_target_ports:
    print(f'\nNo non-access switchports found — every port already has an explicit `switchport access vlan <n>` line, nothing to push for V-220695.')
if not (vtp_password and vtp_domain):
    missing = []
    if not vtp_password:
        missing.append('vtp_password to secrets.yaml')
    if not vtp_domain:
        missing.append('vtp_domain to inventory.yaml')
    print(f'\nSkipped V-220676 (VTP authentication) — add {" and ".join(missing)} to include it.')
if not ntp_servers:
    print('\nSkipped V-220498 (NTP time sync) — add ntp_servers to inventory.yaml\'s services section to include it.')
if not ntp_key_id:
    print('\nSkipped V-220502 (NTP authentication) — add ntp_auth_key to secrets.yaml to include it.')

print('\nRules requiring interface targeting (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)
