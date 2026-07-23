#!/usr/bin/env python
"""Push the global and interface-scoped hardening fixes from the DISA Cisco
NX-OS Switch L2S STIG to a device. Interface-scoped rules classify each
switchport by whether it has an explicit 'switchport access vlan <n>' line -
present means access/host-facing, absent means trunk (see
classify_switchports() for why this signal is used instead of 'switchport
mode access').
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
V-220695 (native VLAN): unless a switchport already has an explicit
'switchport access vlan <n>' line, it's pushed to trunk mode with the
shared native_vlan - the inverse default from L2_stig_harden.py's
access-layer switches. Appropriate here since NXCore1/NXCore2 are core
switches where most ports interconnect other switches, not end hosts.
V-220683 (UUFB) and V-220685 (IP Source Guard) are pushed to every
access-classified port - V-220685 uses NX-OS's own syntax
('ip verify source dhcp-snooping-vlan'), confirmed different from IOS's
'ip verify source'. V-220687 (storm control) uses NX-OS's percentage-based
threshold ('storm-control broadcast level <percent>'), confirmed different
from IOS's bps-based form - broadcast is the Check Text's compliance floor,
same as L2S. V-220686 (DAI) and V-220692 (trunk VLAN pruning) are pushed
alongside V-220684 (DHCP snooping)/V-220695 respectively, since neither
needs new interface classification beyond what's already gathered.
V-220691/694 (default VLAN on host ports / user-facing ports as access)
aren't pushed by anything here - they're satisfied by construction (access
ports are never touched, only ports without an explicit access VLAN get
converted to trunk), but verifying that needs per-port classification in
NXOS_stig_audit.py, which doesn't have any yet - a separate, later addition."""

import argparse
import re
import netauto
import stig_common

# Interface types that take switchport commands on NX-OS - mgmt0
# (management), Vlan<n> (SVIs), and loopback<n> aren't physical/logical
# switchports and can't take 'switchport mode' commands at all.
NXOS_SWITCHPORT_PREFIXES = ('Ethernet', 'port-channel')


def classify_switchports(cfg):
    """Classify every switchport-capable interface as access (has an
    explicit 'switchport access vlan <n>' line) or not (everything else -
    trunk-classified already, or left in NX-OS's default negotiated mode).
    Checks for the VLAN assignment, not 'switchport mode access' -
    confirmed live that 'switchport mode access' alone doesn't reliably
    show up in NX-OS running-config (default mode, same omission pattern
    IOS uses for VLAN 1), so it isn't a trustworthy signal on its own. Per
    Jorge's policy for these core switches: unless a port is already
    configured as access, it should be trunk - these are the switch's
    interconnect/uplink ports, or ports left in NX-OS's default negotiated
    mode. Returns (access_names, non_access_names)."""
    access, non_access = [], []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if re.search(r'^\s*switchport access vlan \d+\s*$', chunk, re.M):
            access.append(name)
        else:
            non_access.append(name)
    return access, non_access


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

# Pushed to every access-classified port. V-220685 uses NX-OS's own IPSG
# syntax ('ip verify source dhcp-snooping-vlan'), not IOS's 'ip verify
# source'. V-220687's threshold is a percentage (NX-OS), not bps (IOS) -
# 40% matches DISA's own Fix Text example; per the STIG's own note,
# network engineers are responsible for the actual value, this is a
# reasonable default, not a mandated one. Only broadcast is pushed -
# Check Text's compliance floor is broadcast alone, same as L2S's V-220636.
ACCESS_PORT_FIXES = [
    'switchport block unicast',               # V-220683 (UUFB)
    'ip verify source dhcp-snooping-vlan',     # V-220685 (IP Source Guard)
    'storm-control broadcast level 40',        # V-220687 (storm control)
]

# Rules that need per-port audit verification this script's audit
# counterpart doesn't have yet (no interface classification at all in
# NXOS_stig_audit.py) - satisfied by construction on the harden side
# (access ports are never touched, only non-access ports get converted to
# trunk), but not yet independently verified.
SKIPPED_RULES = [
    'V-220691 (default VLAN on host ports)',
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

# Discover the switch's user VLANs (V-220684: DHCP snooping, V-220686: DAI -
# same VLAN set for both), excluding management/servers/unused VLANs from
# inventory.yaml's non_user_vlans
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=netauto.load_non_user_vlans())

# V-220692: trunks should carry only VLANs that actually exist in the switch's
# VLAN database, minus the default VLAN (1) and the designated unused VLAN -
# same explicit-list pattern L2_stig_harden.py uses (sidesteps 'except'/
# 'remove' semantics entirely, no risk of clobbering a pre-existing
# restriction on first run).
unused_vlan = netauto.load_unused_vlan()
trunk_vlan_exclude = [1] + ([unused_vlan] if unused_vlan else [])
allowed_trunk_vlans = stig_common.discover_user_vlans(net_connect, exclude=trunk_vlan_exclude)

# V-220695/683/685/687: classify switchports so every port lacking explicit
# access mode gets pushed to trunk with the shared native VLAN, and every
# access-classified port gets UUFB/IPSG/storm control. Native VLAN comes
# from inventory.yaml (same native_vlan value L2_stig_harden.py uses,
# currently 999) - created in the VLAN database here too.
running_config = str(net_connect.send_command('show running-config'))
access_ports, trunk_target_ports = classify_switchports(running_config)
native_vlan_id = netauto.load_native_vlan()

native_vlan_commands = [f'vlan {native_vlan_id}', 'name NATIVE', 'exit'] if native_vlan_id else []

access_interface_commands = []
for name in access_ports:
    access_interface_commands.append(f'interface {name}')
    access_interface_commands += ACCESS_PORT_FIXES

interface_commands = []
for name in trunk_target_ports:
    interface_commands.append(f'interface {name}')
    interface_commands.append('switchport mode trunk')
    if allowed_trunk_vlans:
        interface_commands.append(f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)}')
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
if access_ports:
    applied_fixes['V-220683/685/687 (UUFB/IP Source Guard/storm control)'] = (
        f'{"; ".join(ACCESS_PORT_FIXES)} (on {len(access_ports)} access port(s): {", ".join(access_ports)})'
    )
if trunk_target_ports and native_vlan_id:
    applied_fixes['V-220695 (native VLAN)'] = (
        f'switchport mode trunk; switchport trunk native vlan {native_vlan_id} '
        f'(on {len(trunk_target_ports)} non-access port(s): {", ".join(trunk_target_ports)})'
    )
if trunk_target_ports and allowed_trunk_vlans:
    applied_fixes['V-220692 (trunk VLAN pruning)'] = (
        f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)} '
        f'(on {len(trunk_target_ports)} trunk port(s))'
    )
if vlan_ids:
    applied_fixes['V-220684 (DHCP snooping)'] = f'feature dhcp; ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}'
    applied_fixes['V-220686 (DAI)'] = f'ip arp inspection vlan {",".join(vlan_ids)}'
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
    commands += [
        'feature dhcp', 'ip dhcp snooping', f'ip dhcp snooping vlan {",".join(vlan_ids)}',
        f'ip arp inspection vlan {",".join(vlan_ids)}',  # V-220686 (DAI) - same VLAN set as DHCP snooping
    ]
commands += native_vlan_commands + access_interface_commands + interface_commands
if vtp_password and vtp_domain:
    # Domain must be set before the password takes effect - confirmed live
    # on NXCore1 ('vtp password ...' fails with "Domain not set" otherwise.
    # Transparent mode also means this switch won't originate/relay VLAN
    # database changes to peers (same reasoning L2_stig_harden.py uses).
    commands += ['feature vtp', f'vtp domain {vtp_domain}', 'vtp mode transparent', f'vtp password {vtp_password}']
commands += ntp_commands

# Push the hardening commands and close the session. read_timeout raised
# well above Netmiko's default - confirmed live that this device's per-port
# trunk conversion (V-220695, potentially dozens of unused ports on a core
# switch) takes long enough that the default caused a ReadTimeout mid-batch,
# aborting the script before most of the interface loop had even run.
output = net_connect.send_config_set(commands, read_timeout=180)
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

if not access_ports:
    print('\nNo access switchports found (explicit `switchport access vlan <n>`) — nothing to push for V-220683/685/687.')
if not native_vlan_id:
    print('\nSkipped V-220695 (native VLAN) — add native_vlan to inventory.yaml to include it.')
elif not trunk_target_ports:
    print(f'\nNo non-access switchports found — every port already has an explicit `switchport access vlan <n>` line, nothing to push for V-220695/692.')
if trunk_target_ports and not allowed_trunk_vlans:
    print('\nSkipped V-220692 (trunk VLAN pruning) — no VLANs discovered in the VLAN database besides VLAN 1/unused_vlan.')
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
