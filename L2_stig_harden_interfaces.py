#!/usr/bin/env python
"""Push the interface-scoped hardening fixes from the DISA Cisco IOS Switch
L2S STIG to a device - split out of L2_stig_harden_global.py so global fixes and
per-port fixes can be run/reviewed independently, same pattern as
L2_stig_harden_dai.py/NXOS_stig_harden_interfaces.py. Classifies each
switchport as host-facing/access or trunk/uplink based on whether
"switchport mode trunk" is present, then pushes the matching fixes to each.

Run L2_stig_harden_global.py first: it creates the native/unused/default-access
VLANs in the database (referenced here but not created here) and enables
DHCP snooping globally (V-220633) - 'ip dhcp snooping trust'/'ip arp
inspection trust' below are inert until that's active, same as any
per-interface config for a globally-disabled feature.

V-220642 (no default VLAN on host-facing ports) and V-220645 (user-facing
ports must be access) don't get a dedicated command - they're satisfied as
a side effect of the explicit 'switchport mode access' + 'switchport
access vlan <default_access_vlan>' push every access port already gets
(see the comment above L2_stig_audit.py's CHECKS dict for how the audit
verifies this now that both are explicit).
V-220634 (IP Source Guard) is pushed separately by L2_stig_harden_ipsg.py,
and V-220635 (DAI) separately by L2_stig_harden_dai.py - both split out
because they only trust the DHCP snooping binding table, so a statically-
addressed host with no DHCP lease gets its traffic dropped once either is
pushed (see the static-host-binding gap tracked in project memory).
V-220632 (UUFB) and V-220636 (storm control) are still pushed here for
real hardware, even though confirmed live that neither command exists/
functions on the lab's vios_l2 switches - they're silently rejected
there, not removed from the script. V-220636's threshold is scaled by
port speed and skipped entirely on FastEthernet interfaces (see
storm_control_command()) - DISA's own Fix Text notes storm control isn't
supported on most FastEthernet ports, and a single flat threshold would
either violate or fail on ports well outside Gigabit speed.
V-220630 (BPDU Guard) pushes 'spanning-tree portfast' to every access port -
the global 'spanning-tree portfast bpduguard default' fix (in
L2_stig_harden_global.py) only activates BPDU Guard on ports that have PortFast
enabled, so without this the global command was present but functionally
inert everywhere (a false PASS).
V-220623 (802.1x/MAB): the global prerequisites ('dot1x system-auth-control',
'aaa authentication dot1x default group radius') are pushed by
L2_stig_harden_aaa.py instead, not here - the latter needs aaa new-model
already active, which neither this nor L2_stig_harden_global.py pushes (see that
script's own docstring for why). Only the per-port commands (authentication
port-control auto / dot1x pae authenticator / mab, in access_fixes below)
are pushed here; they're inert until the global prerequisites are active,
same as any config for a globally-disabled feature."""

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


def storm_control_command(interface_name):
    """V-220636: DISA's own Fix Text notes storm control isn't supported on
    most FastEthernet interfaces - those are skipped entirely rather than
    given a threshold that would likely just be rejected. The bps threshold
    is scaled to DISA's allowed range by port speed (Gigabit: 10M-1G bps,
    10-Gigabit: 100M-10G bps), both kept at ~2% of link speed. Port-channel/
    plain Ethernet interfaces default to the Gigabit-range value - their
    actual bundled/negotiated speed isn't visible from the interface name
    alone."""
    if interface_name.startswith('FastEthernet'):
        return None
    if interface_name.startswith('TenGigabitEthernet'):
        return 'storm-control broadcast level bps 200000000'
    return 'storm-control broadcast level bps 20000000'


def shutdown_access_ports(cfg, access_names):
    """Return the subset of access_names whose interface block has 'shutdown' —
    used by V-220641 to reassign only ports that are already disabled."""
    shutdown = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if m and m.group(1) in access_names and re.search(r'^\s*shutdown\s*$', chunk, re.M):
            shutdown.append(m.group(1))
    return shutdown


# Pushed to every trunk/uplink-classified interface (allowed-vlan list, native VLAN
# line, added separately below once the device's actual VLAN database is known)
TRUNK_PORT_FIXES = [
    'switchport nonegotiate',  # V-220640 (static trunk, no DTP negotiation)
    # DHCP snooping (V-220633) makes every port untrusted by default - an
    # untrusted port drops any DHCPOFFER/DHCPACK outright, so without this the
    # trunk port(s) toward wherever the real DHCP server lives would silently
    # break DHCP for every client behind this switch. Every trunk-classified
    # port gets trusted, consistent with this repo's existing trunk = switch-
    # to-switch uplink model (not a mix of trusted-upstream/untrusted-peer
    # trunks).
    'ip dhcp snooping trust',
    # DAI (V-220635) trust is a separate setting from DHCP snooping trust above
    # - defaults to untrusted even on a DHCP-snooping-trusted port. DHCP
    # snooping bindings are learned per-switch only, from DORA exchanges seen
    # locally, never synced between switches. Without this, DAI on a trunk
    # port validates transit ARP traffic from hosts behind other switches
    # against this switch's own (often empty) binding table and drops it -
    # confirmed live: S1 dropped ARP traffic for a host bound only on S3's
    # local table (%SW_DAI-4-DHCP_SNOOPING_DENY on a trunk port, 0 local
    # bindings on S1). Trusting trunk/uplink ports for DAI too keeps
    # inspection scoped to actual access ports, where the local binding table
    # is authoritative.
    'ip arp inspection trust',
]

# Rules satisfied as a side effect of the access-port mode/VLAN push, not by
# a dedicated command of their own (see module docstring)
SIDE_EFFECT_RULES = [
    'V-220642 (no default VLAN on host ports)',
    'V-220645 (user-facing ports as access)',
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push interface-scoped L2S STIG hardening fixes to a device from inventory.yaml')
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

# V-220629: STP root port(s), live - Root Guard must never be pushed there (see
# stig_common.discover_root_port_interfaces for why: it forces the port into
# root-inconsistent/blocking state, a real outage risk).
root_ports = stig_common.discover_root_port_interfaces(net_connect)

# Classify switchports (host-facing/access vs. trunk/uplink) for the interface-scoped fixes
running_config = str(net_connect.send_command('show running-config'))
access_ports, trunk_ports = parse_switchports(running_config)
root_guard_ports = [name for name in trunk_ports if name not in root_ports]

# V-220641: already-shutdown access ports get reassigned to the designated
# unused VLAN (safe - they're not passing traffic). The VLAN's own database
# entry is created by L2_stig_harden_global.py, not here.
unused_vlan = netauto.load_unused_vlan()
disabled_ports = shutdown_access_ports(running_config, access_ports) if unused_vlan else []

# Native VLAN for trunk ports (V-220646) comes from inventory.yaml instead of a
# prompt. Its own database entry is created by L2_stig_harden_global.py, not here.
native_vlan_id = netauto.load_native_vlan()

# V-220643/641: trunks should carry only VLANs that actually exist in the switch's
# VLAN database, minus the default VLAN (1), the designated unused VLAN, and the
# native VLAN - not just "everything except 1/999", which would still leave every
# undefined VLAN ID allowed too. An explicit list also sidesteps the except/remove
# semantics entirely (no risk of clobbering a pre-existing restriction on first
# run). native_vlan_id is a genuinely separate exclusion from unused_vlan - they
# used to be the same ID by convention, so excluding unused_vlan implicitly
# excluded native_vlan too; now that they're deliberately different VLANs (see
# inventory.yaml), both need to be named explicitly or native_vlan_id would get
# swept into the discovered allowed-list once it exists in the VLAN database.
trunk_vlan_exclude = [1] + ([unused_vlan] if unused_vlan else []) + ([native_vlan_id] if native_vlan_id else [])
allowed_trunk_vlans = stig_common.discover_user_vlans(net_connect, exclude=trunk_vlan_exclude)

# Default VLAN for host-facing/access ports (comes from inventory.yaml instead
# of a prompt). A freshly built port has no explicit switchport mode/VLAN at
# all, which silently breaks other access-port fixes that require the port to
# already be in access mode first - confirmed live on a fresh S3 in GNS3.
# Every non-trunk port gets 'switchport mode access' + this VLAN explicitly;
# the VLAN's own database entry is created by L2_stig_harden_global.py, not here.
default_access_vlan = netauto.load_default_access_vlan()

access_fixes = ['switchport mode access']
if default_access_vlan:
    access_fixes.append(f'switchport access vlan {default_access_vlan}')
# V-220630 (BPDU Guard): the global 'spanning-tree portfast bpduguard default'
# fix (in L2_stig_harden_global.py) only activates BPDU Guard on ports that have
# PortFast enabled - per the STIG's own Discussion text, BPDU Guard disables
# "the port that has PortFast configured" on BPDU reception. Without this,
# that global command is a no-op everywhere: it was present in the config
# (audit PASS) but never actually protected a single port. PortFast belongs
# on access/host-facing ports only, never trunk/uplinks (a trunk receiving
# BPDUs is normal STP behavior, not a rogue-switch signal).
access_fixes.append('spanning-tree portfast')
# Kept for real hardware even though confirmed live that neither command
# exists on these lab vios_l2 switches ("% Invalid input") - Jorge wants them
# available for a real deployment, not removed just because the lab can't run
# them. Netmiko doesn't treat a rejected command as fatal, so pushing these
# against vios_l2 is harmless (silently skipped), not a crash risk.
access_fixes += [
    'switchport block unicast',                     # V-220632 (UUFB)
    'authentication port-control auto',              # V-220623 (802.1x/MAB)
    'dot1x pae authenticator',                        # V-220623 (802.1x/MAB)
    'mab',                                            # V-220623 (802.1x/MAB)
]
# V-220636 (storm control) is pushed per-port, not in the flat access_fixes
# list above - the threshold varies by port speed, and FastEthernet ports
# are skipped entirely (see storm_control_command()).
storm_control_ports = {name: cmd for name in access_ports if (cmd := storm_control_command(name))}

# Build the per-interface command blocks now that ports are classified
trunk_fixes = list(TRUNK_PORT_FIXES)
if allowed_trunk_vlans:
    trunk_fixes.append(f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)}')
if native_vlan_id:
    trunk_fixes.append(f'switchport trunk native vlan {native_vlan_id}')

interface_commands = []
for name in access_ports:
    interface_commands.append(f'interface {name}')
    interface_commands += access_fixes
    if name in storm_control_ports:
        interface_commands.append(storm_control_ports[name])
for name in trunk_ports:
    interface_commands.append(f'interface {name}')
    interface_commands += trunk_fixes
    if name in root_guard_ports:
        interface_commands.append('spanning-tree guard root')
for name in disabled_ports:
    interface_commands.append(f'interface {name}')
    interface_commands.append(f'switchport access vlan {unused_vlan}')

applied_fixes = {}
if access_ports:
    applied_fixes['Default access mode/VLAN'] = (
        f'switchport mode access' + (f'; switchport access vlan {default_access_vlan}' if default_access_vlan else '')
        + f' (on {len(access_ports)} access port(s))'
    )
    applied_fixes['V-220630b (PortFast, required for BPDU Guard to activate)'] = f'spanning-tree portfast (on {len(access_ports)} access port(s))'
    applied_fixes['V-220632 (UUFB)'] = f'switchport block unicast (on {len(access_ports)} access port(s) - not supported on lab vios_l2, kept for real hardware)'
    if storm_control_ports:
        applied_fixes['V-220636 (storm control)'] = (
            f'storm-control broadcast level bps ... (speed-scaled, on {len(storm_control_ports)} of {len(access_ports)} '
            f'access port(s) - not supported on lab vios_l2, kept for real hardware)'
        )
    applied_fixes['V-220623 (802.1x/MAB)'] = f'authentication port-control auto; dot1x pae authenticator; mab (on {len(access_ports)} access port(s) - not supported on lab vios_l2, kept for real hardware)'
if trunk_ports:
    applied_fixes['V-220640 (static trunk)'] = f'switchport nonegotiate (on {len(trunk_ports)} trunk port(s))'
    applied_fixes['V-220633b/635b (DHCP snooping + DAI trust)'] = f'ip dhcp snooping trust; ip arp inspection trust (on {len(trunk_ports)} trunk port(s))'
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

commands = interface_commands

# Push the interface commands and close the session
output = net_connect.send_config_set(commands) if commands else ''
net_connect.disconnect()
netauto.log_push('L2_stig_harden_interfaces.py', device_name, username, commands)

if commands:
    print(f'Interface hardening commands pushed to {device_name}:')
    for command in commands:
        print('  ' + command)
    print()
    print(output)

print('\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not access_ports:
    print('\nNo access/host-facing switchports found — nothing to push for V-220632/634/636.')
elif not storm_control_ports:
    print('\nSkipped V-220636 (storm control) — every access port is FastEthernet, not supported per the STIG\'s own Fix Text note.')
if not trunk_ports:
    print('\nNo trunk switchports found — nothing to push for V-220629/640/643/646.')
elif not root_guard_ports:
    print('\nSkipped V-220629 (Root Guard) — every trunk port is this switch\'s STP root port toward the root bridge; Root Guard must not be applied there.')
if trunk_ports and not allowed_trunk_vlans:
    print('\nSkipped V-220643/641b (trunk VLAN scoping) — no VLANs discovered in the VLAN database besides VLAN 1/unused_vlan.')
if trunk_ports and not native_vlan_id:
    print('\nSkipped V-220646 (native VLAN) — add native_vlan to inventory.yaml to include it.')
if access_ports and not default_access_vlan:
    print('\nSkipped default access VLAN assignment — add default_access_vlan to inventory.yaml to include it. Access ports will still get switchport mode access, just no explicit VLAN.')
if not unused_vlan:
    print('\nSkipped V-220641 (unused VLAN) — add unused_vlan to inventory.yaml to include it.')
elif not disabled_ports:
    print('\nNo disabled (shutdown) access ports found — nothing to reassign for V-220641.')

print('\nV-220634 (IP Source Guard) is pushed separately by L2_stig_harden_ipsg.py.')
print('V-220635 (DAI) is pushed separately by L2_stig_harden_dai.py.')
print('V-220623a/b (dot1x system-auth-control + AAA method) is pushed separately by L2_stig_harden_aaa.py, '
      'after aaa new-model is confirmed active - only the per-port V-220623 commands above are pushed here.')

print('\nRules satisfied as a side effect of the access-port mode/VLAN push above, not by a dedicated command:')
for rule in SIDE_EFFECT_RULES:
    print('  - ' + rule)
