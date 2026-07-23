#!/usr/bin/env python
"""Push the global and interface-scoped hardening fixes from the DISA Cisco IOS
Switch L2S STIG to a device. Interface-scoped rules classify each switchport as
host-facing/access or trunk/uplink based on whether "switchport mode trunk" is
present, then push the matching fixes to each. V-220642 (no default VLAN on
host-facing ports) and V-220645 (user-facing ports must be access) don't get a
dedicated command - they're satisfied as a side effect of the explicit
'switchport mode access' + 'switchport access vlan <default_access_vlan>'
push every access port already gets (see the comment above L2_stig_audit.py's
CHECKS dict for how the audit verifies this now that both are explicit).
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
the global 'spanning-tree portfast bpduguard default' fix only activates
BPDU Guard on ports that have PortFast enabled, so without this the global
command was present but functionally inert everywhere (a false PASS).
V-220623 (802.1x/MAB): the global prerequisites ('dot1x system-auth-control',
'aaa authentication dot1x default group radius') are pushed by
L2_stig_harden_aaa.py instead, not here - the latter needs aaa new-model
already active, which this script doesn't push (see that script's own
docstring for why). Only the per-port commands (authentication
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
    'V-220595a (password encryption)': 'service password-encryption',
    'V-220600 (audit failure alert)': 'logging trap critical',
    # Confirmed live that this lab's vios_l2 rejects 'file privilege 15'
    # ("% Invalid input") - same category as UUFB/storm-control/mls
    # qos/security passwords min-length, kept for real hardware. Doesn't
    # affect the audit result here since V-220583/584/585 are conditional on
    # `logging persistent` (not pushed anywhere), which isn't configured.
    'V-220583/584/585 (file privilege 15)': 'file privilege 15',
}

# Not a STIG requirement - pushed for host visibility only. ARP-probes every
# L2 port and populates 'show ip device tracking all' with each host's
# IP/MAC/VLAN/interface, static or DHCP-assigned alike (unlike IP Source Guard,
# it doesn't rely on the DHCP snooping binding table).
OPTIONAL_FIXES = {
    'IP Device Tracking (host visibility, not a STIG requirement)': 'ip device tracking',
}

# V-220570: session-limit needs its own "line vty 0 4" context. DISA's rule is
# "organization-defined number," not a fixed value - 5 concurrent sessions.
# V-220596: exec-timeout must be nonzero and <=5 min (stig_common.exec_timeout_ok) -
# "0 0" disables the timeout entirely, which is non-compliant, not exempt from it.
VTY_SESSION_LIMIT_FIX = ['line vty 0 4', 'session-limit 5', 'exec-timeout 5 0']

# V-220596 also requires the console line, not just vty (DISA's Fix Text
# configures both) - previously only vty was ever set, so the console line
# sat at IOS's un-set default (10 min, non-compliant) indefinitely.
CONSOLE_EXEC_TIMEOUT_FIX = ['line con 0', 'exec-timeout 5 0']

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

# Rules satisfied as a side effect of the access-port mode/VLAN push, not by
# a dedicated command of their own (see module docstring)
SIDE_EFFECT_RULES = [
    'V-220642 (no default VLAN on host ports)',
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

# SNMPv3 auth/priv passwords (V-220604/605) come from secrets.yaml. Config-only
# push - no SNMP monitoring station in this lab to actually poll it, this is
# purely to satisfy the audit. SHA for auth (FIPS-validated HMAC, V-220604) and
# AES for priv (FIPS 140-2 approved, V-220605) - "v3 priv" implies auth too, so
# one group/user satisfies both rules.
SNMPV3_GROUP = 'SNMPV3_GROUP'
SNMPV3_USER = 'SNMPV3_USER'
snmpv3 = secrets.get('snmpv3') or {}
snmp_auth_password = str(snmpv3.get('auth_password') or '').strip()
snmp_priv_password = str(snmpv3.get('priv_password') or '').strip()

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

# Create the native/unused VLAN in the VLAN database itself, named NATIVE.
# Referencing it on interfaces (switchport trunk native vlan / switchport
# access vlan) doesn't create a VLAN database entry by itself, so without
# this it never shows up in `show vlan brief`. Must explicitly 'exit' the
# 'vlan <id>' sub-mode, not just leave it hanging - the interface commands
# built below assume global config context, and Netmiko sends this whole
# list as one flat sequence.
#
# Not a STIG requirement, but pushed first: in VTP server mode (the Cisco
# default), VLAN database entries live in a separate vlan.dat file on flash,
# not in the running-config/startup-config text - confirmed live that VLAN
# 999/NATIVE never once appeared in `show running-config` even right after
# being pushed, and was lost entirely on a reload of S3 despite `copy
# running-config startup-config` (which never saves vlan.dat). 'vtp mode
# transparent' makes VLAN config part of the regular running-config instead,
# so it saves/persists the normal way - also has the effect of disabling
# VTP's own database-synchronization behavior between switches.
native_vlan_commands = ['vtp mode transparent', f'vlan {native_vlan_id}', 'name NATIVE', 'exit'] if native_vlan_id else []

# Default VLAN for host-facing/access ports (comes from inventory.yaml instead
# of a prompt). A freshly built port has no explicit switchport mode/VLAN at
# all, which silently breaks other access-port fixes that require the port to
# already be in access mode first - confirmed live on a fresh S3 in GNS3.
# Every non-trunk port gets 'switchport mode access' + this VLAN explicitly;
# the VLAN itself is created in the database the same way as native_vlan_id
# above (needs 'vtp mode transparent' too, already pushed by native_vlan_commands
# if that ran - if native_vlan_id isn't set this pushes its own copy).
default_access_vlan = netauto.load_default_access_vlan()
access_vlan_commands = []
if default_access_vlan:
    if not native_vlan_commands:
        access_vlan_commands.append('vtp mode transparent')
    access_vlan_commands += [f'vlan {default_access_vlan}', 'name USER', 'exit']
access_fixes = ['switchport mode access']
if default_access_vlan:
    access_fixes.append(f'switchport access vlan {default_access_vlan}')
# V-220630 (BPDU Guard): the global 'spanning-tree portfast bpduguard default'
# fix (in BASE_FIXES) only activates BPDU Guard on ports that have PortFast
# enabled - per the STIG's own Discussion text, BPDU Guard disables "the port
# that has PortFast configured" on BPDU reception. Without this, that global
# command is a no-op everywhere: it was present in the config (audit PASS)
# but never actually protected a single port. PortFast belongs on access/
# host-facing ports only, never trunk/uplinks (a trunk receiving BPDUs is
# normal STP behavior, not a rogue-switch signal).
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

snmpv3_commands = []
if snmp_auth_password and snmp_priv_password:
    snmpv3_commands = [
        f'snmp-server group {SNMPV3_GROUP} v3 priv',
        f'snmp-server user {SNMPV3_USER} {SNMPV3_GROUP} v3 auth sha {snmp_auth_password} priv aes 128 {snmp_priv_password}',
    ]

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

applied_fixes = dict(BASE_FIXES)
applied_fixes.update(OPTIONAL_FIXES)
applied_fixes['V-220586 (unnecessary services)'] = '; '.join(UNNECESSARY_SERVICES_FIX)
applied_fixes['V-220608 (SSH encryption)'] = '; '.join(SSH_ENCRYPTION_FIX)
applied_fixes['V-220571/572/573/574/582/597/611/613 (archive logging)'] = '; '.join(ARCHIVE_LOGGING_FIX)
applied_fixes['V-220570b/596 (VTY session limit + exec-timeout)'] = '; '.join(VTY_SESSION_LIMIT_FIX)
applied_fixes['V-220596b (console exec-timeout)'] = '; '.join(CONSOLE_EXEC_TIMEOUT_FIX)
if vlan_ids:
    applied_fixes['V-220633 (DHCP snooping)'] = (
        f'ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}; no ip dhcp snooping information option'
    )
if vtp_password:
    applied_fixes['V-220624 (VTP authentication)'] = f'vtp password {vtp_password}'
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
if native_vlan_commands:
    applied_fixes['Native/unused VLAN database entry'] = '; '.join(native_vlan_commands)
if access_vlan_commands:
    applied_fixes['Default access VLAN database entry'] = '; '.join(access_vlan_commands)
if snmpv3_commands:
    applied_fixes['V-220604/605 (SNMPv3 auth/priv)'] = f'snmp-server group {SNMPV3_GROUP} v3 priv; snmp-server user {SNMPV3_USER} ... v3 auth sha ... priv aes 128 ...'
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

commands = list(BASE_FIXES.values()) + list(OPTIONAL_FIXES.values()) + UNNECESSARY_SERVICES_FIX + SSH_ENCRYPTION_FIX + ARCHIVE_LOGGING_FIX + VTY_SESSION_LIMIT_FIX + CONSOLE_EXEC_TIMEOUT_FIX
if vlan_ids:
    # `information option` (Option 82 relay-agent info insertion) is on by
    # default once DHCP snooping is enabled - turned off here since some DHCP
    # servers/relays reject or mishandle it, and V-220633 doesn't require it.
    commands += [
        'ip dhcp snooping',
        f'ip dhcp snooping vlan {",".join(vlan_ids)}',
        'no ip dhcp snooping information option',
    ]
# Order here doesn't functionally matter for vtp password - turned out V-220624
# was a false FAIL all along (VTP passwords are deliberately excluded from
# `show running-config` on Cisco IOS, confirmed live via `show vtp password`
# showing it set correctly regardless of push order - see L2_stig_audit.py's
# _vtp_password_check). Keeping native_vlan_commands first anyway since it's
# still the more sensible order (mode/VLAN setup before other global config).
commands += native_vlan_commands
if vtp_password:
    commands.append(f'vtp password {vtp_password}')
commands += access_vlan_commands
commands += snmpv3_commands
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
if not (snmp_auth_password and snmp_priv_password):
    print('\nSkipped V-220604/605 (SNMPv3 auth/priv) — add snmpv3.auth_password and snmpv3.priv_password to secrets.yaml to include it.')
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

print('\nV-220634 (IP Source Guard) is pushed separately by L2_stig_harden_ipsg.py.')
print('V-220635 (DAI) is pushed separately by L2_stig_harden_dai.py.')
print('V-220587/617 (AAA new-model + RADIUS auth) is pushed separately by L2_stig_harden_aaa.py.')
print('V-220623a/b (dot1x system-auth-control + AAA method) is pushed separately by L2_stig_harden_aaa.py, '
      'after aaa new-model is confirmed active - only the per-port V-220623 commands above are pushed here.')

print('\nRules satisfied as a side effect of the access-port mode/VLAN push above, not by a dedicated command:')
for rule in SIDE_EFFECT_RULES:
    print('  - ' + rule)
