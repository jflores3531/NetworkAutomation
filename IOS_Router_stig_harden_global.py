#!/usr/bin/env python
"""Push the global (non-interface-specific) hardening fixes from the DISA Cisco
IOS Router RTR STIG to a device. Interface-scoped rules (directed broadcast,
ICMP redirects/unreachables/mask-reply, proxy ARP, LLDP transmit) need to be
applied per-interface and are intentionally left out of this pass.

AAA/RADIUS + password complexity (V-215681-686/709) and the vty management
ACL (V-215667) are pushed by separate scripts (IOS_Router_stig_harden_aaa.py,
IOS_Router_stig_harden_acl.py) - both are the highest lockout-risk pushes in
this project (see their own docstrings), kept isolated the same way L2S
splits L2_stig_harden_aaa.py/L2_stig_harden_acl.py out of L2_stig_harden_global.py."""

import argparse
import netauto

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    'V-216563 (Gratuitous ARPs)': 'no ip gratuitous-arps',
    'V-216585 (CDP)': 'no cdp run',
    'V-229030 (CEF)': 'ip cef',
    'V-215672 (log timestamps)': 'service timestamps log datetime localtime',
    'V-215691 (logging buffer size)': 'logging buffered 64000 informational',
    'V-215692 (audit failure alert)': 'logging trap critical',
    'V-215670a (admin activity logging: privilege escalation)': 'logging userinfo',
    'V-215704a (log on-failure)': 'login on-failure log',
    'V-215704b (log on-success)': 'login on-success log',
    'V-215668 (lockout after 3 failed attempts)': 'login block-for 900 attempts 3 within 120',
    # Not confirmed to be valid syntax on this lab's IOSv image without a base
    # MPLS feature-set active - included per the check text's literal presence
    # requirement (no "not applicable if MPLS unused" language, unlike the
    # BGP/OSPF/MPLS-TE-gated rules IOS_Router_audit.py reports NOT APPLICABLE
    # for). If rejected live, harmless - doesn't touch AAA/access.
    'V-216610 (MPLS TTL propagation)': 'no mpls ip propagate-ttl',
    'V-216993 (drop IP options)': 'ip options drop',
}

# V-216571 (AUX port disabled) needs two lines under "line aux 0", so it's
# handled separately from the single-command BASE_FIXES
AUX_PORT_FIX = ['line aux 0', 'no exec']

# V-215688: exec-timeout on console and vty, plus the HTTP timeout-policy the
# check text's own example lists alongside them. Pushed unconditionally like
# CONSOLE_EXEC_TIMEOUT_FIX/VTY_SESSION_LIMIT_FIX are in the L2S/NX-OS harden
# scripts - `ip http timeout-policy` is a no-op if the HTTP server is never
# enabled.
CONSOLE_EXEC_TIMEOUT_FIX = ['line con 0', 'exec-timeout 5 0']
VTY_EXEC_TIMEOUT_FIX = ['line vty 0 4', 'exec-timeout 5 0']
HTTP_TIMEOUT_FIX = ['ip http timeout-policy idle 300 life 180 requests 1']

# V-215662: concurrent session limit, same "line vty 0 4" context and value
# (5) as L2S's VTY_SESSION_LIMIT_FIX for consistency across the project -
# DISA's own check/fix text example uses 2, but leaves the actual number
# organization-defined.
VTY_SESSION_LIMIT_FIX = ['line vty 0 4', 'session-limit 5']

# V-215670b: the second half of V-215670's evidence requirement (checked by
# IOS_Router_audit.py's _admin_activity_logged as one combined rule with
# 'logging userinfo' above - both must be present together). Same archive
# block as L2S's ARCHIVE_LOGGING_FIX.
ARCHIVE_LOGGING_FIX = [
    'archive',
    'log config',
    'logging enable',
    'logging size 1000',
    'notify syslog contenttype plaintext',
    'hidekeys',
]

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

# NTP server IPs (V-215693) and syslog server IPs (V-220136) come from
# inventory.yaml's services section. NTP authentication key (V-215698) comes
# from secrets.yaml (gitignored, never committed - see secrets.yaml.example).
services = netauto.load_services()
ntp_servers = services.get('ntp_servers', [])
syslog_servers = services.get('syslog_servers', [])
ntp_auth_key = netauto.load_secrets().get('ntp_auth_key') or {}
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

applied_fixes = dict(BASE_FIXES)
applied_fixes['V-216571 (AUX port disabled)'] = '; '.join(AUX_PORT_FIX)
applied_fixes['V-215688 (exec-timeout)'] = '; '.join(CONSOLE_EXEC_TIMEOUT_FIX + VTY_EXEC_TIMEOUT_FIX + HTTP_TIMEOUT_FIX)
applied_fixes['V-215662 (session limit)'] = '; '.join(VTY_SESSION_LIMIT_FIX)
applied_fixes['V-215670b (admin activity logging: archive)'] = '; '.join(ARCHIVE_LOGGING_FIX)
if ntp_servers:
    applied_fixes['V-215693 (NTP time sync)'] = '; '.join(
        f'ntp server {ip}' + (f' key {ntp_key_id}' if ntp_key_id else '') for ip in ntp_servers)
if ntp_key_id:
    applied_fixes['V-215698 (NTP authentication)'] = '; '.join([
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}', 'ntp authenticate', f'ntp trusted-key {ntp_key_id}'])
if syslog_servers:
    applied_fixes['V-220136 (dual syslog servers)'] = '; '.join(f'logging host {ip}' for ip in syslog_servers)

commands = (
    list(BASE_FIXES.values()) + AUX_PORT_FIX + CONSOLE_EXEC_TIMEOUT_FIX + VTY_EXEC_TIMEOUT_FIX
    + HTTP_TIMEOUT_FIX + VTY_SESSION_LIMIT_FIX + ARCHIVE_LOGGING_FIX + ntp_commands
    + [f'logging host {ip}' for ip in syslog_servers]
)

# Push the hardening commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('IOS_Router_stig_harden_global.py', device_name, username, commands)

print(f'Hardening commands pushed to {device_name}:')
for command in commands:
    print('  ' + command)
print()
print(output)

print(f'\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not ntp_servers:
    print('\nSkipped V-215693 (NTP time sync) — add ntp_servers to inventory.yaml\'s services section to include it.')
if not ntp_key_id:
    print('\nSkipped V-215698 (NTP authentication) — add ntp_auth_key to secrets.yaml to include it.')
if not syslog_servers:
    print('\nSkipped V-220136 (dual syslog servers) — add syslog_servers to inventory.yaml\'s services section to include it.')

print('\nRules requiring interface targeting (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)

print('\nV-215667 (vty management ACL) is pushed separately by IOS_Router_stig_harden_acl.py.')
print('V-215681-686/709 (AAA new-model + RADIUS auth + password complexity) is pushed separately by IOS_Router_stig_harden_aaa.py.')
