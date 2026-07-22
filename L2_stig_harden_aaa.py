#!/usr/bin/env python
"""Push aaa new-model + RADIUS auth (V-220587: single local account with an
AAA fallback line, V-220617: RADIUS as primary auth source) to a device, kept
separate from L2_stig_harden.py's ~60-command batch on purpose. Pushing this
alongside everything else caused a live session on S2 to drop right after
'aaa new-model' took effect, before the rest of the block (radius-server
host, aaa authentication login, aaa authorization exec) could send - leaving
the device half-configured and SSH-inaccessible (recovered via console +
'no aaa new-model').

Before touching aaa new-model at all, this script pushes the enable secret
on its own and verifies it actually works: drop to user EXEC with 'disable',
then escalate back with Netmiko's enable() (which uses the same secret), and
confirm privileged EXEC was reached. If that round-trip fails for any
reason, it aborts without pushing anything AAA-related - a bad or missing
enable secret can never again leave a device stuck the way S2/S3 did."""

import argparse
import netauto

# Parse the target device from the command line
parser = argparse.ArgumentParser(
    description='Push aaa new-model + RADIUS auth to a device from inventory.yaml/secrets.yaml (V-220587/617)'
)
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# RADIUS server IPs come from inventory.yaml's services section, the shared
# secret and enable secret from secrets.yaml (never hardcoded/prompted via
# CLI flag). This script requires all three up front and refuses to do
# anything if they're missing - unlike L2_stig_harden.py's "skip and
# continue" pattern, there's no safe partial version of this push.
secrets = netauto.load_secrets()
services = netauto.load_services()
enable_secret = str(secrets.get('enable_secret') or '').strip()
radius_key = str(secrets.get('radius_key') or '').strip()
radius_servers = services.get('radius_servers', [])

if not enable_secret:
    print('Aborting: no enable_secret in secrets.yaml. Set one first - it is the only way back into '
          'privileged EXEC once aaa new-model is active, and this script verifies it works before using it.')
    raise SystemExit(1)
if not radius_servers or not radius_key:
    print('Aborting: radius_servers (inventory.yaml services section) and radius_key (secrets.yaml) are both required.')
    raise SystemExit(1)
if len(radius_servers) < 2:
    print(f'Warning: only {len(radius_servers)} RADIUS server(s) configured - V-220617 wants 2+. Continuing anyway.')

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Push the enable secret on its own first (idempotent if already set).
enable_secret_command = [f'enable secret {enable_secret}']
net_connect.send_config_set(enable_secret_command)
netauto.log_push('L2_stig_harden_aaa.py', device_name, username, enable_secret_command)

# Verify it actually works before going anywhere near aaa new-model: drop to
# user EXEC, then escalate back using the same secret Netmiko already has
# from netauto.connect(). check_enable_mode() reflects the real prompt, not
# just whether enable() raised - IOS can accept 'enable' and still leave you
# at user EXEC in some failure modes.
#
# exit_enable_mode() (not a raw send_command('disable')) - send_command()
# waits for Netmiko's already-cached 'S3#'-style prompt to reappear, which
# never happens once 'disable' changes it to 'S3>', causing a hang and a
# ReadTimeout crash. exit_enable_mode() knows to expect the new prompt.
net_connect.exit_enable_mode()
net_connect.enable()
if not net_connect.check_enable_mode():
    print(f'ABORT: enable secret verification failed on {device_name} - not back at privileged EXEC after '
          'disable -> enable. Not touching aaa new-model. Investigate via console before retrying.')
    net_connect.disconnect()
    raise SystemExit(1)

print(f'Enable secret verified working on {device_name} (disable -> enable round-trip succeeded).')

# Verified - now safe to push aaa new-model + RADIUS. 'local' stays last in
# both method lists as a fallback, same as the account this script is
# connected with.
#
# Modern block-style 'radius server <name>' / 'address ipv4 ...' / 'key ...',
# not the classic single-line 'radius-server host <ip> key <string>' -
# confirmed live that this platform rejects the classic form ("radius-server
# host" -> "% Invalid input" right at 'host'; 'radius server ?' accepts a
# name). The built-in "group radius" referenced by the aaa authentication/
# authorization lines below picks up servers defined either way.
aaa_commands = ['aaa new-model']
for i, ip in enumerate(radius_servers, start=1):
    aaa_commands += [
        f'radius server RADIUS{i}',
        f'address ipv4 {ip} auth-port 1812 acct-port 1813',
        f'key {radius_key}',
        'exit',
    ]
aaa_commands += [
    'aaa authentication login default group radius local',
    'aaa authorization exec default group radius local',
]

output = net_connect.send_config_set(aaa_commands)
net_connect.disconnect()
netauto.log_push('L2_stig_harden_aaa.py', device_name, username, aaa_commands)

print(f'\nAAA/RADIUS commands pushed to {device_name}:')
for command in aaa_commands:
    print('  ' + command)
print()
print(output)

print('\nRules addressed by this pass:')
print('  - V-220587 (single local account with AAA fallback)')
print('  - V-220617 (RADIUS as primary auth source)')
