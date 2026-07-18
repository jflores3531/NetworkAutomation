#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco NX-OS Switch L2S/NDM
STIG rules in New NXOS Checklist.cklb, reporting PASS/FAIL for the rules that
can be checked from config text alone."""

import argparse
import json
import re
import netauto

CHECKLIST_PATH = 'New NXOS Checklist.cklb'
SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}

# Regex/keyword checks for rules that can be verified directly from running-config
# text. Rules with no entry here need external infrastructure (RADIUS, syslog,
# NTP, PKI) or manual/topology review, and are reported as NOT AUTOMATED.
CHECKS = {
    # --- L2S (Layer 2 Switch) ---
    'V-220676': lambda cfg: bool(re.search(r'^vtp password \S+', cfg, re.M)),
    'V-220681': lambda cfg: bool(re.search(r'spanning-tree port type edge bpduguard default|spanning-tree bpduguard enable', cfg)),
    'V-220682': lambda cfg: 'spanning-tree loopguard default' in cfg,
    'V-220683': lambda cfg: bool(re.search(r'switchport block unicast', cfg)),
    'V-220684': lambda cfg: 'feature dhcp' in cfg and bool(re.search(r'^ip dhcp snooping$', cfg, re.M)) and bool(re.search(r'ip dhcp snooping vlan', cfg)),
    'V-220685': lambda cfg: bool(re.search(r'ip verify source dhcp-snooping-vlan', cfg)),
    'V-220686': lambda cfg: bool(re.search(r'ip arp inspection vlan', cfg)),
    'V-220687': lambda cfg: bool(re.search(r'storm-control (broadcast|multicast|unicast) level', cfg)),
    'V-220688': lambda cfg: 'no ip igmp snooping' not in cfg,
    'V-220689': lambda cfg: 'feature udld' in cfg and bool(re.search(r'udld (enable|aggressive)', cfg)),
    'V-220691': lambda cfg: not bool(re.search(r'switchport access vlan 1\b', cfg)),
    'V-220692': lambda cfg: bool(re.search(r'switchport trunk allowed vlan (?!.*\b1\b)\S+', cfg)),
    'V-220694': lambda cfg: bool(re.search(r'switchport mode access', cfg)),
    'V-220695': lambda cfg: bool(re.search(r'switchport trunk native vlan (?!1\b)\d+', cfg)),

    # --- NDM (Network Device Management) ---
    'V-220481': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-220489': lambda cfg: 'password strength-check' in cfg,
    'V-220490': lambda cfg: 'password strength-check' in cfg,
    'V-220491': lambda cfg: 'password strength-check' in cfg,
    'V-220492': lambda cfg: 'password strength-check' in cfg,
    'V-220493': lambda cfg: bool(re.search(r'exec-timeout [0-5] ', cfg)),
}

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Audit a device against DISA NX-OS STIG rules from New NXOS Checklist.cklb')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. NXCore1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Load the STIG rules from both benchmarks in the checklist file
with open(CHECKLIST_PATH, encoding='utf-8') as f:
    checklist = json.load(f)
rules = [rule for stig in checklist['stigs'] for rule in stig['rules']]
rules.sort(key=lambda rule: SEVERITY_ORDER.get(rule['severity'], 99))

# Prompt for credentials
username, password = netauto.get_credentials()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Pull the running config and close the session
running_config = str(net_connect.send_command('show running-config'))
net_connect.disconnect()

results = {'PASS': 0, 'FAIL': 0, 'NOT AUTOMATED': 0}

print(f'NX-OS STIG audit for {device_name}\n')

for rule in rules:
    group_id = rule['group_id']
    check = CHECKS.get(group_id)

    if check is None:
        status = 'NOT AUTOMATED'
    else:
        status = 'PASS' if check(running_config) else 'FAIL'
    results[status] += 1

    print(f"[{rule['severity'].upper():6}] {status:14} {group_id}  {rule['rule_title']}")

print(f"\n{results['PASS']} passed, {results['FAIL']} failed, {results['NOT AUTOMATED']} not automated (need manual review or external infrastructure) out of {len(rules)} rules.")
