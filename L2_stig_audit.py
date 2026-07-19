#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco IOS Switch L2S/NDM
STIG rules in New Layer 2 switch Checklist.cklb, reporting PASS/FAIL for the
rules that can be checked from config text alone."""

import argparse
import re
import netauto
import stig_common

CHECKLIST_PATH = 'New Layer 2 switch Checklist.cklb'

# Regex/keyword checks for rules that can be verified directly from running-config
# text. Rules with no entry here need external infrastructure (RADIUS, syslog,
# NTP, PKI) or manual/topology review, and are reported as NOT AUTOMATED.
CHECKS = {
    # --- L2S (Layer 2 Switch) ---
    'V-220624': lambda cfg: bool(re.search(r'^vtp password \S+', cfg, re.M)),
    'V-220630': lambda cfg: bool(re.search(r'spanning-tree bpduguard enable|spanning-tree portfast bpduguard default', cfg)),
    'V-220631': lambda cfg: 'spanning-tree loopguard default' in cfg,
    'V-220632': lambda cfg: bool(re.search(r'switchport block unicast', cfg)),
    'V-220633': lambda cfg: bool(re.search(r'^ip dhcp snooping$', cfg, re.M)) and bool(re.search(r'ip dhcp snooping vlan', cfg)),
    'V-220634': lambda cfg: bool(re.search(r'ip verify source', cfg)),
    'V-220635': lambda cfg: bool(re.search(r'ip arp inspection vlan', cfg)),
    'V-220636': lambda cfg: bool(re.search(r'storm-control (broadcast|multicast|unicast) level', cfg)),
    'V-220637': lambda cfg: 'no ip igmp snooping' not in cfg,
    'V-220638': lambda cfg: bool(re.search(r'spanning-tree mode rapid-pvst', cfg)),
    'V-220639': lambda cfg: bool(re.search(r'udld (enable|aggressive)', cfg)),
    'V-220640': lambda cfg: bool(re.search(r'switchport mode trunk', cfg)) and not re.search(r'switchport mode dynamic', cfg),
    'V-220642': lambda cfg: not bool(re.search(r'switchport access vlan 1\b', cfg)),
    'V-220643': lambda cfg: bool(re.search(r'switchport trunk allowed vlan (?!.*\b1\b)\S+', cfg)),
    'V-220645': lambda cfg: bool(re.search(r'switchport mode access', cfg)),
    'V-220646': lambda cfg: bool(re.search(r'switchport trunk native vlan (?!1\b)\d+', cfg)),

    # --- NDM (Network Device Management) ---
    'V-220577': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-220589': lambda cfg: bool(re.search(r'security passwords min-length (1[5-9]|[2-9]\d)', cfg)),
    'V-220595': lambda cfg: 'service password-encryption' in cfg and 'enable secret' in cfg,
    'V-220596': lambda cfg: bool(re.search(r'exec-timeout [0-5] ', cfg)),
    'V-220607': lambda cfg: bool(re.search(r'ip ssh version 2', cfg)),
}

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Audit a device against DISA STIG rules from New Layer 2 switch Checklist.cklb')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

stig_common.run_stig_audit(
    device_name, device_info, CHECKLIST_PATH, CHECKS,
    title='STIG audit',
    username=username, password=password,
)
