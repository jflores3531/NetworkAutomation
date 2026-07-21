#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco NX-OS Switch L2S/NDM
STIG rules in New NXOS Checklist.cklb, reporting PASS/FAIL for the rules that
can be checked from config text alone."""

import argparse
import re
import netauto
import stig_common

CHECKLIST_PATH = 'New NXOS Checklist.cklb'

# Regex/keyword checks for rules that can be verified directly from running-config
# text. Rules with no entry here need external infrastructure (RADIUS, syslog,
# NTP, PKI) or manual/topology review, and are reported as NOT AUTOMATED.
CHECKS = {
    # --- L2S (Layer 2 Switch) ---
    # V-220683/685/687/691/692/694/695 (unicast flood blocking, IP source guard,
    # storm control, default VLAN on host ports, default VLAN pruned from trunks,
    # access ports, native VLAN) are per-interface: finding the string anywhere in
    # the config doesn't mean every relevant interface has it (or, for V-220691,
    # its absence doesn't prove no port is on the default VLAN, since NX-OS often
    # omits "switchport access vlan 1" when it's already the default). They're
    # deliberately left out and reported as NOT AUTOMATED (same reasoning
    # NXOS_stig_harden.py already uses to skip them as needing interface targeting).
    'V-220676': lambda cfg: bool(re.search(r'^vtp password \S+', cfg, re.M)),
    'V-220681': lambda cfg: bool(re.search(r'spanning-tree port type edge bpduguard default|spanning-tree bpduguard enable', cfg)),
    'V-220682': lambda cfg: 'spanning-tree loopguard default' in cfg,
    'V-220684': lambda cfg: 'feature dhcp' in cfg and bool(re.search(r'^ip dhcp snooping$', cfg, re.M)) and bool(re.search(r'ip dhcp snooping vlan', cfg)),
    'V-220686': lambda cfg: bool(re.search(r'ip arp inspection vlan', cfg)),
    'V-220688': lambda cfg: 'no ip igmp snooping' not in cfg,
    'V-220689': lambda cfg: 'feature udld' in cfg and bool(re.search(r'udld (enable|aggressive)', cfg)),
    'V-220498': lambda cfg: 'feature ntp' in cfg and len(set(re.findall(r'^ntp server (\S+)', cfg, re.M))) >= 2,
    'V-220502': lambda cfg: (
        'feature ntp' in cfg
        and 'ntp authenticate' in cfg
        and bool(re.search(r'ntp authentication-key \d+ md5 \S+', cfg))
        and bool(re.search(r'ntp trusted-key \d+', cfg))
        and bool(re.search(r'ntp server \S+ key \d+', cfg))
    ),
    # V-220499 (log time stamps mappable to UTC/GMT) is deliberately left out: UTC
    # is the default zone, so the checklist itself notes "clock timezone" may not
    # appear in the config even when compliant. Its absence doesn't indicate a
    # finding, so this can't be turned into a meaningful PASS/FAIL from config text
    # alone and is reported as NOT AUTOMATED.

    # --- NDM (Network Device Management) ---
    'V-220481': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-220489': lambda cfg: 'password strength-check' in cfg,
    'V-220490': lambda cfg: 'password strength-check' in cfg,
    'V-220491': lambda cfg: 'password strength-check' in cfg,
    'V-220492': lambda cfg: 'password strength-check' in cfg,
    'V-220493': stig_common.exec_timeout_ok,
}

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Audit a device against DISA NX-OS STIG rules from New NXOS Checklist.cklb')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. NXCore1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

stig_common.run_stig_audit(
    device_name, device_info, CHECKLIST_PATH, CHECKS,
    title='NX-OS STIG audit',
    username=username, password=password,
)
