#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco IOS Router NDM/RTR
STIG rules in New IOS Router Checklist.cklb, reporting PASS/FAIL for the
rules that can be checked from config text alone."""

import argparse
import re
import netauto
import stig_common

CHECKLIST_PATH = 'New IOS Router Checklist.cklb'


def aux_port_disabled(cfg):
    """V-216571: 'line aux 0' block must contain 'no exec'."""
    match = re.search(r'line aux 0\n((?:.*\n)*?)(?=line |\Z)', cfg)
    return bool(match) and 'no exec' in match.group(1)


# Regex/keyword checks for rules that can be verified directly from running-config
# text. Most RTR rules describe perimeter/BGP/MPLS/multicast topology and policy
# decisions (authorized sources, AS numbers, site address space, etc.) that can't
# be verified from a single device's config alone, so only the generically
# checkable ones are covered here. The rest are reported as NOT AUTOMATED.
CHECKS = {
    # --- NDM (Network Device Management) ---
    'V-215669': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-215681': lambda cfg: bool(re.search(r'min-length (1[5-9]|[2-9]\d)', cfg)),
    'V-215687': lambda cfg: 'service password-encryption' in cfg,
    'V-215688': lambda cfg: bool(re.search(r'exec-timeout [0-5] ', cfg)),
    'V-215699': lambda cfg: 'ip ssh version 2' in cfg and bool(re.search(r'ip ssh server algorithm mac\s+\S*hmac-sha2', cfg)),
    'V-215700': lambda cfg: bool(re.search(r'ip ssh server algorithm encryption\s+\S*aes', cfg)),

    # --- RTR (Router) ---
    'V-216563': lambda cfg: 'no ip gratuitous-arps' in cfg,
    'V-216564': lambda cfg: 'no ip directed-broadcast' in cfg,
    'V-216565': lambda cfg: 'no ip unreachables' in cfg,
    'V-216566': lambda cfg: 'no ip mask-reply' in cfg,
    'V-216567': lambda cfg: 'no ip redirects' in cfg,
    'V-216571': aux_port_disabled,
    'V-216584': lambda cfg: 'no lldp transmit' in cfg,
    'V-216585': lambda cfg: 'no cdp run' in cfg or 'no cdp enable' in cfg,
    'V-216586': lambda cfg: 'no ip proxy-arp' in cfg,
    'V-229030': lambda cfg: 'no ip cef' not in cfg,
}

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Audit a device against DISA IOS Router STIG rules from New IOS Router Checklist.cklb')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

stig_common.run_stig_audit(
    device_name, device_info, CHECKLIST_PATH, CHECKS,
    title='IOS Router STIG audit',
    username=username, password=password,
    not_automated_note='need manual review, topology/policy context, or external infrastructure',
)
