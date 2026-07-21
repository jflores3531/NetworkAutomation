#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco NX-OS Switch L2S/NDM
STIG rules in New NXOS Checklist.cklb, reporting PASS/FAIL for the rules that
can be checked from config text alone."""

import argparse
import re
import netauto
import stig_common

CHECKLIST_PATH = 'New NXOS Checklist.cklb'


def _vlan_in_spec(vlan, spec):
    """True if vlan appears in a comma-separated list of VLAN IDs/ranges, e.g. '2-4094'."""
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-')
            if int(lo) <= vlan <= int(hi):
                return True
        elif part.isdigit() and int(part) == vlan:
            return True
    return False


def _vlan_range_covers_user_vlans(cfg, pattern, user_vlans, missing_line_what):
    """PASS only if the VLAN range captured by `pattern` (e.g. from an
    `ip dhcp snooping vlan <spec>` or `ip arp inspection vlan <spec>` line)
    actually covers every VLAN in `user_vlans` — not just that *some* list is
    configured. Catches the case where the feature is scoped to the wrong VLANs
    (e.g. management/default) while the real user VLAN has none."""
    m = re.search(pattern, cfg, re.M)
    if not m:
        return False, f'missing {missing_line_what}'
    spec = m.group(1)
    if not user_vlans:
        return False, 'no genuine user VLANs discovered from `show vlan brief` (check inventory.yaml non_user_vlans / device VLAN config)'
    missing = [v for v in user_vlans if not _vlan_in_spec(int(v), spec)]
    if missing:
        return False, f'configured VLAN range `{spec}` does not cover user VLAN(s): {", ".join(missing)}'
    return True, f'`{spec}` covers all user VLAN(s): {", ".join(sorted(user_vlans, key=int))}'


def _dhcp_snooping_check(cfg, user_vlans):
    if 'feature dhcp' not in cfg:
        return False, 'missing `feature dhcp`'
    if not re.search(r'^ip dhcp snooping$', cfg, re.M):
        return False, 'missing `ip dhcp snooping` (globally enabled)'
    return _vlan_range_covers_user_vlans(
        cfg, r'ip dhcp snooping vlan (\S+)', user_vlans, 'an `ip dhcp snooping vlan <list>` line'
    )


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
    # V-220684/686 (DHCP snooping/DAI VLAN coverage) are added below, after
    # discovering the device's genuine user VLANs — a plain presence check can't
    # tell "configured for the wrong VLANs" from "configured correctly" (e.g.
    # snooping enabled on VLAN 1,10 while the real user VLAN has none).
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

# Discover genuine user VLANs (excludes management/servers/unused VLANs from
# inventory.yaml's non_user_vlans) so V-220684/V-220686 can verify DHCP
# snooping/DAI actually cover them, not just that some VLAN list exists. Uses a
# separate connection since run_stig_audit manages its own for running-config.
vlan_discovery_connect = netauto.connect(device_name, device_info, username, password)
if vlan_discovery_connect is None:
    raise SystemExit(1)
user_vlans = stig_common.discover_user_vlans(vlan_discovery_connect, exclude=netauto.load_non_user_vlans())
vlan_discovery_connect.disconnect()

CHECKS['V-220684'] = lambda cfg: _dhcp_snooping_check(cfg, user_vlans)
CHECKS['V-220686'] = lambda cfg: _vlan_range_covers_user_vlans(
    cfg, r'ip arp inspection vlan (\S+)', user_vlans, 'an `ip arp inspection vlan <list>` line'
)

stig_common.run_stig_audit(
    device_name, device_info, CHECKLIST_PATH, CHECKS,
    title='NX-OS STIG audit',
    username=username, password=password,
)
