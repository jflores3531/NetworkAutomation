#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco IOS Switch L2S/NDM
STIG rules in New Layer 2 switch Checklist.cklb, reporting PASS/FAIL for the
rules that can be checked from config text alone."""

import argparse
import re
import netauto
import stig_common

CHECKLIST_PATH = 'New Layer 2 switch Checklist.cklb'

# Interface types that take switchport commands — VLAN SVIs, loopbacks, etc. are
# excluded since "switchport mode trunk" can never appear in their blocks and they'd
# otherwise be misclassified as host-facing/access.
SWITCHPORT_PREFIXES = ('GigabitEthernet', 'FastEthernet', 'TenGigabitEthernet', 'Ethernet', 'Port-channel')


def parse_switchports(cfg):
    """Classify every switchport-capable interface as trunk or host-facing/access:
    an interface counts as trunk only if its block has 'switchport mode trunk';
    anything else (access mode, unset mode, dynamic negotiation) is host-facing.
    Returns (access_blocks, trunk_blocks), each {interface_name: block_text}."""
    access, trunk = {}, {}
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M):
            trunk[name] = chunk
        else:
            access[name] = chunk
    return access, trunk


def _all_access_ports_have(cfg, pattern):
    access, _ = parse_switchports(cfg)
    return bool(access) and all(re.search(pattern, block) for block in access.values())


def _all_trunk_ports_have(cfg, pattern):
    _, trunk = parse_switchports(cfg)
    return bool(trunk) and all(re.search(pattern, block) for block in trunk.values())


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


def default_vlan_pruned_from_trunks(cfg):
    """PASS only if every trunk interface explicitly excludes VLAN 1 from its
    allowed-VLAN list (via 'except'/'remove', or an explicit list that omits 1).
    A trunk with no 'switchport trunk allowed vlan' line defaults to allowing every
    VLAN including 1, so that's a finding. An 'add ...' spec is additive to an
    unknown existing list and can't be reliably evaluated from config text alone,
    so it's conservatively treated as a finding too."""
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False
    for block in trunk.values():
        m = re.search(r'switchport trunk allowed vlan (.+)$', block, re.M)
        if not m:
            return False
        spec = m.group(1).strip()
        if spec.startswith('except') and _vlan_in_spec(1, spec[len('except'):].strip()):
            continue
        if spec.startswith('remove') and _vlan_in_spec(1, spec[len('remove'):].strip()):
            continue
        if not spec.startswith(('except', 'remove', 'add')) and not _vlan_in_spec(1, spec):
            continue
        return False
    return True


# Regex/keyword checks for rules that can be verified directly from running-config
# text. Rules with no entry here need external infrastructure (RADIUS, syslog,
# NTP, PKI) or manual/topology review, and are reported as NOT AUTOMATED.
CHECKS = {
    # --- L2S (Layer 2 Switch) ---
    # V-220642 (default VLAN on host-facing ports) and V-220645 (user-facing ports
    # must be access) are deliberately left NOT AUTOMATED. V-220642: IOS omits
    # "switchport access vlan 1" when it's already the default, so a port's absence
    # of that line can't be distinguished from an explicit (and non-compliant)
    # assignment to VLAN 1 — same false-pass risk fixed in ee04718. V-220645: under
    # this file's own host-facing/trunk classification (host-facing = "lacks
    # switchport mode trunk"), every access-classified port is host-facing *and*
    # already non-trunk by definition — the check could never fail, so it isn't a
    # real verification.
    'V-220632': lambda cfg: _all_access_ports_have(cfg, r'switchport block unicast'),
    'V-220634': lambda cfg: _all_access_ports_have(cfg, r'ip verify source'),
    'V-220636': lambda cfg: _all_access_ports_have(cfg, r'storm-control broadcast level'),
    'V-220640': lambda cfg: _all_trunk_ports_have(cfg, r'switchport nonegotiate'),
    'V-220643': lambda cfg: default_vlan_pruned_from_trunks(cfg),
    'V-220646': lambda cfg: _all_trunk_ports_have(cfg, r'switchport trunk native vlan (?!1\s*$)\d+'),
    # V-220586: presence of any of these directives (not "no "-prefixed) is a
    # finding — unnecessary/nonsecure services that should stay disabled by default.
    'V-220586': lambda cfg: not bool(re.search(
        r'^\s*(boot network|ip boot server|ip bootp server|ip dns server|ip identd|'
        r'ip finger|ip http server|ip rcmd rcp-enable|ip rcmd rsh-enable|'
        r'service config|service finger|service tcp-small-servers|'
        r'service udp-small-servers|service pad|service call-home)\s*$',
        cfg, re.M
    )),
    'V-220624': lambda cfg: bool(re.search(r'^vtp password \S+', cfg, re.M)),
    'V-220630': lambda cfg: bool(re.search(r'spanning-tree bpduguard enable|spanning-tree portfast bpduguard default', cfg)),
    'V-220631': lambda cfg: 'spanning-tree loopguard default' in cfg,
    'V-220633': lambda cfg: bool(re.search(r'^ip dhcp snooping$', cfg, re.M)) and bool(re.search(r'ip dhcp snooping vlan', cfg)),
    'V-220635': lambda cfg: bool(re.search(r'ip arp inspection vlan', cfg)),
    'V-220637': lambda cfg: 'no ip igmp snooping' not in cfg,
    'V-220638': lambda cfg: bool(re.search(r'spanning-tree mode rapid-pvst', cfg)),
    'V-220639': lambda cfg: bool(re.search(r'udld (enable|aggressive)', cfg)),
    'V-220601': lambda cfg: len(set(re.findall(r'^ntp server (\S+)', cfg, re.M))) >= 2,
    'V-220606': lambda cfg: (
        'ntp authenticate' in cfg
        and bool(re.search(r'ntp authentication-key \d+ md5 \S+', cfg))
        and bool(re.search(r'ntp trusted-key \d+', cfg))
        and bool(re.search(r'ntp server \S+ key \d+', cfg))
    ),

    # --- NDM (Network Device Management) ---
    'V-220577': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-220589': lambda cfg: bool(re.search(r'security passwords min-length (1[5-9]|[2-9]\d)', cfg)),
    'V-220595': lambda cfg: 'service password-encryption' in cfg and 'enable secret' in cfg,
    'V-220596': stig_common.exec_timeout_ok,
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
