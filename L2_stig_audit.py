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


def _presence(cfg, pattern, flags=0, what=None):
    """PASS if pattern is found; reason shows the matched line, or what was
    searched for if it wasn't."""
    m = re.search(pattern, cfg, flags)
    label = what or f'a line matching `{pattern}`'
    if m:
        return True, f'found: `{m.group(0).strip()}`'
    return False, f'not found — searched for {label}'


def _absence(cfg, pattern, flags=0, what=None):
    """PASS if pattern is NOT found (for "must not have X" rules)."""
    m = re.search(pattern, cfg, flags)
    label = what or f'`{pattern}`'
    if m:
        return False, f'found (should be absent): `{m.group(0).strip()}`'
    return True, f'not found (correctly absent) — searched for {label}'


def _all_of(cfg, conditions):
    """conditions: list of (label, pattern), each tested with re.search(pattern,
    cfg, re.M). PASS only if all match; reason lists what's missing/present."""
    missing, present = [], []
    for label, pattern in conditions:
        (present if re.search(pattern, cfg, re.M) else missing).append(label)
    if missing:
        detail = f"missing: {', '.join(missing)}"
        if present:
            detail += f' (have: {", ".join(present)})'
        return False, detail
    return True, f"all present: {', '.join(present)}"


def _count_distinct(cfg, pattern, minimum, noun, flags=re.M):
    """PASS if at least `minimum` distinct values of `pattern`'s capture group
    are found. Reason lists what was actually found."""
    found = sorted(set(re.findall(pattern, cfg, flags)))
    if len(found) >= minimum:
        return True, f'found {len(found)} {noun}: {", ".join(found)}'
    if found:
        return False, f'only {len(found)} of {minimum}+ required {noun} found: {", ".join(found)}'
    return False, f'no {noun} found (need {minimum}+) — searched for `{pattern}`'


def _all_access_ports_have(cfg, pattern, what):
    access, _ = parse_switchports(cfg)
    if not access:
        return False, 'no access/host-facing switchports found in config'
    missing = sorted(name for name, block in access.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(access)} access port(s): {", ".join(sorted(access))}'


def _all_trunk_ports_have(cfg, pattern, what):
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk switchports found in config'
    missing = sorted(name for name, block in trunk.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(trunk)} trunk port(s): {", ".join(sorted(trunk))}'


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
    so it's conservatively treated as a finding too. Reason lists which specific
    trunk(s) still allow VLAN 1."""
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk switchports found in config'
    bad = []
    for name, block in sorted(trunk.items()):
        m = re.search(r'switchport trunk allowed vlan (.+)$', block, re.M)
        if not m:
            bad.append(f'{name} (no allowed-vlan restriction, VLAN 1 allowed by default)')
            continue
        spec = m.group(1).strip()
        pruned = (
            (spec.startswith('except') and _vlan_in_spec(1, spec[len('except'):].strip()))
            or (spec.startswith('remove') and _vlan_in_spec(1, spec[len('remove'):].strip()))
            or (not spec.startswith(('except', 'remove', 'add')) and not _vlan_in_spec(1, spec))
        )
        if not pruned:
            bad.append(f'{name} (`switchport trunk allowed vlan {spec}` still allows VLAN 1)')
    if bad:
        return False, 'VLAN 1 not pruned on: ' + '; '.join(bad)
    return True, f'VLAN 1 pruned on all {len(trunk)} trunk port(s): {", ".join(sorted(trunk))}'


# V-220586: presence of any of these directives (not "no "-prefixed) is a finding —
# unnecessary/nonsecure services that should stay disabled by default.
UNNECESSARY_SERVICES_PATTERN = (
    r'^\s*(boot network|ip boot server|ip bootp server|ip dns server|ip identd|'
    r'ip finger|ip http server|ip rcmd rcp-enable|ip rcmd rsh-enable|'
    r'service config|service finger|service tcp-small-servers|'
    r'service udp-small-servers|service pad|service call-home)\s*$'
)


def _no_unnecessary_services(cfg):
    found = sorted(set(re.findall(UNNECESSARY_SERVICES_PATTERN, cfg, re.M)))
    if found:
        return False, f'enabled (should be disabled): {", ".join(found)}'
    return True, 'none of the unnecessary/nonsecure services found enabled'


def _exec_timeout_reason(cfg):
    matches = re.findall(r'exec-timeout (\d+) (\d+)', cfg)
    ok = stig_common.exec_timeout_ok(cfg)
    shown = ', '.join(f'{m}m{s}s' for m, s in matches)
    if ok:
        return True, f'exec-timeout line(s) OK (nonzero, <=5 min): {shown}'
    if not matches:
        return False, 'no `exec-timeout <min> <sec>` lines found'
    return False, f'non-compliant exec-timeout line(s) (need nonzero, <=5 min): {shown}'


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
    'V-220632': lambda cfg: _all_access_ports_have(cfg, r'switchport block unicast', 'UUFB (`switchport block unicast`)'),
    'V-220634': lambda cfg: _all_access_ports_have(cfg, r'ip verify source', 'IP Source Guard (`ip verify source`)'),
    'V-220636': lambda cfg: _all_access_ports_have(cfg, r'storm-control broadcast level', 'storm control (`storm-control broadcast level ...`)'),
    'V-220640': lambda cfg: _all_trunk_ports_have(cfg, r'switchport nonegotiate', '`switchport nonegotiate`'),
    'V-220643': lambda cfg: default_vlan_pruned_from_trunks(cfg),
    'V-220646': lambda cfg: _all_trunk_ports_have(cfg, r'switchport trunk native vlan (?!1\s*$)\d+', 'a non-default native VLAN'),
    'V-220586': _no_unnecessary_services,
    'V-220624': lambda cfg: _presence(cfg, r'^vtp password \S+', re.M, 'a `vtp password <value>` line'),
    'V-220630': lambda cfg: _presence(cfg, r'spanning-tree bpduguard enable|spanning-tree portfast bpduguard default', what='`spanning-tree bpduguard enable` or `spanning-tree portfast bpduguard default`'),
    'V-220631': lambda cfg: _presence(cfg, r'spanning-tree loopguard default', what='`spanning-tree loopguard default`'),
    'V-220633': lambda cfg: _all_of(cfg, [
        ('ip dhcp snooping', r'^ip dhcp snooping$'),
        ('ip dhcp snooping vlan <list>', r'ip dhcp snooping vlan'),
    ]),
    'V-220635': lambda cfg: _presence(cfg, r'ip arp inspection vlan', what='an `ip arp inspection vlan <list>` line'),
    'V-220637': lambda cfg: _absence(cfg, r'no ip igmp snooping', what='`no ip igmp snooping` (would disable it)'),
    'V-220638': lambda cfg: _presence(cfg, r'spanning-tree mode rapid-pvst', what='`spanning-tree mode rapid-pvst`'),
    'V-220639': lambda cfg: _presence(cfg, r'udld (enable|aggressive)', what='`udld enable` or `udld aggressive`'),
    'V-220601': lambda cfg: _count_distinct(cfg, r'^ntp server (\S+)', 2, 'NTP server(s)'),
    'V-220606': lambda cfg: _all_of(cfg, [
        ('ntp authenticate', r'ntp authenticate'),
        ('ntp authentication-key <id> md5 <value>', r'ntp authentication-key \d+ md5 \S+'),
        ('ntp trusted-key <id>', r'ntp trusted-key \d+'),
        ('ntp server <ip> key <id>', r'ntp server \S+ key \d+'),
    ]),

    # --- NDM (Network Device Management) ---
    'V-220577': lambda cfg: _presence(cfg, r'banner (login|motd)', what='a `banner login` or `banner motd`'),
    'V-220589': lambda cfg: _presence(cfg, r'security passwords min-length (1[5-9]|[2-9]\d)', what='`security passwords min-length` of 15+'),
    'V-220595': lambda cfg: _all_of(cfg, [
        ('service password-encryption', r'service password-encryption'),
        ('enable secret', r'enable secret'),
    ]),
    'V-220596': _exec_timeout_reason,
    'V-220607': lambda cfg: _presence(cfg, r'ip ssh version 2', what='`ip ssh version 2`'),
    'V-220608': lambda cfg: _all_of(cfg, [
        ('ip ssh version 2', r'ip ssh version 2'),
        ('ip ssh server algorithm encryption ...aes...', r'ip ssh server algorithm encryption\s+\S*aes'),
    ]),
    # V-220620: matches "logging host x.x.x.x" or the bare legacy "logging x.x.x.x"
    # form. Deliberately excludes non-IP "logging ..." directives (buffered, trap,
    # on, console, etc.) by requiring the token after "logging"/"logging host" to
    # look like an IPv4 address.
    'V-220620': lambda cfg: _count_distinct(
        cfg, r'^logging (?:host )?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 2, 'syslog server(s)'
    ),
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
