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


def _bpdu_guard_check(cfg):
    """V-220681: like L2S's V-220630, the global 'spanning-tree port type edge
    bpduguard default' form only activates BPDU Guard on ports typed as
    "edge" (NX-OS's PortFast equivalent) - checking for its presence alone is
    a false-pass risk if edge type was never enabled anywhere (globally via
    'spanning-tree port type edge default', or per-port via 'spanning-tree
    port type edge'). The per-interface 'spanning-tree bpduguard enable'
    form has no such dependency and is accepted on its own."""
    if re.search(r'spanning-tree bpduguard enable', cfg):
        return True, 'found: `spanning-tree bpduguard enable` (per-interface, no edge-type dependency)'
    has_bpduguard_default = bool(re.search(r'^spanning-tree port type edge bpduguard default\s*$', cfg, re.M))
    has_edge_type = bool(re.search(r'^\s*spanning-tree port type edge(?:\s+default)?\s*$', cfg, re.M))
    if has_bpduguard_default and has_edge_type:
        return True, 'found: `spanning-tree port type edge default` (or per-port) + `spanning-tree port type edge bpduguard default`'
    if has_bpduguard_default:
        return False, (
            '`spanning-tree port type edge bpduguard default` present but no edge port type found '
            '(`spanning-tree port type edge default` globally, or `spanning-tree port type edge` per-port) '
            '- BPDU Guard has no edge ports to activate on'
        )
    return False, 'missing BPDU Guard (`spanning-tree bpduguard enable` per-interface, or `spanning-tree port type edge bpduguard default` + edge type)'


def _password_strength_check(cfg):
    """V-220489/490/491/492: password complexity (strength-check) is enabled
    by default on NX-OS - DISA's Check Text says the compliant state is that
    `no password strength-check` should NOT be found, not that `password
    strength-check` must be explicitly present. The old check used
    `'password strength-check' in cfg`, a plain substring test that also
    matches inside `no password strength-check` - meaning a device that
    explicitly disabled it would still show a false PASS."""
    if re.search(r'^no password strength-check\s*$', cfg, re.M):
        return False, 'found `no password strength-check` - password complexity is explicitly disabled'
    return True, 'password strength-check enabled (default-on, not explicitly disabled)'


def _line_exec_timeout_ok_nxos(chunk, max_minutes=5):
    """NX-OS's exec-timeout takes a single argument (minutes only), unlike
    IOS's two-argument 'exec-timeout <min> <sec>' form. Returns
    (ok, matched_text_or_None)."""
    m = re.search(r'exec-timeout (\d+)', chunk)
    if not m:
        return False, None
    minutes = int(m.group(1))
    return minutes != 0 and minutes <= max_minutes, m.group(0)


def _exec_timeout_check(cfg):
    """V-220493: stig_common.exec_timeout_ok() assumes IOS's two-argument
    exec-timeout syntax and will never match real NX-OS config (single
    argument), causing a permanent false FAIL regardless of actual
    compliance. DISA's Check Text also configures exec-timeout on both
    `line console` and `line vty` as separate required scopes - same
    false-pass shape as L2S's V-220596 if only checked as "any exec-timeout
    line present"."""
    con_ok = con_match = vty_ok = vty_match = None
    for chunk in re.split(r'^(?=line \S)', cfg, flags=re.M):
        header = chunk.splitlines()[0] if chunk else ''
        if header.startswith('line console'):
            con_ok, con_match = _line_exec_timeout_ok_nxos(chunk)
        elif header.startswith('line vty'):
            ok, match = _line_exec_timeout_ok_nxos(chunk)
            vty_ok = bool(vty_ok) or ok
            vty_match = vty_match or match

    if con_ok and vty_ok:
        return True, f'compliant on console (`{con_match}`) and vty (`{vty_match}`)'
    missing = []
    if not con_ok:
        missing.append('console (`line console`): ' + (f'non-compliant (`{con_match}`)' if con_match else 'no exec-timeout set'))
    if not vty_ok:
        missing.append('vty: ' + (f'non-compliant (`{vty_match}`)' if vty_match else 'no exec-timeout set'))
    return False, '; '.join(missing)


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
    'V-220681': _bpdu_guard_check,
    'V-220682': lambda cfg: 'spanning-tree loopguard default' in cfg,
    # V-220684/686 (DHCP snooping/DAI VLAN coverage) are added below, after
    # discovering the device's genuine user VLANs — a plain presence check can't
    # tell "configured for the wrong VLANs" from "configured correctly" (e.g.
    # snooping enabled on VLAN 1,10 while the real user VLAN has none).
    'V-220688': lambda cfg: 'no ip igmp snooping' not in cfg,
    # Fix Text's only command is 'feature udld' - confirmed live on NXCore1
    # that 'udld enable' isn't valid NX-OS syntax at all ("% Invalid command").
    # UDLD is on by default for every fiber interface once the feature itself
    # is enabled, per the STIG's own note - no separate enable line needed.
    'V-220689': lambda cfg: 'feature udld' in cfg,
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
    'V-220489': _password_strength_check,
    'V-220490': _password_strength_check,
    'V-220491': _password_strength_check,
    'V-220492': _password_strength_check,
    'V-220493': _exec_timeout_check,
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
