#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco NX-OS Switch L2S/NDM
STIG rules in New NXOS Checklist.cklb, reporting PASS/FAIL for the rules that
can be checked from config text alone."""

import argparse
import re
import netauto
import stig_common

CHECKLIST_PATH = 'New NXOS Checklist.cklb'


# Interface types that take switchport commands on NX-OS - mgmt0, Vlan<n>
# (SVIs), and loopback<n> aren't physical/logical switchports. Same list
# NXOS_stig_harden_global.py uses.
NXOS_SWITCHPORT_PREFIXES = ('Ethernet', 'port-channel')

# 'show interface status' uses abbreviated interface names ('Eth1/5',
# 'Po10') - running-config uses the full form ('Ethernet1/5',
# 'port-channel10'). Same mapping NXOS_stig_harden_interfaces.py uses.
_SHORT_TO_FULL_PREFIX = (('Eth', 'Ethernet'), ('Po', 'port-channel'))

# Every status value 'show interface status' actually prints in the Status
# column - used as an anchor to pull the status out of a fixed-width table
# whose Name field is free text that can't be reliably column-sliced.
_INTERFACE_STATUSES = (
    'connected', 'disabled', 'suspended', 'notconnect', 'noOperMem',
    'inactive', 'xcvrAbsent', 'sfpAbsent', 'err-disabled',
)


def parse_interface_status(output):
    """Maps every interface name (expanded to running-config form) found in
    'show interface status' output to its Status column value. 'disabled'
    specifically means administratively shutdown - confirmed live on
    NXCore1, distinct from 'suspended'/'notconnect' which don't mean unused.
    Same parser NXOS_stig_harden_interfaces.py uses to decide what to push -
    kept in sync so the audit checks the same "not in use" definition the
    harden side acts on."""
    statuses = {}
    for line in output.splitlines():
        m = re.match(r'^(\S+)\s+.*?\b(' + '|'.join(_INTERFACE_STATUSES) + r')\b', line)
        if not m:
            continue
        short_name, status = m.group(1), m.group(2)
        full_name = short_name
        for short_prefix, full_prefix in _SHORT_TO_FULL_PREFIX:
            if short_name.startswith(short_prefix) and short_name[len(short_prefix):len(short_prefix) + 1].isdigit():
                full_name = full_prefix + short_name[len(short_prefix):]
                break
        statuses[full_name] = status
    return statuses


def parse_switchports(cfg):
    """Classify every switchport-capable interface as access or trunk based on
    explicit evidence in its own config block - NOT NXOS_stig_harden_global.py's
    push-time assumption that "lacks an access VLAN, so it should become
    trunk" (that's a policy for what to push, not evidence of what's already
    there). Access: explicit 'switchport access vlan <n>' line - the only
    reliable access signal on NX-OS (confirmed live that 'switchport mode
    access' alone doesn't consistently appear in running-config, same
    omission NXOS_stig_harden_global.py's own classify_switchports() works around).
    Trunk: explicit 'switchport mode trunk' line. A port with neither (still
    in NX-OS's default negotiated/L3-routed state) falls into neither bucket -
    it's not silently treated as access; V-220694's check below is the one
    that catches that ambiguous state directly.
    Returns (access_blocks, trunk_blocks), each {interface_name: block_text}."""
    access, trunk = {}, {}
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if re.search(r'^\s*switchport access vlan \d+\s*$', chunk, re.M):
            access[name] = chunk
        elif re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M):
            trunk[name] = chunk
    return access, trunk


def _all_access_ports_have(cfg, pattern, what, exclude_vlan=None):
    """exclude_vlan drops ports assigned to the given VLAN from the access
    population before checking - used to exclude unused_vlan-assigned ports
    (V-220690's disabled-port bucket) from host-facing-only requirements
    like UUFB/IPSG/storm control. Those rules' own titles say "host-facing
    or untrusted access switch ports" - a port deliberately parked on the
    black-hole VLAN isn't host-facing, it's not in use at all."""
    access, _ = parse_switchports(cfg)
    if exclude_vlan:
        access = {
            name: block for name, block in access.items()
            if not re.search(rf'^\s*switchport access vlan {exclude_vlan}\s*$', block, re.M)
        }
    if not access:
        return None, (
            'not applicable - no access-classified switchports found in config '
            '(this rule only governs host-facing access ports)'
        )
    missing = sorted(name for name, block in access.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(access)} access port(s): {", ".join(sorted(access))}'


def _all_trunk_ports_have(cfg, pattern, what):
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk-classified switchports found in config'
    missing = sorted(name for name, block in trunk.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(trunk)} trunk port(s): {", ".join(sorted(trunk))}'


# V-220692: same pruning logic as L2_stig_audit.py's default_vlan_pruned_from_trunks,
# adapted to NX-OS's identical 'switchport trunk allowed vlan <spec>' syntax
# (confirmed same command form as IOS, per NXOS_stig_harden_global.py's V-220692 push).
def _default_vlan_pruned_from_trunks(cfg):
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk-classified switchports found in config'
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


# V-220694: unlike L2S's access-layer switches (default policy: non-trunk =
# access), NXOS_stig_harden_global.py's core-switch policy is the inverse (default:
# non-access = trunk) - so "must be configured as access" can't be checked
# literally per-port here without topology knowledge this script doesn't
# have (which ports are host-facing vs. interconnects on a core switch).
# What IS checkable, and what the rule's underlying intent actually is (see
# L2_stig_audit.py's V-220645 - same reasoning): no switchport-capable
# interface should be left without an explicit access-or-trunk
# classification, i.e. sitting in NX-OS's default negotiated/L3-routed
# state. That ambiguous state is the real risk DISA is guarding against.
def _all_ports_explicit_mode(cfg):
    bad, total = [], 0
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        total += 1
        is_access = bool(re.search(r'^\s*switchport access vlan \d+\s*$', chunk, re.M))
        is_trunk = bool(re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M))
        if not (is_access or is_trunk):
            bad.append(m.group(1))
    if total == 0:
        return False, 'no switchport-capable interfaces found in config'
    if bad:
        return False, (
            f'left without an explicit access or trunk classification (still in '
            f"NX-OS's default negotiated/routed state): {', '.join(sorted(bad))}"
        )
    return True, f'all {total} switchport-capable interface(s) explicitly classified as access or trunk'


def _no_access_ports_on_native_vlan(cfg, native_vlan_id):
    """V-220696: no access-classified switchport should be assigned to the
    native VLAN. Satisfied by construction in this project's design (access
    ports get real user VLANs like 50/100, the native VLAN is a dedicated
    unused/black-hole VLAN reserved for trunk native assignment only) - this
    verifies it independently rather than assuming the design held."""
    if not native_vlan_id:
        return None, 'not applicable - no native_vlan configured in inventory.yaml'
    access, _ = parse_switchports(cfg)
    if not access:
        return None, 'not applicable - no access-classified switchports found in config'
    offenders = sorted(
        name for name, block in access.items()
        if re.search(rf'^\s*switchport access vlan {native_vlan_id}\s*$', block, re.M)
    )
    if offenders:
        return False, f'access port(s) assigned to native VLAN {native_vlan_id}: {", ".join(offenders)}'
    return True, f'no access port(s) assigned to native VLAN {native_vlan_id} (checked {len(access)} access port(s))'


def _disabled_ports_on_unused_vlan(cfg, unused_vlan, interface_statuses):
    """V-220690. Check Content's literal finding condition: "If there are
    any access switch ports not in use and not in an inactive VLAN, this is
    a finding." "Not in use" is verified via 'show interface status''s
    'disabled' status (administratively shutdown) rather than parse_switchports()'s
    access/trunk split - a disabled port pushed to trunk mode by an earlier
    NXOS_stig_harden_interfaces.py run (before this feature existed) would
    otherwise be invisible to this check, which only inspects access-block
    text. Every switchport-capable interface currently reported 'disabled'
    needs an explicit 'switchport access vlan <unused_vlan>' line,
    regardless of its current access/trunk classification."""
    if not unused_vlan:
        return None, 'not applicable - no unused_vlan configured in inventory.yaml'
    offenders, checked = [], 0
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if interface_statuses.get(name) != 'disabled':
            continue
        checked += 1
        if not re.search(rf'^\s*switchport access vlan {unused_vlan}\s*$', chunk, re.M):
            offenders.append(name)
    if checked == 0:
        return None, 'not applicable - no administratively-shutdown switchport-capable interfaces found'
    if offenders:
        return False, f'disabled port(s) not assigned to unused VLAN {unused_vlan}: {", ".join(sorted(offenders))}'
    return True, f'all {checked} disabled switchport-capable interface(s) assigned to unused VLAN {unused_vlan}'


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


def _ssh_macs_fips_check(cfg):
    """V-220488/503: both rules share the identical Fix Text example ('ssh
    macs hmac-sha2-256 hmac-sha2-512') under different CCI categories
    (replay-resistant auth vs. FIPS-validated HMAC integrity) - one check
    covers both. That Fix Text example doesn't carry over to NX-OS though
    (confirmed live on NXCore1: 'ssh macs' takes exactly one algorithm name
    per invocation, not a list) - and hmac-sha2-256/hmac-sha2-512 are
    already in NX-OS's default MAC allow-list on this platform ("Config is
    already present" pushing either), which also means they never appear in
    plain `show running-config` the way most default state doesn't. What
    running-config *does* show is explicit 'no ssh macs <algo>' overrides -
    same as 'no password strength-check' - so the actual compliant state
    here (confirmed via `show running-config all | include macs`) is
    verified by checking that everything except hmac-sha2-256/hmac-sha2-512
    is explicitly disabled: hmac-sha1/hmac-sha1-etm@openssh.com are
    genuinely weak (SHA-1), while hmac-sha2-256-etm@openssh.com/
    hmac-sha2-512-etm@openssh.com are still SHA-2-based but outside the two
    algorithms DISA's Fix Text example names, so disabled too rather than
    left to interpretation."""
    non_compliant_macs = [
        'hmac-sha1', 'hmac-sha1-etm@openssh.com',
        'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
    ]
    still_allowed = [algo for algo in non_compliant_macs if f'no ssh macs {algo}' not in cfg]
    if still_allowed:
        return False, f'MAC(s) not explicitly disabled: {", ".join(still_allowed)}'
    return True, (
        'all MACs besides hmac-sha2-256/hmac-sha2-512 explicitly disabled '
        '- those two remain allowed by NX-OS default'
    )


def _ssh_login_attempts_check(cfg):
    """V-220480: 3 is NX-OS's own default value on this platform - confirmed
    via `show running-config all | include login-attempts` on NXCore1, which
    only appears there and not in plain `show running-config`, same
    hidden-default pattern as `feature ntp`/the FIPS MACs above. No explicit
    line therefore means the compliant default (3) is in effect, not a
    missing/failed push. Requires exactly 3, not "3 or fewer" - the Check
    Text's required value is the literal number 3, not an org-defined
    ceiling, so a stricter override (e.g. 1) is treated as a deviation from
    the specified value rather than automatically compliant."""
    m = re.search(r'^ssh login-attempts (\d+)', cfg, re.M)
    if not m:
        return True, 'no explicit override found - NX-OS default of 3 is in effect'
    attempts = int(m.group(1))
    if attempts == 3:
        return True, f'ssh login-attempts {attempts}'
    return False, f'ssh login-attempts {attempts} does not equal the required value of 3'


# Regex/keyword checks for rules that can be verified directly from running-config
# text. Rules with no entry here need external infrastructure (RADIUS, syslog,
# NTP, PKI) or manual/topology review, and are reported as NOT AUTOMATED.
CHECKS = {
    # --- L2S (Layer 2 Switch) ---
    # V-220683/685/687/691/692/694/695 (unicast flood blocking, IP source guard,
    # storm control, default VLAN on host ports, default VLAN pruned from trunks,
    # access ports, native VLAN) are per-interface, verified via parse_switchports()
    # above - same interface-classification approach as L2_stig_audit.py, adapted
    # to NX-OS's own reliable signals (see that function's docstring for why).
    # exclude_vlan=unused_vlan on all four - unused_vlan is a module-level
    # global assigned further down (after the device connection), but these
    # lambdas aren't called until stig_common.run_stig_audit() runs, well
    # after that assignment, so Python's late-binding closures resolve it
    # correctly at call time.
    'V-220683': lambda cfg: _all_access_ports_have(cfg, r'switchport block unicast', 'UUFB (`switchport block unicast`)', exclude_vlan=unused_vlan),
    'V-220685': lambda cfg: _all_access_ports_have(cfg, r'ip verify source dhcp-snooping-vlan', 'IP Source Guard (`ip verify source dhcp-snooping-vlan`)', exclude_vlan=unused_vlan),
    'V-220687': lambda cfg: _all_access_ports_have(cfg, r'storm-control broadcast level \d+', 'storm control (`storm-control broadcast level <n>`)', exclude_vlan=unused_vlan),
    'V-220691': lambda cfg: _all_access_ports_have(cfg, r'switchport access vlan (?!1\s*$)\d+', 'an explicit non-default access VLAN (not VLAN 1)', exclude_vlan=unused_vlan),
    'V-220692': _default_vlan_pruned_from_trunks,
    'V-220694': _all_ports_explicit_mode,
    'V-220695': lambda cfg: _all_trunk_ports_have(cfg, r'switchport trunk native vlan (?!1\s*$)\d+', 'a non-default native VLAN'),
    # V-220676 (VTP password) is added below, after a separate `show vtp
    # password` command — confirmed live on NXCore1 that NX-OS deliberately
    # omits the VTP password from `show running-config` entirely (only
    # 'feature vtp'/'vtp domain' show there), so scanning running-config text
    # for it can never pass regardless of whether it's actually set.
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
    # No 'feature ntp' requirement here, unlike V-220689/676/684's feature
    # checks - confirmed live on NXCore1 that NTP isn't gated behind an
    # explicit feature toggle on this platform/image ('feature ntp' pushes
    # as a no-op, "NTP feature is already enabled", and never appears in
    # `show running-config` even with NTP fully configured and working).
    # V-220516: same >=2-distinct-servers shape as V-220498's NTP check below.
    'V-220516': lambda cfg: len(set(re.findall(r'^logging server (\S+)', cfg, re.M))) >= 2,
    # V-220474: Check Text's example scopes session-limit to 'line vty' only
    # (not 'line console') - the bare command is unambiguous enough on its
    # own that a plain search doesn't risk matching anything else.
    'V-220474': lambda cfg: bool(re.search(r'session-limit \d+', cfg)),
    # V-220480: Check Text's required value is literally 3, not an
    # org-defined number - matches the exact command this project pushes.
    'V-220480': _ssh_login_attempts_check,
    'V-220488': _ssh_macs_fips_check,
    'V-220503': _ssh_macs_fips_check,
    'V-220498': lambda cfg: len(set(re.findall(r'^ntp server (\S+)', cfg, re.M))) >= 2,
    'V-220502': lambda cfg: (
        'ntp authenticate' in cfg
        and bool(re.search(r'ntp authentication-key \d+ md5 \S+', cfg))
        and bool(re.search(r'ntp trusted-key \d+', cfg))
        # '.*' between the server and 'key <id>' - confirmed live on NXCore1
        # that NX-OS auto-inserts 'use-vrf default' between them
        # ('ntp server <ip> use-vrf default key <id>'), so a tight
        # '\S+ key \d+' adjacency never matches even when correctly configured.
        and bool(re.search(r'^ntp server \S+.*\bkey \d+', cfg, re.M))
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
# inventory.yaml's non_user_vlans/non_user_vlans_by_device, plus unused_vlan/
# native_vlan) so V-220684/V-220686 can verify DHCP snooping/DAI actually
# cover them, not just that some VLAN list exists. Same exclude set
# NXOS_stig_harden_global.py uses - without also excluding unused_vlan/native_vlan
# here, VLAN 999 (the designated black-hole/native VLAN) gets misclassified
# as an uncovered user VLAN once it exists in the database, the same bug
# already fixed on the harden side. Uses a separate connection since
# run_stig_audit manages its own for running-config.
vlan_discovery_connect = netauto.connect(device_name, device_info, username, password)
if vlan_discovery_connect is None:
    raise SystemExit(1)
non_user_vlan_exclude = list(netauto.load_non_user_vlans(device_name=device_name))
unused_vlan = netauto.load_unused_vlan()
native_vlan_id = netauto.load_native_vlan()
if unused_vlan:
    non_user_vlan_exclude.append(unused_vlan)
if native_vlan_id:
    non_user_vlan_exclude.append(native_vlan_id)
user_vlans = stig_common.discover_user_vlans(vlan_discovery_connect, exclude=non_user_vlan_exclude)

# V-220676: 'show vtp password' instead of running-config - see the comment
# by CHECKS['V-220681'] above for why running-config text can't be used here.
vtp_password_output = str(vlan_discovery_connect.send_command('show vtp password'))

# V-220690: 'show interface status' for live admin state - see
# parse_interface_status()'s docstring for why running-config text alone
# (shutdown/no shutdown presence) isn't used here.
interface_statuses = parse_interface_status(str(vlan_discovery_connect.send_command('show interface status')))
vlan_discovery_connect.disconnect()

CHECKS['V-220684'] = lambda cfg: _dhcp_snooping_check(cfg, user_vlans)
CHECKS['V-220686'] = lambda cfg: _vlan_range_covers_user_vlans(
    cfg, r'ip arp inspection vlan (\S+)', user_vlans, 'an `ip arp inspection vlan <list>` line'
)
CHECKS['V-220676'] = lambda cfg: (
    bool(re.search(r'VTP password:\s*\S+', vtp_password_output)),
    'verified via `show vtp password` (NX-OS omits it from running-config)'
)
CHECKS['V-220696'] = lambda cfg: _no_access_ports_on_native_vlan(cfg, native_vlan_id)
CHECKS['V-220690'] = lambda cfg: _disabled_ports_on_unused_vlan(cfg, unused_vlan, interface_statuses)

stig_common.run_stig_audit(
    device_name, device_info, CHECKLIST_PATH, CHECKS,
    title='NX-OS STIG audit',
    username=username, password=password,
)
