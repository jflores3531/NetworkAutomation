#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco IOS Switch L2S/NDM
STIG rules in New Layer 2 switch Checklist.cklb, reporting PASS/FAIL for the
rules that can be checked from config text alone."""

import argparse
import ipaddress
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


# V-220647: no access port may be assigned to a trunk's native VLAN (double-
# encapsulation/VLAN-hopping risk). Determines the actual native VLAN(s) in use
# from each trunk's 'switchport trunk native vlan <id>' line - IOS's default
# native VLAN (1) if a trunk has no explicit line - then checks every access
# port's actual VLAN (also defaulting to 1 if unset) against that set.
def _no_access_ports_on_native_vlan(cfg):
    access, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk switchports found in config, cannot determine native VLAN'
    native_vlans = set()
    for name, block in trunk.items():
        m = re.search(r'switchport trunk native vlan (\d+)', block)
        native_vlans.add(m.group(1) if m else '1')
    if not access:
        return True, f'no access ports found - nothing to check against native VLAN(s) {", ".join(sorted(native_vlans))}'
    bad = []
    for name, block in sorted(access.items()):
        m = re.search(r'switchport access vlan (\d+)', block)
        actual = m.group(1) if m else '1'
        if actual in native_vlans:
            bad.append(f'{name} (VLAN {actual})')
    if bad:
        return False, f'access port(s) assigned to the native VLAN: {", ".join(bad)}'
    return True, f'no access ports assigned to native VLAN(s) {", ".join(sorted(native_vlans))}'


# V-220641: disabled (shutdown) access ports must be assigned to the designated
# unused VLAN, and that VLAN must be pruned from all trunk links (same pruning
# logic as default_vlan_pruned_from_trunks, but for the unused VLAN instead of 1).
def _disabled_ports_unused_vlan_check(cfg, unused_vlan):
    if unused_vlan is None:
        return False, 'no `unused_vlan` configured in inventory.yaml'
    access, trunk = parse_switchports(cfg)

    bad_access = []
    disabled_count = 0
    for name, block in sorted(access.items()):
        if not re.search(r'^\s*shutdown\s*$', block, re.M):
            continue
        disabled_count += 1
        m = re.search(r'switchport access vlan (\d+)', block)
        actual = m.group(1) if m else 'default (untagged, VLAN 1)'
        if not m or int(m.group(1)) != unused_vlan:
            bad_access.append(f'{name} (VLAN {actual})')
    if bad_access:
        return False, f'disabled access port(s) not assigned to VLAN {unused_vlan}: {", ".join(bad_access)}'

    bad_trunk = []
    for name, block in sorted(trunk.items()):
        m = re.search(r'switchport trunk allowed vlan (.+)$', block, re.M)
        if not m:
            bad_trunk.append(f'{name} (no allowed-vlan restriction, VLAN {unused_vlan} allowed by default)')
            continue
        spec = m.group(1).strip()
        pruned = (
            (spec.startswith('except') and _vlan_in_spec(unused_vlan, spec[len('except'):].strip()))
            or (spec.startswith('remove') and _vlan_in_spec(unused_vlan, spec[len('remove'):].strip()))
            or (not spec.startswith(('except', 'remove', 'add')) and not _vlan_in_spec(unused_vlan, spec))
        )
        if not pruned:
            bad_trunk.append(f'{name} (`switchport trunk allowed vlan {spec}` still allows VLAN {unused_vlan})')
    if bad_trunk:
        return False, f'VLAN {unused_vlan} not pruned from trunk(s): {"; ".join(bad_trunk)}'

    return True, f'{disabled_count} disabled access port(s) correctly assigned to VLAN {unused_vlan}, pruned from all {len(trunk)} trunk port(s)'


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
    if not re.search(r'^ip dhcp snooping$', cfg, re.M):
        return False, 'missing `ip dhcp snooping` (globally enabled)'
    return _vlan_range_covers_user_vlans(
        cfg, r'ip dhcp snooping vlan (\S+)', user_vlans, 'an `ip dhcp snooping vlan <list>` line'
    )


# V-220575: vty access-class ACL must actually be scoped to the management
# subnet, not just present. A "permit any" or out-of-subnet source doesn't
# satisfy "controlling the flow of management information."
def _acl_source_in_subnet(source_spec, subnet):
    if source_spec.strip() == 'any':
        return False
    m = re.match(r'host (\S+)$', source_spec.strip())
    if m:
        try:
            return ipaddress.ip_address(m.group(1)) in subnet
        except ValueError:
            return False
    m = re.match(r'(\S+)\s+(\S+)$', source_spec.strip())
    if m:
        addr, wildcard = m.groups()
        try:
            netmask = ipaddress.ip_address(int(ipaddress.ip_address(wildcard)) ^ 0xFFFFFFFF)
            acl_net = ipaddress.ip_network(f'{addr}/{netmask}', strict=False)
            return acl_net.subnet_of(subnet)
        except ValueError:
            return False
    return False


def _vty_management_acl_check(cfg, subnet_str):
    if not subnet_str:
        return False, 'no `management_subnet` configured in inventory.yaml'
    subnet = ipaddress.ip_network(subnet_str, strict=False)

    acl_name = None
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith('line vty'):
            m = re.search(r'access-class (\S+) in', chunk)
            if m:
                acl_name = m.group(1)
                break
    if not acl_name:
        return False, 'no `access-class <name> in` found under any `line vty` block'

    permits = None
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith(f'ip access-list extended {acl_name}'):
            permits = re.findall(r'^\s*(?:\d+\s+)?permit ip (.+?)\s+any\s*$', chunk, re.M)
            break
    if permits is None:
        return False, f'`access-class {acl_name} in` applied, but no `ip access-list extended {acl_name}` block found'
    if not permits:
        return False, f'`{acl_name}` has no `permit ip <source> any` lines'

    bad = [src for src in permits if not _acl_source_in_subnet(src, subnet)]
    if bad:
        return False, f'`{acl_name}` (via `access-class {acl_name} in`) permits source(s) outside {subnet_str}: {", ".join(bad)}'
    return True, f'`{acl_name}` (via `access-class {acl_name} in`) permits only sources within {subnet_str}: {", ".join(permits)}'


# V-220571/572/573/574/582/597/611/613: DISA reuses the exact same evidence
# (archive / log config / logging enable) for 8 different audit-logging rules
# (account creation/modification/disabling/removal/enabling, privileges deleted,
# privileged activities, full-text privileged-command logging) — one check
# covers all of them.
def _archive_logging_enabled(cfg):
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith('archive'):
            missing = [c for c in ('log config', 'logging enable') if c not in chunk]
            if missing:
                return False, f'`archive` block present but missing: {", ".join(missing)}'
            return True, 'found: `archive` / `log config` / `logging enable`'
    return False, 'missing `archive` block (with `log config` / `logging enable`)'


# V-220578: administrator activity logging — logging userinfo (privilege escalation)
# plus the same archive block as the 8-rule cluster above
def _admin_activity_logged(cfg):
    if 'logging userinfo' not in cfg:
        return False, 'missing `logging userinfo`'
    archive_ok, archive_reason = _archive_logging_enabled(cfg)
    if not archive_ok:
        return False, f'`logging userinfo` present, but {archive_reason}'
    return True, f'found: `logging userinfo`, {archive_reason}'


# V-220570: concurrent management sessions limited via either ip http
# max-connections or line vty session-limit (either is sufficient per DISA)
def _session_limit_check(cfg):
    http_m = re.search(r'^ip http max-connections (\d+)', cfg, re.M)
    session_m = re.search(r'^\s*session-limit (\d+)', cfg, re.M)
    if http_m or session_m:
        found = []
        if http_m:
            found.append(f'ip http max-connections {http_m.group(1)}')
        if session_m:
            found.append(f'session-limit {session_m.group(1)}')
        return True, f'found: {", ".join(found)}'
    return False, 'missing both `ip http max-connections <n>` and `line vty ... session-limit <n>` (need at least one)'


# V-220590/591/592/593/594: password complexity, each is one sub-command inside
# an `aaa common-criteria policy <name>` block.
def _cc_policy_check(cfg, pattern, min_value, what):
    if 'aaa new-model' not in cfg:
        return False, 'missing `aaa new-model`'
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if not chunk.startswith('aaa common-criteria policy'):
            continue
        m = re.search(pattern, chunk, re.M)
        if m and int(m.group(1)) >= min_value:
            return True, f'found: `{m.group(0).strip()}`'
    return False, f'no `aaa common-criteria policy` block with {what} >= {min_value}'


def _single_local_account_check(cfg):
    usernames = re.findall(r'^username (\S+)', cfg, re.M)
    if len(usernames) != 1:
        found = ', '.join(usernames) if usernames else 'none'
        return False, f'found {len(usernames)} `username` line(s) (need exactly 1): {found}'
    if not re.search(r'^aaa authentication \S+ \S+ group \S+ local\s*$', cfg, re.M):
        return False, f'exactly 1 local account (`{usernames[0]}`) found, but no `aaa authentication ... group <server> local` fallback line'
    return True, f'exactly 1 local account (`{usernames[0]}`), configured as fallback after the AAA server group'


# V-220617: at least 2 RADIUS servers, actually used as the primary auth source
# (not just configured but unused). Checks both the classic single-line
# 'radius-server host <ip>' form and the modern block-style 'radius server
# <name>' / 'address ipv4 <ip> ...' form - confirmed live that this lab's
# vios_l2 image only accepts the modern form ("radius-server host" is
# rejected outright), but other platforms may still use the classic one.
def _radius_redundancy_check(cfg):
    if 'aaa new-model' not in cfg:
        return False, 'missing `aaa new-model`'
    if not re.search(r'^aaa authentication \S+ \S+ group radius( local)?\s*$', cfg, re.M):
        return False, 'missing an `aaa authentication ... group radius ...` line using RADIUS as the primary source'
    legacy_servers = re.findall(r'^radius-server host (\S+)', cfg, re.M) + re.findall(r'^radius host (\S+)', cfg, re.M)
    modern_servers = []
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith('radius server '):
            m = re.search(r'^\s*address ipv4 (\S+)', chunk, re.M)
            if m:
                modern_servers.append(m.group(1))
    servers = sorted(set(legacy_servers + modern_servers))
    if len(servers) >= 2:
        return True, f'found {len(servers)} RADIUS server(s): {", ".join(servers)}'
    if servers:
        return False, f'only {len(servers)} of 2+ required RADIUS server(s) found: {", ".join(servers)}'
    return False, 'no RADIUS servers found (checked classic `radius-server host` and modern `radius server <name>`/`address ipv4` forms - need 2+)'


# V-220624: VTP passwords are deliberately excluded from `show running-config`
# on Cisco IOS (so they don't leak into config backups/TFTP exports) - confirmed
# live that this holds even in VTP transparent mode, not a platform quirk. IOS
# even confirms a redundant push with "Password already set to <value>" rather
# than silently no-op'ing, proving it's genuinely active despite never
# appearing in the config text. A regex against running-config can never find
# it, so this needs live `show vtp password` output instead.
def _vtp_password_check(vtp_password_output):
    if not vtp_password_output or re.search(r'not set', vtp_password_output, re.I):
        return False, 'no VTP password set (`show vtp password` reports none)'
    m = re.search(r'VTP Password:\s*(\S+)', vtp_password_output)
    if m:
        return True, f'VTP password set (`show vtp password`): `{m.group(1)}`'
    return False, f'unexpected `show vtp password` output: {vtp_password_output.strip()}'


# V-220576: exactly 3 consecutive invalid attempts, blocked for >= 900s (15 min)
def _login_block_check(cfg):
    m = re.search(r'^login block-for (\d+) attempts (\d+) within (\d+)', cfg, re.M)
    if not m:
        return False, 'missing `login block-for <secs> attempts <n> within <secs>` line'
    block_secs, attempts, within_secs = int(m.group(1)), int(m.group(2)), int(m.group(3))
    found = f'`login block-for {block_secs} attempts {attempts} within {within_secs}`'
    if attempts != 3:
        return False, f'found {found} but attempts must be exactly 3'
    if block_secs < 900:
        return False, f'found {found} but block-for must be >= 900 (15 min)'
    return True, f'found: {found}'


# V-220629: Root Guard belongs on trunk ports connecting to other switches, but
# never on this switch's own STP root port (see
# stig_common.discover_root_port_interfaces for why). A switch whose only trunk
# port(s) are all root ports (e.g. a leaf/access switch with no downstream
# switches of its own) has nothing eligible to guard - that's a PASS, not a
# finding, since there's nothing wrong to fix.
def _root_guard_check(cfg, root_ports):
    _, trunk = parse_switchports(cfg)
    eligible = sorted(name for name in trunk if name not in root_ports)
    if not eligible:
        return True, (
            'no eligible trunk ports - every trunk port is this switch\'s STP root port '
            'toward the root bridge, and Root Guard must not be applied there'
        )
    missing = [name for name in eligible if not re.search(r'spanning-tree guard root', trunk[name])]
    if missing:
        return False, (
            f'missing `spanning-tree guard root` on: {", ".join(missing)} '
            f'(root port(s) excluded from this check: {", ".join(sorted(root_ports)) or "none"})'
        )
    return True, f'`spanning-tree guard root` present on all {len(eligible)} eligible trunk port(s): {", ".join(eligible)}'


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
    'V-220647': _no_access_ports_on_native_vlan,
    'V-220641': lambda cfg: _disabled_ports_unused_vlan_check(cfg, netauto.load_unused_vlan()),
    'V-220586': _no_unnecessary_services,
    # IOS 15.x rewrites "spanning-tree portfast bpduguard default" to include
    # "edge" in running-config ("...portfast edge bpduguard default") - accept both.
    'V-220630': lambda cfg: _presence(cfg, r'spanning-tree bpduguard enable|spanning-tree portfast (edge )?bpduguard default', what='`spanning-tree bpduguard enable` or `spanning-tree portfast bpduguard default`'),
    'V-220631': lambda cfg: _presence(cfg, r'spanning-tree loopguard default', what='`spanning-tree loopguard default`'),
    # V-220633/635 (DHCP snooping/DAI VLAN coverage) are added below, after
    # discovering the device's genuine user VLANs — a plain presence check can't
    # tell "configured for the wrong VLANs" from "configured correctly" (e.g.
    # snooping enabled on VLAN 1,10 while the real user VLAN 55 has none).
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
    'V-220571': _archive_logging_enabled,
    'V-220572': _archive_logging_enabled,
    'V-220573': _archive_logging_enabled,
    'V-220574': _archive_logging_enabled,
    'V-220582': _archive_logging_enabled,
    'V-220597': _archive_logging_enabled,
    'V-220611': _archive_logging_enabled,
    'V-220613': _archive_logging_enabled,
    'V-220578': _admin_activity_logged,
    'V-220570': _session_limit_check,
    'V-220575': lambda cfg: _vty_management_acl_check(cfg, netauto.load_management_subnet()),
    'V-220587': _single_local_account_check,
    'V-220617': _radius_redundancy_check,
    'V-220590': lambda cfg: _cc_policy_check(cfg, r'^\s*upper-case (\d+)', 1, '`upper-case <n>`'),
    'V-220591': lambda cfg: _cc_policy_check(cfg, r'^\s*lower-case (\d+)', 1, '`lower-case <n>`'),
    'V-220592': lambda cfg: _cc_policy_check(cfg, r'^\s*numeric-count (\d+)', 1, '`numeric-count <n>`'),
    'V-220593': lambda cfg: _cc_policy_check(cfg, r'^\s*special-case (\d+)', 1, '`special-case <n>`'),
    'V-220594': lambda cfg: _cc_policy_check(cfg, r'^\s*char-changes (\d+)', 8, '`char-changes <n>`'),
    'V-220580': lambda cfg: _presence(cfg, r'service timestamps log datetime localtime', what='`service timestamps log datetime localtime`'),
    'V-220599': lambda cfg: _presence(cfg, r'logging buffered \d+', what='a `logging buffered <size> ...` line'),
    'V-220612': lambda cfg: _all_of(cfg, [
        ('login on-failure log', r'login on-failure log'),
        ('login on-success log', r'login on-success log'),
    ]),
    'V-220576': _login_block_check,
    'V-220625': lambda cfg: _presence(cfg, r'^mls qos\s*$', re.M, what='`mls qos`'),
    'V-220604': lambda cfg: _presence(cfg, r'snmp-server group \S+ v3 (auth|priv)', what='an `snmp-server group <name> v3 auth` or `v3 priv` line'),
    'V-220605': lambda cfg: _presence(cfg, r'snmp-server group \S+ v3 priv', what='an `snmp-server group <name> v3 priv` line'),
    'V-220577': lambda cfg: _presence(cfg, r'banner (login|motd)', what='a `banner login` or `banner motd`'),
    'V-220589': lambda cfg: _presence(cfg, r'security passwords min-length (1[5-9]|[2-9]\d)', what='`security passwords min-length` of 15+'),
    'V-220595': lambda cfg: _all_of(cfg, [
        ('service password-encryption', r'^\s*service password-encryption\s*$'),
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

# Discover genuine user VLANs (excludes management/servers/unused VLANs from
# inventory.yaml's non_user_vlans) so V-220633/V-220635 can verify DHCP
# snooping/DAI actually cover them, not just that some VLAN list exists. Also
# discovers the live STP root port(s) for V-220629 (Root Guard must never be
# checked/pushed there), and the live VTP password for V-220624 (never appears
# in running-config, see _vtp_password_check). Uses a separate connection
# since run_stig_audit manages its own for running-config.
vlan_discovery_connect = netauto.connect(device_name, device_info, username, password)
if vlan_discovery_connect is None:
    raise SystemExit(1)
user_vlans = stig_common.discover_user_vlans(vlan_discovery_connect, exclude=netauto.load_non_user_vlans())
root_ports = stig_common.discover_root_port_interfaces(vlan_discovery_connect)
vtp_password_output = str(vlan_discovery_connect.send_command('show vtp password'))
vlan_discovery_connect.disconnect()

CHECKS['V-220633'] = lambda cfg: _dhcp_snooping_check(cfg, user_vlans)
CHECKS['V-220635'] = lambda cfg: _vlan_range_covers_user_vlans(
    cfg, r'ip arp inspection vlan (\S+)', user_vlans, 'an `ip arp inspection vlan <list>` line'
)
CHECKS['V-220629'] = lambda cfg: _root_guard_check(cfg, root_ports)
CHECKS['V-220624'] = lambda cfg: _vtp_password_check(vtp_password_output)

stig_common.run_stig_audit(
    device_name, device_info, CHECKLIST_PATH, CHECKS,
    title='STIG audit',
    username=username, password=password,
)
