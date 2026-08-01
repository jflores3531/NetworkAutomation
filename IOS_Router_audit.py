#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco IOS Router NDM/RTR
STIG rules in New IOS Router Checklist.cklb, reporting PASS/FAIL for the
rules that can be checked from config text alone."""

import argparse
import ipaddress
import re
import netauto
import stig_common

CHECKLIST_PATH = 'New IOS Router Checklist.cklb'


def aux_port_disabled(cfg):
    """V-216571: 'line aux 0' block must contain 'no exec'."""
    match = re.search(r'line aux 0\n((?:.*\n)*?)(?=line |\Z)', cfg)
    return bool(match) and 'no exec' in match.group(1)


def _line_exec_timeout_ok(chunk):
    """True if `chunk` (a `line ...` block) has a compliant exec-timeout
    (nonzero, <=5 min). Returns (ok, matched_text_or_None)."""
    m = re.search(r'exec-timeout (\d+) (\d+)', chunk)
    if not m:
        return False, None
    minutes, seconds = int(m.group(1)), int(m.group(2))
    ok = not (minutes == 0 and seconds == 0) and minutes <= 5
    return ok, m.group(0)


def _http_timeout_ok(cfg):
    """Part of V-215688: the check text's own example includes `ip http
    timeout-policy` alongside line con/vty, since an enabled HTTP(S) management
    server is itself a device-management network connection covered by 'all
    network connections associated with a device management'. If neither `ip
    http server` nor `ip http secure-server` is enabled there's no HTTP
    management connection to time out, so there's nothing to check."""
    if not re.search(r'^ip http server\s*$', cfg, re.M) and not re.search(r'^ip http secure-server\s*$', cfg, re.M):
        return True, None
    m = re.search(r'ip http timeout-policy idle (\d+)', cfg)
    if not m:
        return False, 'HTTP(S) server enabled but no `ip http timeout-policy idle ...` set'
    idle = int(m.group(1))
    if idle <= 300:
        return True, m.group(0)
    return False, f'`{m.group(0)}` exceeds 300 seconds (5 min)'


def _exec_timeout_reason(cfg):
    """V-215688: stig_common.exec_timeout_ok() checks whatever exec-timeout
    lines happen to be present anywhere in cfg, so it silently false-passes if
    one required scope (most commonly console, since IOS never prints an unset
    line at its own default) is left unconfigured as long some other line is
    already compliant. Checks console, vty, and (per the check text's own
    example) the HTTP timeout-policy as separate, required scopes instead.
    ALL vty blocks must be individually compliant, not just one."""
    con_ok = con_match = None
    vty_results = []
    for chunk in re.split(r'^(?=line \S)', cfg, flags=re.M):
        header = chunk.splitlines()[0] if chunk else ''
        if header.startswith('line con'):
            con_ok, con_match = _line_exec_timeout_ok(chunk)
        elif header.startswith('line vty'):
            ok, match = _line_exec_timeout_ok(chunk)
            vty_results.append((header.strip(), ok, match))

    vty_ok = bool(vty_results) and all(ok for _, ok, _ in vty_results)
    http_ok, http_match = _http_timeout_ok(cfg)

    if con_ok and vty_ok and http_ok:
        vty_summary = ', '.join(f'{h} (`{m}`)' for h, _, m in vty_results)
        http_summary = f', HTTP (`{http_match}`)' if http_match else ''
        return True, f'compliant on console (`{con_match}`) and vty: {vty_summary}{http_summary}'

    missing = []
    if not con_ok:
        missing.append('console (`line con 0`): ' + (f'non-compliant (`{con_match}`)' if con_match else 'no exec-timeout set'))
    if not vty_ok:
        if not vty_results:
            missing.append('vty: no `line vty` block found')
        else:
            bad = [f'{h}: ' + (f'non-compliant (`{m}`)' if m else 'no exec-timeout set') for h, ok, m in vty_results if not ok]
            missing.append('vty: ' + '; '.join(bad))
    if not http_ok:
        missing.append(http_match)
    return False, '; '.join(missing)


def _ntp_auth_check(cfg):
    """V-215698: Check Text's own note - "Cisco IOS is limited to MD5 for NTP
    authentication, and incurs a permanent finding as it is not FIPS
    compliant" - means this can never PASS regardless of config. Still reports
    whether every configured NTP server is actually authenticated (the old
    check only confirmed ONE server via re.search, not all of them) as
    context on the best-available mitigation."""
    servers = set(re.findall(r'^ntp server (\S+)', cfg, re.M))
    servers_with_key = set(re.findall(r'^ntp server (\S+) key \d+', cfg, re.M))
    key_ids_authenticated = set(re.findall(r'ntp authentication-key (\d+) md5 \S+', cfg))
    key_ids_trusted = set(re.findall(r'ntp trusted-key (\d+)', cfg))
    key_ids_used = set(re.findall(r'ntp server \S+ key (\d+)', cfg, re.M))
    correlated = key_ids_authenticated & key_ids_trusted & key_ids_used

    if 'ntp authenticate' in cfg and correlated and servers and servers == servers_with_key:
        mitigation = (
            'MD5-based NTP authentication is configured as the best available mitigation - all '
            f'{len(servers)} configured server(s) authenticated with key id(s) {", ".join(sorted(correlated))}'
        )
    elif servers - servers_with_key:
        mitigation = f'not all configured NTP servers are authenticated (missing key on: {", ".join(sorted(servers - servers_with_key))})'
    else:
        mitigation = 'MD5-based NTP authentication is not fully configured (missing `ntp authenticate`, or no key id is consistently used across the authentication-key/trusted-key/server lines)'

    return False, (
        'permanent finding on IOS - Check Text: "Cisco IOS is limited to MD5 for NTP authentication, '
        f'and incurs a permanent finding as it is not FIPS compliant." {mitigation}.'
    )


def _cdp_check(cfg):
    """V-216585: 'no cdp enable' appearing anywhere in cfg only proves CDP is
    disabled on at least one interface, not on every external interface - the
    check text's last sentence ("If CDP is enabled on any external interface,
    this is a finding") requires all of them. Config text alone can't identify
    which interfaces are 'external' (that's topology context), so the only
    condition this can verify unambiguously is the global disable, which is
    also the only remediation IOS_Router_stig_harden_global.py actually pushes."""
    if 'no cdp run' in cfg:
        return True, 'CDP disabled globally: `no cdp run`'
    return False, (
        'CDP not disabled globally (no `no cdp run`); a per-interface `no cdp enable` on some interfaces '
        'cannot be verified from config alone to cover every external interface'
    )


def _ssh_algorithm_fips_check(cfg, algo_type, required_substring, algo_desc):
    """V-215699/700 SSH portions: the old regex (`algorithm mac\\s+\\S*hmac-sha2`
    / `algorithm encryption\\s+\\S*aes`) is only anchored to the FIRST
    space-separated algorithm token after `algorithm <type>` - a compliant
    algorithm listed second or later (e.g. `hmac-sha1 hmac-sha2-256`, kept for
    legacy compatibility) false-failed even though the check text only
    requires the FIPS-validated algorithm be present, not first."""
    if 'ip ssh version 2' not in cfg:
        return False, 'missing `ip ssh version 2`'
    m = re.search(rf'^ip ssh server algorithm {algo_type}\s+(.+)$', cfg, re.M)
    if not m:
        return False, f'missing `ip ssh server algorithm {algo_type} ...`'
    algos = m.group(1).strip()
    if required_substring in algos:
        return True, f'`ip ssh version 2` + FIPS-validated {algo_desc}: `ip ssh server algorithm {algo_type} {algos}`'
    return False, f'`ip ssh server algorithm {algo_type} {algos}` does not include a FIPS-validated ({required_substring}) algorithm'


def _confidentiality_check(cfg):
    """V-215700: Check Content presents SSH and HTTPS as two separate,
    alternative examples (not an AND) for protecting confidentiality of
    remote maintenance sessions - the old check only ever looked at the SSH
    encryption-algorithm line (with the same tight-adjacency regex bug as
    V-215699) and ignored the HTTPS path entirely, false-failing a router
    that secures remote management via HTTPS with a FIPS-approved (AES-based)
    cipher suite instead of/in addition to SSH."""
    ssh_ok, ssh_detail = _ssh_algorithm_fips_check(cfg, 'encryption', 'aes', 'encryption algorithm')
    if ssh_ok:
        return True, ssh_detail

    if not re.search(r'^ip http secure-server\s*$', cfg, re.M):
        return False, f'SSH: {ssh_detail}; HTTPS: `ip http secure-server` not enabled'
    m = re.search(r'^ip http secure-ciphersuite\s+(.+)$', cfg, re.M)
    if m and 'aes' in m.group(1):
        return True, f'HTTPS with FIPS-approved cipher suite: `{m.group(0).strip()}`'
    https_detail = f'`{m.group(0).strip()}` does not include a FIPS-approved (aes) cipher' if m else 'no `ip http secure-ciphersuite` set'
    return False, f'SSH: {ssh_detail}; HTTPS: {https_detail}'


# V-215681: password minimum length lives inside an `aaa common-criteria
# policy` block - checking the pattern anywhere in cfg (old behavior) could
# match a stale/leftover policy block never actually applied to any account.
# Requires there be exactly one policy block, same reasoning as L2S's
# _cc_policy_check (L2_stig_audit.py) for the analogous L2S rules.
def _cc_policy_check(cfg, pattern, min_value, what):
    if not re.search(r'^aaa new-model\s*$', cfg, re.M):
        return False, 'missing `aaa new-model`'
    policy_blocks = [chunk for chunk in re.split(r'^(?=\S)', cfg, flags=re.M) if chunk.startswith('aaa common-criteria policy')]
    if not policy_blocks:
        return False, 'no `aaa common-criteria policy` block found'
    if len(policy_blocks) > 1:
        names = [c.split()[3] if len(c.split()) > 3 else '?' for c in policy_blocks]
        return False, f'{len(policy_blocks)} `aaa common-criteria policy` blocks found ({", ".join(names)}) - ambiguous which one is actually applied'
    chunk = policy_blocks[0]
    m = re.search(pattern, chunk, re.M)
    if m and int(m.group(1)) >= min_value:
        return True, f'found: `{m.group(0).strip()}`'
    return False, f'the single `aaa common-criteria policy` block does not have {what} >= {min_value}'


def _presence(cfg, pattern, flags=0, what=None):
    """PASS if pattern is found; reason shows the matched line, or what was
    searched for if it wasn't. Ported from L2_stig_audit.py."""
    m = re.search(pattern, cfg, flags)
    label = what or f'a line matching `{pattern}`'
    if m:
        return True, f'found: `{m.group(0).strip()}`'
    return False, f'not found — searched for {label}'


def _all_of(cfg, conditions):
    """conditions: list of (label, pattern), each tested with re.search(pattern,
    cfg, re.M). PASS only if all match; reason lists what's missing/present.
    Ported from L2_stig_audit.py."""
    missing, present = [], []
    for label, pattern in conditions:
        (present if re.search(pattern, cfg, re.M) else missing).append(label)
    if missing:
        detail = f"missing: {', '.join(missing)}"
        if present:
            detail += f' (have: {", ".join(present)})'
        return False, detail
    return True, f"all present: {', '.join(present)}"


# V-215678: presence of any of these directives (not "no "-prefixed) is a
# finding — unnecessary/nonsecure services that should stay disabled by
# default. Same exact command list as L2S's V-220586 (UNNECESSARY_SERVICES_PATTERN
# in L2_stig_audit.py) - the check/fix text is identical between the two
# checklists for this rule.
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


# V-215662: concurrent management sessions limited via either ip http
# max-connections or line vty session-limit (either is sufficient per DISA's
# check text). Ported from L2_stig_audit.py's _session_limit_check.
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


# V-215668: exactly 3 consecutive invalid attempts, blocked for >= 900s (15
# min). Ported from L2_stig_audit.py's _login_block_check.
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


# V-220136: check/fix text's own example uses the legacy bare `logging
# x.x.x.x` form (IOS normalizes this to `logging host <ip>` in running-config
# on most releases, but this matches either). Anchored to a literal IPv4
# address so it can't accidentally match an unrelated `logging <keyword>`
# line (buffered/trap/synchronous/persistent/userinfo/etc.).
def _syslog_redundancy_check(cfg):
    servers = sorted(set(re.findall(r'^logging (?:host )?(\d{1,3}(?:\.\d{1,3}){3})\s*$', cfg, re.M)))
    if len(servers) >= 2:
        return True, f'found {len(servers)} syslog server(s): {", ".join(servers)}'
    if servers:
        return False, f'only {len(servers)} of 2+ required syslog server(s) found: {", ".join(servers)}'
    return False, 'no syslog servers found (`logging <ip>` / `logging host <ip>`)'


# V-215709: at least two RADIUS servers, actually used as the primary auth
# source for administrative access (not just configured but unused). Checks
# both the classic single-line 'radius-server host <ip>' form (used in the
# check/fix text's own example) and the modern block-style 'radius server
# <name>' / 'address ipv4 <ip> ...' form, same as L2S/NX-OS's equivalent
# check - which syntax a given platform/image accepts varies (see
# project memory on vios_l2 only accepting the modern form).
def _radius_redundancy_check(cfg):
    if not re.search(r'^aaa new-model\s*$', cfg, re.M):
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
    return False, 'no RADIUS servers configured (classic `radius-server host` or modern `radius server <name>` block)'


# V-215670/V-215672/V-215691/V-215692's shared evidence: an `archive` block
# with `log config`/`logging enable` sub-commands. Ported from
# L2_stig_audit.py's _archive_logging_enabled/_admin_activity_logged.
def _archive_logging_enabled(cfg):
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith('archive'):
            missing = [c for c in ('log config', 'logging enable') if c not in chunk]
            if missing:
                return False, f'`archive` block present but missing: {", ".join(missing)}'
            return True, 'found: `archive` / `log config` / `logging enable`'
    return False, 'missing `archive` block (with `log config` / `logging enable`)'


# V-215670: administrator activity logging — logging userinfo (privilege
# escalation) plus the same archive block above.
def _admin_activity_logged(cfg):
    if not re.search(r'^logging userinfo\s*$', cfg, re.M):
        return False, 'missing `logging userinfo`'
    archive_ok, archive_reason = _archive_logging_enabled(cfg)
    if not archive_ok:
        return False, f'`logging userinfo` present, but {archive_reason}'
    return True, f'found: `logging userinfo`, {archive_reason}'


_SYSLOG_SEVERITY_RANK = {
    'emergencies': 0, 'alerts': 1, 'critical': 2, 'errors': 3,
    'warnings': 4, 'notifications': 5, 'informational': 6, 'debugging': 7,
}


# V-215692: check text's own note - "informational is the default severity
# level; hence, if the severity level is configured to informational, the
# logging trap command will not be shown in the configuration" - so an
# absent `logging trap` line is compliant (defaults to informational, which
# is broader/more inclusive than the required "critical" minimum), not a
# finding. Ported from L2_stig_audit.py/NXOS_stig_audit.py's
# _logging_trap_check.
def _logging_trap_check(cfg):
    m = re.search(r'^logging trap (\S+)', cfg, re.M)
    if not m:
        return True, 'no explicit `logging trap <level>` line - defaults to `informational`, which satisfies this (broader than the required `critical` minimum)'
    level = m.group(1).lower()
    rank = _SYSLOG_SEVERITY_RANK.get(level)
    if rank is None:
        return False, f'found `logging trap {level}` but unrecognized severity level'
    if rank < _SYSLOG_SEVERITY_RANK['critical']:
        return False, f'found `logging trap {level}` - narrower than the required `critical` minimum (misses errors/warnings/notifications/informational events)'
    return True, f'found: `logging trap {level}`'


# V-215675/676/677: protect audit info from unauthorized modification/
# deletion, and limit privileges to change software libraries - DISA reuses
# the same evidence (file privilege 15) for all three, and all three are
# explicitly conditional in the check text: "If persistent logging is
# enabled ... Otherwise, this requirement is not applicable." No `logging
# persistent` line means PASS (not a finding), not FAIL. Ported from
# L2_stig_audit.py's _audit_info_protection_check.
def _audit_info_protection_check(cfg):
    if not re.search(r'^logging persistent', cfg, re.M):
        return True, 'persistent logging not configured - not applicable per DISA (only required when `logging persistent` is enabled)'
    if re.search(r'^file privilege 15', cfg, re.M):
        return True, 'persistent logging enabled and `file privilege 15` present'
    return False, 'persistent logging enabled but missing `file privilege 15` (required to restrict file-system access once persistent logging is on)'


# V-215667: vty access-class ACL must actually be scoped to the management
# subnet, not just present. A "permit any" or out-of-subnet source doesn't
# satisfy "controlling the flow of management information." Ported from
# L2_stig_audit.py's _acl_source_in_subnet/_vty_acl_blocks/_vty_management_acl_check
# (V-220575's equivalent) - IOS Router's own check text uses the identical
# `permit ip x.x.x.0 0.0.0.255 any` / `deny ip any any log-input` example.
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


def _vty_acl_blocks(cfg):
    """Return a list of (line_vty_chunk, acl_name_or_None, acl_block_or_None)
    for EVERY 'line vty ...' stanza in the config - handles split vty ranges
    (e.g. 'line vty 0 1' / 'line vty 2 4')."""
    results = []
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if not chunk.startswith('line vty'):
            continue
        m = re.search(r'access-class (\S+) in', chunk)
        acl_name = m.group(1) if m else None
        acl_block = None
        if acl_name:
            for c2 in re.split(r'^(?=\S)', cfg, flags=re.M):
                if c2.startswith(f'ip access-list extended {acl_name}'):
                    acl_block = c2
                    break
        results.append((chunk, acl_name, acl_block))
    return results


def _vty_management_acl_check(cfg, subnet_str):
    if not subnet_str:
        return False, 'no `management_subnet` configured in inventory.yaml'
    subnet = ipaddress.ip_network(subnet_str, strict=False)

    vty_blocks = _vty_acl_blocks(cfg)
    if not vty_blocks:
        return False, 'no `line vty` block found'

    problems, compliant = [], []
    for chunk, acl_name, acl_block in vty_blocks:
        header = chunk.splitlines()[0].strip()
        if not acl_name:
            problems.append(f'{header}: no `access-class <name> in` applied')
            continue
        if acl_block is None:
            problems.append(f'{header}: `access-class {acl_name} in` applied, but no `ip access-list extended {acl_name}` block found')
            continue
        permits = re.findall(r'^\s*(?:\d+\s+)?permit ip (.+?)\s+any\s*$', acl_block, re.M)
        if not permits:
            problems.append(f'{header}: `{acl_name}` has no `permit ip <source> any` lines')
            continue
        bad = [src for src in permits if not _acl_source_in_subnet(src, subnet)]
        if bad:
            problems.append(f'{header}: `{acl_name}` permits source(s) outside {subnet_str}: {", ".join(bad)}')
            continue
        compliant.append(f'{header}: `{acl_name}` permits only sources within {subnet_str}: {", ".join(permits)}')
    if problems:
        return False, '; '.join(problems)
    return True, '; '.join(compliant)


# V-216559: 'boot network'/'service config' (classic auto-config
# auto-loading) or any CNS zero-touch command being present is the finding
# condition - 'boot network'/'service config' overlap V-215678's
# unnecessary-services list (checked again here since this is a distinct
# rule ID with its own evidence requirement).
def _zero_touch_check(cfg):
    found = []
    if re.search(r'^boot network', cfg, re.M):
        found.append('boot network')
    if re.search(r'^service config\s*$', cfg, re.M):
        found.append('service config')
    for cmd in ('cns trusted-server config', 'cns trusted-server image', 'cns config initial', 'cns exec', 'cns image'):
        if re.search(rf'^{re.escape(cmd)}', cfg, re.M):
            found.append(cmd)
    if found:
        return False, f'auto-configuration/zero-touch deployment feature(s) enabled: {", ".join(found)}'
    return True, 'no auto-configuration or CNS zero-touch deployment features found enabled'


# V-216602: Cisco IOS enforces the first-AS check by default; only a finding
# if 'no bgp enforce-first-as' has been explicitly configured to turn it
# off. Not applicable if the device doesn't run BGP at all - the rule (and
# its title) are scoped to BGP routers.
def _bgp_enforce_first_as_check(cfg):
    m = re.search(r'^router bgp \S+\n((?:.*\n)*?)(?=router |\Z)', cfg, re.M)
    if not m:
        return None, 'no `router bgp` block found - not a BGP router'
    if re.search(r'^\s*no bgp enforce-first-as\s*$', m.group(1), re.M):
        return False, 'first-AS enforcement explicitly disabled: `no bgp enforce-first-as`'
    return True, 'first-AS enforcement is enabled by default (no `no bgp enforce-first-as` override found)'


# V-230041: FEC0::/10 (Site-Local Unicast, deprecated by RFC 3879) must not
# be assigned to any interface. FEC0::/10 covers hex prefixes fec0-feff.
def _ipv6_site_local_check(cfg):
    m = re.search(r'ipv6 address (fe[c-f][0-9a-fA-F]\S*)', cfg, re.I)
    if m:
        return False, f'IPv6 Site-Local address found: `{m.group(0).strip()}`'
    return True, 'no IPv6 Site-Local (FEC0::/10) addresses found'


# V-216607: routers use their loopback for LDP peering by default (check
# text's own words: "By default, routers will use its loopback address for
# LDP peering") - only a finding if `mpls ldp router-id` is explicitly set
# to something other than a loopback interface.
def _mpls_ldp_router_id_check(cfg):
    m = re.search(r'^mpls ldp router-id (\S+)', cfg, re.M)
    if not m:
        return True, 'no `mpls ldp router-id` override - loopback is used by default'
    iface = m.group(1)
    if iface.lower().startswith(('loopback', 'lo')):
        return True, f'`mpls ldp router-id {iface}` - a loopback interface'
    return False, f'`mpls ldp router-id {iface}` overrides the default with a non-loopback interface'


# V-216608: check text says to "review the router OSPF or IS-IS
# configuration" - only applicable if the router actually runs one of those
# protocols.
def _mpls_ldp_sync_check(cfg):
    blocks = [c for c in re.split(r'^(?=\S)', cfg, flags=re.M) if c.startswith('router ospf') or c.startswith('router isis')]
    if not blocks:
        return None, 'no `router ospf` or `router isis` block found - not applicable'
    missing = [c.splitlines()[0].strip() for c in blocks if 'mpls ldp sync' not in c]
    if missing:
        return False, f'`mpls ldp sync` missing under: {", ".join(missing)}'
    return True, '`mpls ldp sync` present under all configured OSPF/IS-IS process(es)'


# V-216609: check text's own Step 1 gates Step 2 on this - "Determine if
# MPLS TE is enabled globally and at least one interface... If MPLS TE is
# enabled, verify that message pacing is enabled."
def _rsvp_message_pacing_check(cfg):
    if not re.search(r'^mpls traffic-eng tunnels\s*$', cfg, re.M):
        return None, 'MPLS TE (`mpls traffic-eng tunnels`) not enabled - not applicable'
    if re.search(r'^\s*ip rsvp signaling rate-limit', cfg, re.M):
        return True, 'MPLS TE enabled with RSVP message pacing configured (`ip rsvp signaling rate-limit ...`)'
    return False, 'MPLS TE enabled but no `ip rsvp signaling rate-limit ...` (message pacing) found'


# Regex/keyword checks for rules that can be verified directly from running-config
# text. Most RTR rules describe perimeter/BGP/MPLS/multicast topology and policy
# decisions (authorized sources, AS numbers, site address space, etc.) that can't
# be verified from a single device's config alone, so only the generically
# checkable ones are covered here. The rest are reported as NOT AUTOMATED.
CHECKS = {
    # --- NDM (Network Device Management) ---
    'V-215669': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-215681': lambda cfg: _cc_policy_check(cfg, r'^\s*min-length (\d+)', 15, '`min-length <n>`'),
    'V-215687': lambda cfg: bool(re.search(r'^service password-encryption\s*$', cfg, re.M)),
    'V-215688': _exec_timeout_reason,
    'V-215699': lambda cfg: _ssh_algorithm_fips_check(cfg, 'mac', 'hmac-sha2', 'MAC (HMAC integrity)'),
    'V-215700': _confidentiality_check,
    'V-215693': lambda cfg: len(set(re.findall(r'^ntp server (\S+)', cfg, re.M))) >= 2,
    'V-215698': _ntp_auth_check,
    'V-215682': lambda cfg: _cc_policy_check(cfg, r'^\s*upper-case (\d+)', 1, '`upper-case <n>`'),
    'V-215683': lambda cfg: _cc_policy_check(cfg, r'^\s*lower-case (\d+)', 1, '`lower-case <n>`'),
    'V-215684': lambda cfg: _cc_policy_check(cfg, r'^\s*numeric-count (\d+)', 1, '`numeric-count <n>`'),
    'V-215685': lambda cfg: _cc_policy_check(cfg, r'^\s*special-case (\d+)', 1, '`special-case <n>`'),
    'V-215686': lambda cfg: _cc_policy_check(cfg, r'^\s*char-changes (\d+)', 8, '`char-changes <n>`'),
    'V-215678': _no_unnecessary_services,
    'V-220136': _syslog_redundancy_check,
    'V-215709': _radius_redundancy_check,
    'V-215662': _session_limit_check,
    'V-215668': _login_block_check,
    'V-215704': lambda cfg: _all_of(cfg, [
        ('login on-failure log', r'^login on-failure log\s*$'),
        ('login on-success log', r'^login on-success log\s*$'),
    ]),
    'V-215691': lambda cfg: _presence(cfg, r'^logging buffered \d+', re.M, what='a `logging buffered <size> ...` line'),
    'V-215692': _logging_trap_check,
    'V-215672': lambda cfg: _presence(cfg, r'^service timestamps log datetime', re.M, what='a `service timestamps log datetime ...` line'),
    'V-215670': _admin_activity_logged,
    'V-215675': _audit_info_protection_check,
    'V-215676': _audit_info_protection_check,
    'V-215677': _audit_info_protection_check,
    'V-215667': lambda cfg: _vty_management_acl_check(cfg, netauto.load_management_subnet()),
    'V-216559': _zero_touch_check,
    'V-216602': _bgp_enforce_first_as_check,
    'V-216610': lambda cfg: _presence(cfg, r'^no mpls ip propagate-ttl\s*$', re.M, what='`no mpls ip propagate-ttl`'),
    'V-216993': lambda cfg: _presence(cfg, r'^ip options drop\s*$', re.M, what='`ip options drop`'),
    'V-230041': _ipv6_site_local_check,
    'V-216607': _mpls_ldp_router_id_check,
    'V-216608': _mpls_ldp_sync_check,
    'V-216609': _rsvp_message_pacing_check,

    # --- RTR (Router) ---
    # V-216564/565/566/567/584/586 (directed broadcast, ICMP unreachables/mask-reply/
    # redirects, LLDP transmit, proxy ARP) are per-interface commands: finding the
    # "no ip ..." string anywhere in the config doesn't mean every interface has it,
    # so they're deliberately left out and reported as NOT AUTOMATED (same reasoning
    # IOS_Router_stig_harden_global.py already uses to skip them as needing interface targeting).
    'V-216563': lambda cfg: 'no ip gratuitous-arps' in cfg,
    'V-216571': aux_port_disabled,
    'V-216585': _cdp_check,
    # 'no ip cef' as a bare substring also matches inside 'no ip cef distributed'
    # (a real IOS command that disables only *distributed* CEF on modular
    # platforms, leaving regular CEF switching enabled) - anchored to the
    # whole line so that doesn't false-fail a device using centralized CEF.
    'V-229030': lambda cfg: not bool(re.search(r'^no ip cef\s*$', cfg, re.M)),
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
