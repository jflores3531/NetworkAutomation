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
    if 'ip http server' not in cfg and 'ip http secure-server' not in cfg:
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
    also the only remediation IOS_Router_stig_harden.py actually pushes."""
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

    if 'ip http secure-server' not in cfg:
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
    if 'aaa new-model' not in cfg:
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


# Regex/keyword checks for rules that can be verified directly from running-config
# text. Most RTR rules describe perimeter/BGP/MPLS/multicast topology and policy
# decisions (authorized sources, AS numbers, site address space, etc.) that can't
# be verified from a single device's config alone, so only the generically
# checkable ones are covered here. The rest are reported as NOT AUTOMATED.
CHECKS = {
    # --- NDM (Network Device Management) ---
    'V-215669': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-215681': lambda cfg: _cc_policy_check(cfg, r'^\s*min-length (\d+)', 15, '`min-length <n>`'),
    'V-215687': lambda cfg: 'service password-encryption' in cfg,
    'V-215688': _exec_timeout_reason,
    'V-215699': lambda cfg: _ssh_algorithm_fips_check(cfg, 'mac', 'hmac-sha2', 'MAC (HMAC integrity)'),
    'V-215700': _confidentiality_check,
    'V-215693': lambda cfg: len(set(re.findall(r'^ntp server (\S+)', cfg, re.M))) >= 2,
    'V-215698': _ntp_auth_check,

    # --- RTR (Router) ---
    # V-216564/565/566/567/584/586 (directed broadcast, ICMP unreachables/mask-reply/
    # redirects, LLDP transmit, proxy ARP) are per-interface commands: finding the
    # "no ip ..." string anywhere in the config doesn't mean every interface has it,
    # so they're deliberately left out and reported as NOT AUTOMATED (same reasoning
    # IOS_Router_stig_harden.py already uses to skip them as needing interface targeting).
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
