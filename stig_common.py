#!/usr/bin/env python
"""Shared STIG audit runner used by IOS_Router_audit.py, L2_stig_audit.py, and
NXOS_stig_audit.py: loads a DISA .cklb checklist, checks a device's
running-config against it, and prints a PASS/FAIL/NOT AUTOMATED report."""

import json
import re

import netauto

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def run_stig_audit(device_name, device_info, checklist_path, checks, title, username, password,
                    not_automated_note='need manual review or external infrastructure'):
    """Connect to a device, check its running-config against a DISA STIG checklist's
    rules using `checks` (group_id -> predicate(running_config) -> bool), and print
    a PASS/FAIL/NOT AUTOMATED report. Rules with no entry in `checks` are reported
    as NOT AUTOMATED."""
    with open(checklist_path, encoding='utf-8') as f:
        checklist = json.load(f)
    rules = [rule for stig in checklist['stigs'] for rule in stig['rules']]
    rules.sort(key=lambda rule: SEVERITY_ORDER.get(rule['severity'], 99))

    net_connect = netauto.connect(device_name, device_info, username, password)
    if net_connect is None:
        raise SystemExit(1)

    running_config = str(net_connect.send_command('show running-config'))
    net_connect.disconnect()

    results = {'PASS': 0, 'FAIL': 0, 'NOT AUTOMATED': 0}

    print(f'{title} for {device_name}\n')

    for rule in rules:
        group_id = rule['group_id']
        check = checks.get(group_id)

        if check is None:
            status = 'NOT AUTOMATED'
        else:
            status = 'PASS' if check(running_config) else 'FAIL'
        results[status] += 1

        print(f"[{rule['severity'].upper():6}] {status:14} {group_id}  {rule['rule_title']}")

    print(f"\n{results['PASS']} passed, {results['FAIL']} failed, {results['NOT AUTOMATED']} not automated ({not_automated_note}) out of {len(rules)} rules.")


def exec_timeout_ok(cfg, max_minutes=5):
    """True if every exec-timeout line sets a nonzero value no longer than
    max_minutes. 'exec-timeout 0 0' disables the timeout entirely, which is
    non-compliant, not a pass - it's excluded even though its minutes field
    (0) would otherwise be <= max_minutes."""
    matches = re.findall(r'exec-timeout (\d+) (\d+)', cfg)
    if not matches:
        return False
    for minutes, seconds in matches:
        minutes, seconds = int(minutes), int(seconds)
        if minutes == 0 and seconds == 0:
            return False
        if minutes > max_minutes:
            return False
    return True


def discover_user_vlans(net_connect):
    """Return a switch's user VLAN IDs from `show vlan brief`, excluding the
    reserved fddi/token-ring VLAN range (1002-1005)."""
    vlan_brief = str(net_connect.send_command('show vlan brief'))
    return [vid for vid in re.findall(r'^(\d+)\s+\S+', vlan_brief, re.M) if not (1002 <= int(vid) <= 1005)]
