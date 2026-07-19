#!/usr/bin/env python
"""Shared STIG audit runner used by IOS_Router_audit.py, L2_stig_audit.py, and
NXOS_stig_audit.py: loads a DISA .cklb checklist, checks a device's
running-config against it, and prints a PASS/FAIL/NOT AUTOMATED report."""

import json

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
