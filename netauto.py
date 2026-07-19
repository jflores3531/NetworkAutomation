#!/usr/bin/env python
"""Shared helpers for connecting to devices in inventory.yaml: inventory loading,
device-name validation, credential prompting, and Netmiko SSH connection handling."""

import json
from getpass import getpass

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def load_inventory(path='inventory.yaml'):
    """Load the devices section of the YAML inventory (name -> {host, device_type})."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory['devices']


def get_credentials():
    """Prompt for the SSH username/password used to connect to devices."""
    username = input('Enter your SSH username: ')
    password = getpass()
    return username, password


def require_devices(all_devices, device_names):
    """Look up device_names in all_devices, exiting with an error if any are unknown."""
    unknown = [name for name in device_names if name not in all_devices]
    if unknown:
        print(f'Device(s) not found in inventory.yaml: {", ".join(unknown)}')
        raise SystemExit(1)
    return {name: all_devices[name] for name in device_names}


def connect(device_name, device_info, username, password):
    """Connect to a device from the inventory. Returns the Netmiko connection,
    or None (after printing why) if the connection failed."""
    print('Connecting to device: ' + device_name)
    ios_device = {
        'device_type': device_info['device_type'],
        'ip': device_info['host'],
        'username': username,
        'password': password
    }

    try:
        return ConnectHandler(**ios_device)
    except NetmikoAuthenticationException:
        print('Authentication failure: ' + device_name)
    except NetmikoTimeoutException:
        print('Timeout to device: ' + device_name)
    except EOFError:
        print('End of file while attempting device ' + device_name)
    except SSHException:
        print('SSH Issue. Are you sure SSH is enabled? ' + device_name)
    except Exception as unknown_error:
        print('Some other error: ' + str(unknown_error))

    return None


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

    net_connect = connect(device_name, device_info, username, password)
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
