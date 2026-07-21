#!/usr/bin/env python
"""Shared helpers for connecting to devices in inventory.yaml: inventory loading,
device-name validation, credential prompting, and Netmiko SSH connection handling."""

import json
import os
from datetime import datetime
from getpass import getpass

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException

AUDIT_LOG_PATH = os.path.join('audit_logs', 'audit.log')


def load_inventory(path='inventory.yaml'):
    """Load the devices section of the YAML inventory (name -> {host, device_type})."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory['devices']


def load_services(path='inventory.yaml'):
    """Load the services section of the YAML inventory (ntp_servers/syslog_servers/
    radius_servers -> list of IPs). Returns an empty dict if the inventory has no
    services section, so callers can .get(...) with a default."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('services', {})


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


def log_push(script_name, device_name, username, commands):
    """Append a JSON-line audit record for a config push to audit_logs/audit.log."""
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    record = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'script': script_name,
        'device': device_name,
        'username': username,
        'commands': commands,
    }
    with open(AUDIT_LOG_PATH, 'a') as f:
        f.write(json.dumps(record) + '\n')
