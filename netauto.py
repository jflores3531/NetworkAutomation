#!/usr/bin/env python
"""Shared helpers for connecting to devices in inventory.yaml: inventory loading,
device-name validation, credential prompting, and Netmiko SSH connection handling."""

from getpass import getpass

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException


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
