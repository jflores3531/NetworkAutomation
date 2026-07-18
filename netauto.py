#!/usr/bin/env python

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException


def load_inventory(path='inventory.yaml'):
    """Load the devices section of the YAML inventory (name -> {host, device_type})."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory['devices']


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
