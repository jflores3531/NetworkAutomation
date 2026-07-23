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


def load_non_user_vlans(path='inventory.yaml'):
    """Load the non_user_vlans list from the YAML inventory — VLAN IDs to exclude
    when discovering "user VLANs" for DHCP snooping/DAI pushes (management,
    servers, unused default VLAN, etc). Returns an empty list if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('non_user_vlans', [])


def load_management_subnet(path='inventory.yaml'):
    """Load the management_subnet string (e.g. '10.10.50.0/24') from the YAML
    inventory, used to verify vty access-class ACLs are actually scoped to the
    management network (V-220575). Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('management_subnet')


def load_automation_host(path='inventory.yaml'):
    """Load the automation_host IP from the YAML inventory - the sole
    permitted source for V-220575's vty ACL (L2_stig_harden_acl.py). Returns
    None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('automation_host')


def load_unused_vlan(path='inventory.yaml'):
    """Load the unused_vlan ID from the YAML inventory — the VLAN designated for
    disabled/unused ports (V-220641). Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('unused_vlan')


def load_vtp_domain(path='inventory.yaml'):
    """Load the vtp_domain name from the YAML inventory — required on NX-OS
    before a VTP password can be set (V-220676); 'vtp password' is rejected
    with "Domain not set" without one first, confirmed live on NXCore1.
    Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('vtp_domain')


def load_native_vlan(path='inventory.yaml'):
    """Load the native_vlan ID from the YAML inventory — the VLAN to assign as
    native on 802.1q trunk links (V-220646). Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('native_vlan')


def load_default_access_vlan(path='inventory.yaml'):
    """Load the default_access_vlan ID from the YAML inventory — the VLAN
    assigned to host-facing/access ports that aren't already in trunk mode.
    Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('default_access_vlan')


def load_secrets(path='secrets.yaml'):
    """Load plaintext secrets used by the *_stig_harden.py scripts (VTP password,
    NTP auth key, etc.) from secrets.yaml - gitignored, never committed. Returns
    an empty dict if the file doesn't exist (see secrets.yaml.example)."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


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
    """Connect to a device from the inventory, escalating to privileged EXEC
    with secrets.yaml's enable_secret if one is set. Needed now that AAA
    governs login on devices with 'aaa new-model' active - a local account's
    privilege 15 stopped being honored automatically on login once that was
    pushed, landing SSH sessions at user EXEC instead. .enable() is a no-op if
    the session is already privileged, so this is safe to call unconditionally
    against devices that don't have AAA active yet too. Returns the Netmiko
    connection, or None (after printing why) if the connection or enable
    escalation failed."""
    print('Connecting to device: ' + device_name)
    enable_secret = str(load_secrets().get('enable_secret') or '').strip()
    ios_device = {
        'device_type': device_info['device_type'],
        'ip': device_info['host'],
        'username': username,
        'password': password,
        # Netmiko's ~10s default conn_timeout is shorter than IOS's own AAA
        # login can take when a RADIUS server is unreachable (login
        # authentication falls through radius -> local *during* the SSH
        # password exchange, not after it) - confirmed live as a ~30s login
        # delay that made valid credentials look like a connection failure.
        # L2_stig_harden_aaa.py tightens RADIUS timeout/retransmit to keep
        # that fallback short, but this stays generous as a safety margin.
        'conn_timeout': 60,
        'auth_timeout': 60,
        'banner_timeout': 60,
    }
    if enable_secret:
        ios_device['secret'] = enable_secret

    try:
        net_connect = ConnectHandler(**ios_device)
    except NetmikoAuthenticationException:
        print('Authentication failure: ' + device_name)
        return None
    except NetmikoTimeoutException:
        print('Timeout to device: ' + device_name)
        return None
    except EOFError:
        print('End of file while attempting device ' + device_name)
        return None
    except SSHException:
        print('SSH Issue. Are you sure SSH is enabled? ' + device_name)
        return None
    except Exception as unknown_error:
        print('Some other error: ' + str(unknown_error))
        return None

    if enable_secret:
        try:
            net_connect.enable()
        except Exception as enable_error:
            print(f'Failed to reach privileged EXEC on {device_name}: {enable_error}')
            net_connect.disconnect()
            return None

    return net_connect


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
