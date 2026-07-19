#!/usr/bin/env python
"""Check the operational health of devices in inventory.yaml.

For each device, reports:
  - Reachability      — did the SSH connection succeed?
  - Interface health  — any interfaces that are down but NOT admin-down?
  - Error counters    — any nonzero input/CRC errors on any interface?
  - CPU utilization   — flagged if over 80% (IOS) or 85% (NX-OS)
  - Optical power     — any fiber transceiver with low Rx power?
  - Default route     — present on IOS routers? (skipped for switches/NX-OS)

Usage:
    # Check all devices in inventory.yaml
    python health_check.py

    # Check one or more specific devices
    python health_check.py R1 S1
"""

import argparse
import re

import netauto

# CPU threshold (%) above which a device is flagged as unhealthy
CPU_WARN_IOS = 80
CPU_WARN_NXOS = 85

# Rx power threshold (dBm) below which an IOS transceiver is flagged as unhealthy.
# IOS's "transceiver detail" output doesn't include per-optic thresholds, so this
# is a conservative generic floor. NX-OS is checked against each optic's own
# low-warning threshold instead, since NX-OS reports it directly.
RX_POWER_WARN_DBM = -15.0

# Device names that should have a default route (routers, not switches)
IOS_ROUTER_NAMES = {'R1', 'R2'}  # add more router names here as your lab grows


# ---------------------------------------------------------------------------
# Per-platform health checks
# ---------------------------------------------------------------------------

def check_ios(device_name, net_connect):
    """Run IOS-specific health checks. Returns a dict of findings."""
    findings = {
        'interfaces_down': [],
        'error_interfaces': [],
        'cpu_pct': None,
        'cpu_flagged': False,
        'optical_low_power': [],
        'default_route': None,
    }

    # --- Interface health: flag line-protocol down but NOT admin-down ---
    iface_brief = net_connect.send_command('show ip interface brief')
    for line in iface_brief.splitlines():
        # Format: Interface   IP-Address   OK?   Method   Status   Protocol
        parts = line.split()
        if len(parts) < 6:
            continue
        iface_name, status, protocol = parts[0], parts[4], parts[5]
        if status == 'administratively' and protocol == 'down':
            continue  # intentionally shut — not a problem
        if protocol == 'down':
            findings['interfaces_down'].append(iface_name)

    # --- Error counters: flag any interface with nonzero input/CRC errors ---
    iface_detail = net_connect.send_command('show interfaces')
    current_iface = None
    for line in iface_detail.splitlines():
        iface_match = re.match(r'^(\S+) is ', line)
        if iface_match:
            current_iface = iface_match.group(1)
        error_match = re.search(r'(\d+) input errors.*?(\d+) CRC', line)
        if error_match and current_iface:
            input_errors = int(error_match.group(1))
            crc_errors = int(error_match.group(2))
            if input_errors > 0 or crc_errors > 0:
                findings['error_interfaces'].append(
                    f'{current_iface} (input errors: {input_errors}, CRC: {crc_errors})'
                )

    # --- CPU utilization ---
    cpu_output = net_connect.send_command('show processes cpu | include CPU utilization')
    cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', cpu_output)
    if cpu_match:
        findings['cpu_pct'] = int(cpu_match.group(1))
        findings['cpu_flagged'] = findings['cpu_pct'] > CPU_WARN_IOS

    # --- Optical power: flag transceivers with Rx power below RX_POWER_WARN_DBM ---
    transceiver_output = net_connect.send_command('show interfaces transceiver detail')
    for line in transceiver_output.splitlines():
        optics_match = re.match(
            r'^(\S+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s*$', line
        )
        if not optics_match:
            continue
        iface, _temp, _voltage, _tx_power, rx_power = optics_match.groups()
        rx_power = float(rx_power)
        if rx_power < RX_POWER_WARN_DBM:
            findings['optical_low_power'].append(f'{iface} (Rx: {rx_power} dBm)')

    # --- Default route (routers only) ---
    if device_name in IOS_ROUTER_NAMES:
        route_output = net_connect.send_command('show ip route 0.0.0.0')
        findings['default_route'] = (
            '0.0.0.0/0' in route_output or 'Gateway of last resort' in route_output
        )

    return findings


def check_nxos(device_name, net_connect):
    """Run NX-OS-specific health checks. Returns a dict of findings."""
    findings = {
        'interfaces_down': [],
        'error_interfaces': [],
        'cpu_pct': None,
        'cpu_flagged': False,
        'optical_low_power': [],
        'default_route': None,  # not checked for NX-OS switches
    }

    # --- Interface health ---
    iface_brief = net_connect.send_command('show interface status')
    for line in iface_brief.splitlines():
        parts = line.split()
        if not parts:
            continue
        iface_name = parts[0]
        if 'disabled' in line.lower():
            continue  # admin-down on NX-OS
        if 'notconnect' in line.lower() or 'sfpAbsent' in line.lower():
            findings['interfaces_down'].append(iface_name)

    # --- Error counters ---
    iface_detail = net_connect.send_command('show interface counters errors')
    current_iface = None
    for line in iface_detail.splitlines():
        parts = line.split()
        if not parts:
            continue
        if re.match(r'^Eth\d+/\d+|^mgmt\d+|^Po\d+', parts[0]):
            current_iface = parts[0]
        elif current_iface and len(parts) >= 2:
            try:
                errors = sum(int(p) for p in parts if p.isdigit())
                if errors > 0:
                    findings['error_interfaces'].append(f'{current_iface} (errors: {errors})')
                    current_iface = None
            except ValueError:
                pass

    # --- CPU utilization ---
    cpu_output = net_connect.send_command('show processes cpu summary')
    cpu_match = re.search(r'(\d+)%\s+(\d+)%\s+(\d+)%', cpu_output)
    if cpu_match:
        findings['cpu_pct'] = int(cpu_match.group(1))
        findings['cpu_flagged'] = findings['cpu_pct'] > CPU_WARN_NXOS

    # --- Optical power: flag transceivers with Rx power at/below their own low-warning threshold ---
    transceiver_output = net_connect.send_command('show interface transceiver details')
    current_iface = None
    for line in transceiver_output.splitlines():
        iface_match = re.match(r'^(Eth\S+|mgmt\S+|Po\S+)', line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue
        rx_match = re.search(
            r'Rx Power\s+(-?[\d.]+)\s*dBm\s+(-?[\d.]+)\s*dBm\s+(-?[\d.]+)\s*dBm\s+'
            r'(-?[\d.]+)\s*dBm\s+(-?[\d.]+)\s*dBm',
            line
        )
        if rx_match and current_iface:
            rx_current = float(rx_match.group(1))
            low_warn = float(rx_match.group(5))
            if rx_current <= low_warn:
                findings['optical_low_power'].append(
                    f'{current_iface} (Rx: {rx_current} dBm, low warn: {low_warn} dBm)'
                )
            current_iface = None

    return findings


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def print_report(results):
    """Print a human-readable health summary for all checked devices."""
    print()
    print('=' * 70)
    print('HEALTH CHECK REPORT')
    print('=' * 70)

    all_healthy = True

    for device_name, result in results.items():
        if not result['reachable']:
            status = 'UNREACHABLE'
            all_healthy = False
        else:
            findings = result['findings']
            flags = []
            if findings['interfaces_down']:
                flags.append(f"interfaces down: {', '.join(findings['interfaces_down'])}")
            if findings['error_interfaces']:
                flags.append(f"errors on: {', '.join(findings['error_interfaces'])}")
            if findings['cpu_flagged']:
                flags.append(f"CPU: {findings['cpu_pct']}%")
            if findings['optical_low_power']:
                flags.append(f"low optical power: {', '.join(findings['optical_low_power'])}")
            if findings.get('default_route') is False:
                flags.append('default route MISSING')

            if flags:
                status = 'FLAGGED'
                all_healthy = False
            else:
                status = 'HEALTHY'

        print(f'\n  {device_name} ({result["host"]})')
        print(f'  Status : {status}')

        if result['reachable'] and result['findings']:
            findings = result['findings']
            if findings['cpu_pct'] is not None:
                print(f'  CPU    : {findings["cpu_pct"]}%')
            if findings['interfaces_down']:
                print(f'  Unexpected down interfaces:')
                for iface in findings['interfaces_down']:
                    print(f'    - {iface}')
            if findings['error_interfaces']:
                print(f'  Interfaces with errors:')
                for iface in findings['error_interfaces']:
                    print(f'    - {iface}')
            if findings['optical_low_power']:
                print(f'  Transceivers with low Rx power:')
                for iface in findings['optical_low_power']:
                    print(f'    - {iface}')
            if findings.get('default_route') is False:
                print(f'  WARNING: Default route not found in routing table')

    print()
    print('=' * 70)
    if all_healthy:
        print('All devices healthy.')
    else:
        print('One or more devices require attention — see above.')
    print('=' * 70)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Check operational health of devices in inventory.yaml'
    )
    parser.add_argument(
        'devices', nargs='*',
        help='Device name(s) to check (e.g. R1 S1). Omit to check all devices.'
    )
    args = parser.parse_args()

    username, password = netauto.get_credentials()
    all_devices = netauto.load_inventory()

    if args.devices:
        devices_to_check = netauto.require_devices(all_devices, args.devices)
    else:
        devices_to_check = all_devices

    results = {}

    for device_name, device_info in devices_to_check.items():
        host = device_info['host']
        device_type = device_info.get('device_type', 'cisco_ios')

        results[device_name] = {'host': host, 'reachable': False, 'findings': None}

        net_connect = netauto.connect(device_name, device_info, username, password)
        if net_connect is None:
            continue

        results[device_name]['reachable'] = True

        if device_type == 'cisco_nxos':
            findings = check_nxos(device_name, net_connect)
        else:
            findings = check_ios(device_name, net_connect)

        net_connect.disconnect()
        results[device_name]['findings'] = findings

    print_report(results)


if __name__ == '__main__':
    main()
