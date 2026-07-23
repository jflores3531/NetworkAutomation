#!/usr/bin/env python
"""Check the operational health of devices in inventory.yaml.

For each device, reports:
  - Reachability      — did the SSH connection succeed?
  - Interface health  — any interfaces that are down but NOT admin-down?
  - Error counters    — any nonzero input/CRC errors on any interface?
  - CPU utilization   — flagged if over 80% (IOS) or 85% (NX-OS)
  - Optical health    — any fiber transceiver with temp/voltage/Tx/Rx power
                        outside warning range?
  - Environment       — temperature/power/fan warnings from `show environment`
                        (reported as not supported on virtual/emulated platforms)
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

# Generic transceiver DOM warning thresholds used for IOS, whose "transceiver
# detail" output has no per-optic thresholds (typical SFP/SFP+ DDM defaults).
# NX-OS is checked against each optic's own warning thresholds instead, since
# NX-OS reports them directly.
TEMP_LOW_WARN_C = 0.0
TEMP_HIGH_WARN_C = 70.0
VOLTAGE_LOW_WARN_V = 3.13
VOLTAGE_HIGH_WARN_V = 3.46
TX_POWER_LOW_WARN_DBM = -9.0
TX_POWER_HIGH_WARN_DBM = 1.0
RX_POWER_LOW_WARN_DBM = -15.0
RX_POWER_HIGH_WARN_DBM = 1.0

# Keywords in `show environment` output that indicate a temp/power/fan problem
ENV_WARNING_WORDS_IOS = ('warning', 'critical', 'failed', 'not present')
ENV_WARNING_WORDS_NXOS = ('minor-alarm', 'major-alarm', 'critical', 'failed', 'absent', 'failure')

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
        'optical_alerts': [],
        'env_supported': True,
        'env_warnings': [],
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

    # --- Optical: flag transceivers with temp/voltage/Tx/Rx outside generic warning bounds ---
    # Each numeric field tolerates an optional inline unit suffix (e.g. "32.5C",
    # "-2.5 dBm") - real hardware output includes units directly in the data
    # columns, unlike this lab's platform which prints bare numbers.
    NUM_WITH_UNIT = r'(-?[\d.]+)\s*[A-Za-z%]*'
    transceiver_output = net_connect.send_command('show interfaces transceiver detail')
    for line in transceiver_output.splitlines():
        optics_match = re.match(
            rf'^(\S+)\s+{NUM_WITH_UNIT}\s+{NUM_WITH_UNIT}\s+{NUM_WITH_UNIT}\s+{NUM_WITH_UNIT}\s*$', line
        )
        if not optics_match:
            continue
        iface, temp, voltage, tx_power, rx_power = optics_match.groups()
        temp, voltage, tx_power, rx_power = (
            float(temp), float(voltage), float(tx_power), float(rx_power)
        )

        alerts = []
        if temp < TEMP_LOW_WARN_C or temp > TEMP_HIGH_WARN_C:
            alerts.append(f'temp: {temp}C')
        if voltage < VOLTAGE_LOW_WARN_V or voltage > VOLTAGE_HIGH_WARN_V:
            alerts.append(f'voltage: {voltage}V')
        if tx_power < TX_POWER_LOW_WARN_DBM or tx_power > TX_POWER_HIGH_WARN_DBM:
            alerts.append(f'Tx power: {tx_power}dBm')
        if rx_power < RX_POWER_LOW_WARN_DBM or rx_power > RX_POWER_HIGH_WARN_DBM:
            alerts.append(f'Rx power: {rx_power}dBm')

        if alerts:
            findings['optical_alerts'].append(f"{iface} ({', '.join(alerts)})")

    # --- Environment: temperature, power supply, and fan state ---
    env_output = net_connect.send_command('show environment all')
    if not env_output.strip() or 'no environment' in env_output.lower():
        findings['env_supported'] = False
    else:
        for line in env_output.splitlines():
            line_lower = line.lower()
            if any(word in line_lower for word in ENV_WARNING_WORDS_IOS):
                findings['env_warnings'].append(line.strip())

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
        'optical_alerts': [],
        'env_supported': True,
        'env_warnings': [],
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

    # --- Optical: flag transceivers with temp/voltage/Tx/Rx outside their own
    # device-reported warning thresholds. Each metric line under a "SFP Detail
    # Diagnostics" block is: Current Measurement, High Alarm, Low Alarm,
    # High Warning, Low Warning (units vary by metric, e.g. C, V, dBm). ---
    metric_labels = {'Temperature': 'C', 'Voltage': 'V', 'Tx Power': 'dBm', 'Rx Power': 'dBm'}
    transceiver_output = net_connect.send_command('show interface transceiver details')
    current_iface = None
    current_alerts = []

    def flush():
        if current_iface and current_alerts:
            findings['optical_alerts'].append(f"{current_iface} ({', '.join(current_alerts)})")

    for line in transceiver_output.splitlines():
        iface_match = re.match(r'^(Eth\S+|mgmt\S+|Po\S+)', line)
        if iface_match:
            flush()
            current_iface = iface_match.group(1)
            current_alerts = []
            continue

        metric_match = re.match(
            r'\s*(Temperature|Voltage|Tx Power|Rx Power)\s+(-?[\d.]+)\s*\S*\s+'
            r'(-?[\d.]+)\s*\S*\s+(-?[\d.]+)\s*\S*\s+(-?[\d.]+)\s*\S*\s+(-?[\d.]+)\s*\S*\s*$',
            line
        )
        if metric_match and current_iface:
            label, current, _alarm_high, _alarm_low, warn_high, warn_low = metric_match.groups()
            current, warn_high, warn_low = float(current), float(warn_high), float(warn_low)
            if current >= warn_high or current <= warn_low:
                unit = metric_labels[label]
                current_alerts.append(
                    f'{label}: {current}{unit} (warn range {warn_low}{unit} to {warn_high}{unit})'
                )

    flush()

    # --- Environment: temperature, power, and fan state. Uses the three focused
    # commands rather than the combined `show environment` since it can be very
    # long on chassis-based Nexus platforms. ---
    for cmd in ('show environment temperature', 'show environment power', 'show environment fan'):
        env_output = net_connect.send_command(cmd)
        if not env_output.strip() or 'not supported' in env_output.lower():
            findings['env_supported'] = False
            continue
        for line in env_output.splitlines():
            line_lower = line.lower()
            if any(word in line_lower for word in ENV_WARNING_WORDS_NXOS):
                findings['env_warnings'].append(line.strip())

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
            if findings['optical_alerts']:
                flags.append(f"optical alerts: {', '.join(findings['optical_alerts'])}")
            if findings['env_warnings']:
                flags.append(f"environment: {len(findings['env_warnings'])} warning(s)")
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
            if findings['optical_alerts']:
                print(f'  Transceiver alerts:')
                for iface in findings['optical_alerts']:
                    print(f'    - {iface}')
            if not findings['env_supported']:
                print(f'  Environment: not supported on this platform (virtual/emulated)')
            elif findings['env_warnings']:
                print(f'  Environment warnings:')
                for warning in findings['env_warnings']:
                    print(f'    - {warning}')
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
