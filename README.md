# Network Automation

Python scripts for automating common network engineering tasks (Cisco IOS/NX-OS) over SSH using [Netmiko](https://github.com/ktbyers/netmiko).

## What's here

### Shared
- **`netauto.py`** — Shared helpers: inventory loading, device-name validation, credential prompting, and Netmiko SSH connection handling with error handling for auth failures, timeouts, and unreachable hosts.
- **`inventory.yaml`** — Device inventory (name, host, device_type). No credentials stored — username/password are always prompted at runtime.

### Read-only / diagnostics
- **`show_command.py`** — Run a show command against one or more devices.
- **`health_check.py`** — Check operational health across the inventory: reachability, unexpected interface state, error counters, CPU utilization, and environment health (temperature/power/fans). Flags anything that needs attention.

### Configuration
- **`config_loopback.py`** — Create or update a loopback interface on a device.
- **`push_config.py`** — Push a set of config commands (one per line, from a file) to one or more devices.

### Backup & compliance
- **`backup_config.py`** — Back up running-config (+ VLANs via `show vlan brief`) for one device or all devices. Saves a "latest" copy per device plus a timestamped archive, pruned to the 5 most recent.
- **`config_diff.py`** — Compare a device's current running-config and VLANs against its last backup to catch drift or unexpected changes.
- **`stig_common.py`** — Shared STIG audit engine used by the audit scripts below: loads a DISA `.cklb` checklist, checks running-config against it, and prints a PASS/FAIL/NOT AUTOMATED report sorted by severity.
- **`L2_stig_audit.py`** — Audit a device against the DISA Cisco IOS Switch L2S/NDM STIG (`New Layer 2 switch Checklist.cklb`).
- **`NXOS_stig_audit.py`** — Audit a device against the DISA Cisco NX-OS Switch L2S/NDM STIG (`New NXOS Checklist.cklb`).
- **`IOS_Router_audit.py`** — Audit a device against the DISA Cisco IOS Router NDM/RTR STIG (`New IOS Router Checklist.cklb`). Most RTR rules require topology/policy context and are reported as NOT AUTOMATED.
- **`L2_stig_harden.py`** — Push global L2S STIG hardening fixes to an IOS switch (BPDU Guard, Loop Guard, Rapid-PVST, UDLD, IGMP snooping, DHCP snooping). Prompts for VTP password at runtime — leave blank to skip. Interface-specific rules are intentionally skipped and listed in the output.
- **`NXOS_stig_harden.py`** — Same as `L2_stig_harden.py` for NX-OS, enabling required features (`feature udld`, `feature dhcp`, `feature vtp`) before applying fixes.
- **`IOS_Router_stig_harden.py`** — Push global RTR STIG hardening fixes to an IOS router (disable gratuitous ARPs, CDP, AUX port; enable CEF). Interface-specific rules are intentionally skipped and listed in the output.

## Requirements

```
pip install -r requirements.txt
```

## Usage

Each script prompts for your SSH username and password (via `getpass`, so the password isn't echoed or stored). Hardening scripts additionally prompt for a VTP domain password — leave blank to skip VTP configuration.

```bash
# Run a show command against one or more devices
python3 show_command.py "show ip interface brief" R1
python3 show_command.py "show ip interface brief" R1 R2 S1

# Check operational health of all devices, or specific ones
python3 health_check.py
python3 health_check.py R1 S1

# Configure a loopback interface
python3 config_loopback.py R1 1.1.1.1 255.255.255.255 --interface 0

# Push config commands from a file to one or more devices
python3 push_config.py commands.txt R1 R2

# Back up one device or all devices
python3 backup_config.py R1
python3 backup_config.py

# Diff current running-config against last backup
python3 config_diff.py R1

# STIG audit (IOS switch, NX-OS switch, IOS router)
python3 L2_stig_audit.py S1
python3 NXOS_stig_audit.py NXCore1
python3 IOS_Router_audit.py R1

# STIG hardening — global fixes only (interface-specific rules listed but skipped)
python3 L2_stig_harden.py S1
python3 NXOS_stig_harden.py NXCore1
python3 IOS_Router_stig_harden.py R1
```

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`).
- Backups are written to `backups/`, with dated copies in `backups/archive/`.
- STIG rules that require external infrastructure (RADIUS, syslog, NTP, PKI) or manual/topology review are reported as NOT AUTOMATED rather than guessed at.

## Roadmap

- [x] Environment checks in `health_check.py` (temperature, power supply, fans via `show environment`)
- [ ] Config push dry-run / diff-before-push mode
- [ ] Audit logging to file (timestamped record of who ran what and when)
- [ ] Nornir-based parallel execution for larger inventories
- [ ] Ansible playbook equivalents for core workflows
