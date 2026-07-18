# Network Automation

Python scripts for automating common network engineering tasks (Cisco IOS/NX-OS) over SSH using [Netmiko](https://github.com/ktbyers/netmiko).

## What's here

### Shared
- **`netauto.py`** — Shared helpers: loads the device inventory from `inventory.yaml`, validates device names, prompts for SSH credentials, and opens a Netmiko SSH connection with error handling for auth failures, timeouts, and unreachable hosts.
- **`inventory.yaml`** — Device inventory (name, host, device_type) used by `netauto.py`. No credentials are stored here — username/password are always prompted at runtime.

### Read-only / diagnostics
- **`show_command.py`** — Run a show command against one or more devices from the inventory.

### Configuration
- **`config_loopback.py`** — Create or update a loopback interface on a device from the inventory.
- **`push_config.py`** — Push a set of config commands (one per line, from a file) to one or more devices from the inventory.

### Backup & compliance
- **`backup_config.py`** — Back up the running-config for one device (or all devices) in the inventory, including VLANs (`show vlan brief`, appended to the same backup since VLANs created via `vlan <id>` often live in the VLAN database rather than the running-config text). Saves a "latest" copy per device plus a timestamped archive, pruned to the 5 most recent per device.
- **`config_diff.py`** — Compare a device's current running-config and VLANs against its last `backup_config.py` backup and print a unified diff, to catch drift or unexpected changes.
- **`L2_stig_audit.py`** — Audit a device's running-config against the DISA Cisco IOS Switch L2S/NDM STIG rules in `New Layer 2 switch Checklist.cklb`, reporting PASS/FAIL for rules checkable from config text alone (rules needing external infrastructure or manual review are reported as NOT AUTOMATED).
- **`NXOS_stig_audit.py`** — Same as `L2_stig_audit.py`, but for the DISA Cisco NX-OS Switch L2S/NDM STIG rules in `New NXOS Checklist.cklb`.

## Requirements

```
pip install -r requirements.txt
```

## Usage

Each script prompts for your SSH username and password (via `getpass`, so the password isn't echoed or stored).

```bash
# Run a show command against one device
python3 show_command.py "show ip interface brief" R1

# Run a show command against several devices
python3 show_command.py "show ip interface brief" R1 R2 S1

# Configure a loopback interface with parameters to select the device you want to configure
python3 config_loopback.py R1 1.1.1.1 255.255.255.255 --interface 0

# Push a set of config commands (one per line in commands.txt) to one or more devices
python3 push_config.py commands.txt R1 R2

# Back up one device's running-config
python3 backup_config.py R1

# Back up every device in the inventory
python3 backup_config.py

# Diff a device's current running-config against its last backup
python3 config_diff.py R1

# Audit a device against the DISA STIG checklist (IOS switches)
python3 L2_stig_audit.py R1

# Audit a device against the DISA STIG checklist (NX-OS switches)
python3 NXOS_stig_audit.py NXCore1
```

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`).
- Backups (running-config + VLANs) are written to `backups/`, with dated copies kept in `backups/archive/`.