# Network Automation

Python scripts for automating common network engineering tasks (Cisco IOS/NX-OS) over SSH using [Netmiko](https://github.com/ktbyers/netmiko).

## What's here

### Shared
- **`netauto.py`** — Shared helpers: loads the device inventory from `inventory.yaml`, validates device names, prompts for SSH credentials, and opens a Netmiko SSH connection with error handling for auth failures, timeouts, and unreachable hosts.
- **`inventory.yaml`** — Device inventory (name, host, device_type) used by `netauto.py`. No credentials are stored here — username/password are always prompted at runtime.

### Read-only / diagnostics
- **`show_command.py`** — Run a show command against one or more devices from the inventory.
- **`health_check.py`** — Check operational health of one or more devices (or the whole inventory): reachability, interfaces down but not admin-down, nonzero input/CRC error counters, CPU utilization (flagged over 80% on IOS / 85% on NX-OS), and default route presence on IOS routers.

### Configuration
- **`config_loopback.py`** — Create or update a loopback interface on a device from the inventory.
- **`push_config.py`** — Push a set of config commands (one per line, from a file) to one or more devices from the inventory.

### Backup & compliance
- **`backup_config.py`** — Back up the running-config for one device (or all devices) in the inventory, including VLANs (`show vlan brief`, appended to the same backup since VLANs created via `vlan <id>` often live in the VLAN database rather than the running-config text). Saves a "latest" copy per device plus a timestamped archive, pruned to the 5 most recent per device.
- **`config_diff.py`** — Compare a device's current running-config and VLANs against its last `backup_config.py` backup and print a unified diff, to catch drift or unexpected changes.
- **`L2_stig_audit.py`** — Audit a device's running-config against the DISA Cisco IOS Switch L2S/NDM STIG rules in `New Layer 2 switch Checklist.cklb`, reporting PASS/FAIL for rules checkable from config text alone (rules needing external infrastructure or manual review are reported as NOT AUTOMATED).
- **`NXOS_stig_audit.py`** — Same as `L2_stig_audit.py`, but for the DISA Cisco NX-OS Switch L2S/NDM STIG rules in `New NXOS Checklist.cklb`.
- **`IOS_Router_audit.py`** — Same as `L2_stig_audit.py`, but for the DISA Cisco IOS Router NDM/RTR STIG rules in `New IOS Router Checklist.cklb`. Most RTR rules describe perimeter/BGP/MPLS/multicast topology and policy decisions that can't be verified from a single device's config, so the majority are reported as NOT AUTOMATED.
- **`L2_stig_harden.py`** — Push the global (non-interface-specific) L2S STIG hardening fixes to a device: BPDU Guard default, Loop Guard, Rapid-PVST, UDLD, IGMP snooping, DHCP snooping (VLANs auto-discovered from `show vlan brief`), and optionally VTP authentication via `--vtp-password`. Rules needing per-interface targeting (host-facing vs. trunk/uplink ports) are intentionally skipped and listed in the output.
- **`NXOS_stig_harden.py`** — Same as `L2_stig_harden.py`, but for NX-OS: BPDU Guard, Loop Guard, IGMP snooping, UDLD (with `feature udld`), DHCP snooping (with `feature dhcp`, VLANs auto-discovered), and optionally VTP authentication (with `feature vtp`) via `--vtp-password`.
- **`IOS_Router_stig_harden.py`** — Push the global (non-interface-specific) RTR STIG hardening fixes to a router: disable gratuitous ARPs, disable CDP, enable CEF, and disable the AUX port. Rules needing per-interface targeting (directed broadcast, ICMP redirects/unreachables/mask-reply, proxy ARP, LLDP transmit) are intentionally skipped and listed in the output.

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

# Check operational health of every device in the inventory
python3 health_check.py

# Check operational health of specific devices
python3 health_check.py R1 S1

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

# Audit a device against the DISA STIG checklist (IOS routers)
python3 IOS_Router_audit.py R1

# Push global L2S STIG hardening fixes to a switch (optionally with VTP auth)
python3 L2_stig_harden.py S1 --vtp-password S3cr3tPass

# Push global L2S STIG hardening fixes to an NX-OS switch (optionally with VTP auth)
python3 NXOS_stig_harden.py NXCore1 --vtp-password S3cr3tPass

# Push global RTR STIG hardening fixes to a router
python3 IOS_Router_stig_harden.py R1
```

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`).
- Backups (running-config + VLANs) are written to `backups/`, with dated copies kept in `backups/archive/`.