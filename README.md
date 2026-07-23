# Network Automation

Python scripts for automating common network engineering tasks (Cisco IOS/NX-OS) over SSH using [Netmiko](https://github.com/ktbyers/netmiko).

## What's here

### Shared
- **`netauto.py`** — Shared helpers: inventory loading, device-name validation, credential prompting, and Netmiko SSH connection handling. `connect()` also escalates to privileged EXEC automatically via `secrets.yaml`'s `enable_secret` if one is set (a no-op if the session is already privileged) — needed once `aaa new-model` governs login on a device.
- **`inventory.yaml`** — Device inventory (name, host, device_type), plus STIG-hardening config: `services` (NTP/syslog/RADIUS server IPs), `non_user_vlans`, `management_subnet`, `automation_host`, `unused_vlan`, `native_vlan`, `default_access_vlan`. No credentials stored — username/password are always prompted at runtime.
- **`secrets.yaml`** (gitignored) — Plaintext secrets used by the `*_stig_harden*.py` scripts (VTP password, NTP auth key, RADIUS key, enable secret, SNMPv3 auth/priv passwords), never prompted for or passed as CLI flags. Copy `secrets.yaml.example` to get started.

### Read-only / diagnostics
- **`show_command.py`** — Run a show command against one or more devices.
- **`health_check.py`** — Check operational health across the inventory: reachability, unexpected interface state, error counters, CPU utilization, and environment health (temperature/power/fans). Flags anything that needs attention.

### Configuration
- **`config_loopback.py`** — Create or update a loopback interface on a device.
- **`push_config.py`** — Push a set of config commands (one per line, from a file) to one or more devices.
- **`L2_quiet_console.py`** — Disable live logging output to the console/terminal (`no logging console` / `no logging monitor`). Not a STIG requirement, pure quality-of-life so log messages stop interrupting an active session. Messages still buffer and forward to syslog as normal; use `show logging` to view them on demand.

### Backup & compliance
- **`backup_config.py`** — Back up running-config (+ VLANs via `show vlan brief`) for one device or all devices. Saves a "latest" copy per device plus a timestamped archive, pruned to the 5 most recent.
- **`config_diff.py`** — Compare a device's current running-config and VLANs against its last backup to catch drift or unexpected changes.
- **`stig_common.py`** — Shared STIG audit engine: loads a DISA `.cklb` checklist, checks running-config (plus a few live show-command lookups — root port, VTP password, discovered VLANs) against it, and prints a PASS/FAIL/NOT AUTOMATED report sorted by severity.
- **`L2_stig_audit.py`** — Audit a device against the DISA Cisco IOS Switch L2S/NDM STIG (`New Layer 2 switch Checklist.cklb`). Full interface-scoped coverage (access vs. trunk classification, native/default VLAN checks, Root Guard, 802.1x/MAB), live discovery for root ports/VTP password/genuine user VLANs. 60/65 rules automated (audited and/or pushed) as of this writing; the rest need external infrastructure or manual/topology review.
- **`NXOS_stig_audit.py`** — Audit a device against the DISA Cisco NX-OS Switch L2S/NDM STIG (`New NXOS Checklist.cklb`).
- **`IOS_Router_audit.py`** — Audit a device against the DISA Cisco IOS Router NDM/RTR STIG (`New IOS Router Checklist.cklb`). Most RTR rules require topology/policy context and are reported as NOT AUTOMATED.
- **`L2_stig_harden.py`** — Push the bulk of L2S STIG hardening to an IOS switch: BPDU Guard, Loop Guard, Rapid-PVST, UDLD, IGMP snooping, DHCP snooping (+ `ip dhcp snooping trust` on trunk ports), archive/audit logging, password encryption, exec-timeout, VTP (mode transparent + password), native/unused/default-access VLAN creation, per-port access/trunk classification and hardening (UUFB, storm control, IP Source Guard prerequisites, 802.1x/MAB attempt, allowed-VLAN scoping), NTP, syslog, SNMPv3. Run this **first** — the other `L2_stig_harden_*.py` scripts below depend on it having already run (DHCP snooping active, ports in access mode).
- **`L2_stig_harden_ipsg.py`** — Push IP Source Guard (`ip verify source`, V-220634) to access ports. Split out on purpose: IPSG only trusts the DHCP snooping binding table, so a statically-addressed host with no DHCP lease gets its traffic dropped — an unresolved gap tracked separately, kept isolated so it can be pushed/pulled independently.
- **`L2_stig_harden_acl.py`** — Push a vty management ACL (V-220575), scoped to `inventory.yaml`'s `automation_host` only. Kept isolated and verified carefully: creates the ACL before applying it, applies `access-class` using the already-open primary session, then opens a **second independent connection** to confirm new logins still work — reverting immediately via the still-open primary session if not. Of everything in this repo, a wrongly-scoped vty ACL is the most direct lockout risk. The ACL's trailing deny also carries `log-input` (V-220581, partial — covers rejected vty access attempts only, not general traffic, and only reaches `show logging` locally since `logging trap critical` is above the informational severity ACL logging uses).
- **`L2_stig_harden_aaa.py`** — Push `aaa new-model` + RADIUS auth (V-220587/617) + password length/complexity policy (V-220589-594). Kept isolated and run **last**: verifies the enable secret actually works (a `disable`→`enable` round-trip) before touching `aaa new-model` at all, aborting cleanly if that fails. See the "Bugs" folder in the project vault for the live incident that drove this design.
- **`L2_device_tracking.py`** — Push SISF `device-tracking policy` blocks (`IPV4_VISIBILITY` per access port, `DT-NOIPV6`/`NOTRACK` per VLAN) for host IP visibility. Not a STIG requirement. **IOS-XE only** — requires the modern SISF CLI, untested against real hardware so far (see Notes below).
- **`NXOS_stig_harden.py`** — Same idea as `L2_stig_harden.py` for NX-OS, enabling required features (`feature udld`, `feature dhcp`, `feature vtp`, `feature ntp`) before applying fixes.
- **`IOS_Router_stig_harden.py`** — Push global RTR STIG hardening fixes to an IOS router (disable gratuitous ARPs, CDP, AUX port; enable CEF; configure NTP).

## Requirements

```
pip install -r requirements.txt
```

Copy `secrets.yaml.example` to `secrets.yaml` and fill in real values before running any `*_stig_harden*.py` script that needs them (see each script's description above for which secrets it uses).

## Usage

Each script prompts for your SSH username and password (via `getpass`, so the password isn't echoed or stored).

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

# STIG hardening for an L2 switch - run in this order:
python3 L2_stig_harden.py S1        # bulk fixes, run first
python3 L2_stig_harden_ipsg.py S1   # IP Source Guard
python3 L2_stig_harden_acl.py S1    # vty management ACL - verified, still the riskiest push
python3 L2_stig_harden_aaa.py S1    # AAA/RADIUS + password policy - run last, verified before use

# NX-OS / IOS router hardening
python3 NXOS_stig_harden.py NXCore1
python3 IOS_Router_stig_harden.py R1

# Optional, non-STIG
python3 L2_quiet_console.py S1      # quiet the console during interactive config work
python3 L2_device_tracking.py S1    # IOS-XE only, host IP visibility
```

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`).
- Backups are written to `backups/`, with dated copies in `backups/archive/`.
- STIG rules that require external infrastructure (organization-defined DoS safeguards, PKI, IOS-version tracking) or manual/topology review are reported as NOT AUTOMATED rather than guessed at.
- A handful of STIG-required commands are confirmed to not exist/function on this project's `vios_l2` lab image (UUFB, storm control, `mls qos`, `security passwords min-length`, `file privilege 15`, 802.1x authenticator role, classic `radius-server host` syntax, SISF `device-tracking policy`) — the scripts still push them unconditionally since they're correct for real Cisco hardware. See the project's Obsidian vault, `Bugs/` folder, for the full list and how each was confirmed.
- Scripts that push config append a JSON-line audit record (timestamp, script, device, username, commands) to `audit_logs/audit.log` for each device. Not tracked in git — local to the machine that ran the script.

## Roadmap

- [x] Environment checks in `health_check.py` (temperature, power supply, fans via `show environment`)
- [x] Audit logging to file (timestamped record of who ran what and when)
- [x] Interface-scoped L2S STIG hardening (IP Source Guard, DAI, storm control, UUFB, native/default/access VLAN, 802.1x/MAB) — full access vs. trunk/uplink port classification in `L2_stig_audit.py`/`L2_stig_harden.py`
- [x] NTP portion of the STIGs — audit and hardening, redundant authenticated time sources
- [x] AAA/RADIUS (V-220587/617) and password complexity policy (V-220589-594) — isolated, verified-before-use in `L2_stig_harden_aaa.py`
- [x] vty management ACL (V-220575) — isolated, verified-before-use in `L2_stig_harden_acl.py`
- [x] SNMPv3 auth/priv (V-220604/605) — config-only, no NMS in this lab to actually poll it
- [ ] Config push dry-run / diff-before-push mode
- [ ] Config removal/undo mode — no script currently has a way to revert what it pushed
- [ ] Static-host binding gap for IP Source Guard/DAI — both only trust the DHCP snooping binding table, so statically-addressed hosts get dropped; needs a dynamic fix (diff `show ip device tracking all` against `show ip dhcp snooping binding`), blocked on IP Device Tracking not activating on this lab's `vios_l2`
- [ ] Interface-scoped RTR STIG hardening for `IOS_Router_stig_harden.py` (directed broadcast, ICMP redirects/unreachables/mask-reply, proxy ARP, LLDP transmit)
- [ ] Port the L2S-style interface-scoped hardening approach to `NXOS_stig_audit.py`/`NXOS_stig_harden.py`
- [ ] Validate `L2_device_tracking.py` and the AAA/ACL/password-policy scripts against real IOS-XE hardware — untested beyond this lab's classic-IOS `vios_l2` switches, which can't run any of it
- [ ] Nornir-based parallel execution for larger inventories
- [ ] Ansible playbook equivalents for core workflows
