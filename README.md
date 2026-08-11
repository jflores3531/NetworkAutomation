# Network Automation — DISA STIG Compliance for Cisco Infrastructure

Python and Ansible tooling that **audits and remediates Cisco network devices against DISA STIG benchmarks** — the hardening standard required on U.S. Department of Defense networks. Built on [Netmiko](https://github.com/ktbyers/netmiko) over SSH.

Manually STIG-checking a single switch means checking ~65 rules by hand against the running-config, then doing it again after every change. The scripts I created automates that loop across three platforms, and pushes the fixes.

| Platform | DISA Benchmarks | Rules | Automated checks |
|---|---|---|---|
| Cisco IOS Switch | L2S + NDM | 65 | 61 |
| Cisco NX-OS Switch | L2S + NDM | 64 | 57 |
| Cisco IOS Router | NDM + RTR | 127 | 59 |

Rules needing external infrastructure (PKI, org-defined DoS safeguards) or topology/policy judgment are reported **NOT AUTOMATED** rather than guessed at — a false pass on a compliance tool is worse than no answer. Every rule check is coded against the STIG's literal Check Text, and every fix against its Fix Text.

Validated against a 7-device virtual lab (2 IOS routers, 3 IOSvL2 switches, 2 NX-OS cores). Ansible roles under [`ansible/`](ansible/) replicate the Python hardening for fleet-wide runs. See [`docs/DESIGN.md`](docs/DESIGN.md) for the reasoning behind script isolation, run order, and credential handling.

## What's here

### Shared
- **`netauto.py`** — Inventory loading, device-name validation, credential prompting, Netmiko SSH connection handling, automatic privilege escalation.
- **`inventory.yaml`** — Device inventory and STIG-hardening config (NTP/syslog/RADIUS server IPs, VLAN IDs, management subnet, automation host). No credentials.
- **`secrets.yaml`** (gitignored) — Plaintext secrets for the `*_stig_harden*.py` scripts. Copy `secrets.yaml.example` to start.

### Read-only / diagnostics
- **`show_command.py`** — Run a show command against one or more devices.
- **`health_check.py`** — Reachability, unexpected interface state, error counters, CPU, environment health (temp/power/fans).

### Configuration
- **`config_loopback.py`** — Create or update a loopback interface.
- **`push_config.py`** — Push config commands from a file to one or more devices.
- **`l2_quiet_console.py`** — Disable live console/monitor logging. Quality-of-life, not a STIG item; messages still buffer and forward to syslog.

### Backup & compliance
- **`backup_config.py`** — Back up running-config + VLANs; keeps a "latest" copy per device plus a timestamped archive pruned to 5.
- **`config_diff.py`** — Compare current running-config/VLANs against the last backup.
- **`save_config.py`** — Save running-config to startup-config on one device or all. Run it *after* a harden pass and its audit, not as part of one — see [`docs/DESIGN.md`](docs/DESIGN.md).
- **`stig_common.py`** — Shared audit engine: loads a DISA `.cklb` checklist, checks the device against it, reports PASS/FAIL/NOT AUTOMATED by severity.
- **`l2_stig_audit.py`** — Audit against the IOS Switch L2S/NDM STIG. Full interface-scoped coverage, live discovery for root ports/VTP/user VLANs.
- **`nxos_stig_audit.py`** — Audit against the NX-OS Switch L2S/NDM STIG.
- **`ios_router_audit.py`** — Audit against the IOS Router NDM/RTR STIG. Most RTR rules need topology/policy context and report NOT AUTOMATED.
- **`l2_stig_harden_global.py`** — Bulk L2S hardening: BPDU/Loop Guard, Rapid-PVST, UDLD, IGMP + DHCP snooping, archive logging, VTP, per-port access/trunk hardening, NTP, syslog, SNMPv3. **Run first** — the other `l2_stig_harden_*.py` scripts depend on it.
- **`l2_stig_harden_ipsg.py`** — IP Source Guard (V-220634) on access ports. See Notes for the static-host caveat.
- **`l2_stig_harden_dai.py`** — Dynamic ARP Inspection (V-220635) on user VLANs. Same static-host caveat.
- **`l2_stig_harden_interfaces.py`** — Per-port L2S fixes split out of the bulk pass: access vs. trunk classification, UUFB, storm control, allowed-VLAN scoping, 802.1x/MAB.
- **`l2_stig_harden_acl.py`** — vty management ACL (V-220575), scoped to the automation host. Run as its own script.
- **`l2_stig_harden_aaa.py`** — `aaa new-model` + RADIUS auth (V-220587/617) + password policy (V-220589-594). **Run last.**
- **`l2_device_tracking.py`** — SISF `device-tracking policy` for host IP visibility. Not a STIG requirement, IOS-XE only.

#### NX-OS
- **`nxos_stig_harden_global.py`** — NX-OS equivalent of `l2_stig_harden_global.py`, enabling required features (`feature udld`, `feature dhcp`, `feature vtp`, `feature ntp`) before applying fixes.
- **`nxos_stig_harden_interfaces.py`** — Per-port NX-OS fixes: UUFB, IP Source Guard, storm control, DAI trust, VLAN pruning.
- **`nxos_stig_harden_acl.py`** — NX-OS management ACL (V-220479), scoped to the automation host.
- **`nxos_stig_harden_aaa.py`** — NX-OS RADIUS auth and accounting. NX-OS falls back to the local account automatically when RADIUS is unreachable.

#### IOS Router
- **`ios_router_stig_harden_global.py`** — Global RTR/NDM fixes: disable gratuitous ARP, CDP, AUX port; enable CEF; NTP, syslog, SSH FIPS ciphers, password encryption.
- **`ios_router_stig_harden_acl.py`** — vty management ACL (V-215667), the router port of `l2_stig_harden_acl.py`.
- **`ios_router_stig_harden_aaa.py`** — AAA/RADIUS (V-215709) plus password complexity (V-215681-686). `local` stays last in the method list, so SSH login still succeeds if RADIUS is unreachable.
- **`ios_router_stig_harden_urpf.py`** — Unicast Reverse Path Forwarding (V-216989) on external-facing interfaces. Requires `allow-default` — see [`docs/DESIGN.md`](docs/DESIGN.md).

## Requirements

```
pip install -r requirements.txt
```

Copy `secrets.yaml.example` to `secrets.yaml` and fill in real values before running any `*_stig_harden*.py` script that needs them.

## Usage

Each script prompts for your SSH username and password via `getpass` (not echoed or stored).

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
python3 l2_stig_audit.py S1
python3 nxos_stig_audit.py NXCore1
python3 ios_router_audit.py R1

# STIG hardening for an L2 switch - run in this order:
python3 l2_stig_harden_global.py S1 # bulk fixes, run first
python3 l2_stig_harden_ipsg.py S1   # IP Source Guard - can drop a statically-addressed host, see Notes
python3 l2_stig_harden_dai.py S1    # DAI - same static-host risk as IPSG, see Notes
python3 l2_stig_harden_acl.py S1    # vty management ACL - run isolated
python3 l2_stig_harden_aaa.py S1    # AAA/RADIUS + password policy - run last

# NX-OS hardening - global first, then the isolated scripts
python3 nxos_stig_harden_global.py NXCore1
python3 nxos_stig_harden_interfaces.py NXCore1
python3 nxos_stig_harden_acl.py NXCore1
python3 nxos_stig_harden_aaa.py NXCore1

# IOS router hardening - same order
python3 ios_router_stig_harden_global.py R1
python3 ios_router_stig_harden_urpf.py R1     # external-facing interfaces only
python3 ios_router_stig_harden_acl.py R1
python3 ios_router_stig_harden_aaa.py R1

# Persist the result - only after re-auditing and confirming it's what you wanted.
# Until this runs, a reload reverts the device, which is the escape hatch if a
# push locked you out.
python3 save_config.py NXCore1
python3 save_config.py            # or every device in the inventory

# Optional, non-STIG
python3 l2_quiet_console.py S1      # quiet the console during interactive config work
python3 l2_device_tracking.py S1    # IOS-XE only, host IP visibility
```

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`).
- Backups are written to `backups/`, with dated copies in `backups/archive/`.
- STIG rules requiring external infrastructure (org-defined DoS safeguards, PKI, IOS-version tracking) or manual/topology review are reported NOT AUTOMATED rather than guessed at.
- `l2_stig_harden_ipsg.py` and `l2_stig_harden_dai.py` both only trust the DHCP snooping binding table — a statically-addressed host with no DHCP lease is invisible to either and can have its traffic dropped once they're pushed. Confirmed live. If a statically-addressed host (e.g. the automation host itself) is directly connected to a device, consider skipping one or both scripts for that device until this has a real fix.
- Scripts that push config append a JSON-line audit record (timestamp, script, device, username, commands) to `audit_logs/audit.log`. Not tracked in git.
- Several STIG-required commands don't exist or function on this lab's `vios_l2` image — see [`docs/DESIGN.md`](docs/DESIGN.md) for the list and why the scripts still push them.

## Roadmap

- [x] Environment checks in `health_check.py` (temperature, power supply, fans)
- [x] Audit logging to file
- [x] Interface-scoped L2S STIG hardening (IPSG, DAI, storm control, UUFB, VLAN classification, 802.1x/MAB)
- [x] NTP audit and hardening, redundant authenticated time sources
- [x] AAA/RADIUS (V-220587/617) and password complexity policy (V-220589-594)
- [x] vty management ACL (V-220575)
- [x] SNMPv3 auth/priv (V-220604/605) — config-only, no NMS in this lab to poll it
- [ ] Config push dry-run / diff-before-push mode
- [ ] Config removal/undo mode
- [ ] Static-host binding gap for IPSG/DAI — needs a dynamic fix diffing `show ip device tracking all` against `show ip dhcp snooping binding`
- [ ] Interface-scoped RTR STIG hardening (directed broadcast, ICMP redirects/unreachables/mask-reply, proxy ARP, LLDP transmit)
- [ ] Port interface-scoped hardening to `nxos_stig_audit.py`/`nxos_stig_harden_global.py`
- [ ] Validate `l2_device_tracking.py` and the AAA/ACL/password-policy scripts against real IOS-XE hardware
- [ ] Nornir-based parallel execution for larger inventories
- [ ] Ansible playbook equivalents for core workflows
